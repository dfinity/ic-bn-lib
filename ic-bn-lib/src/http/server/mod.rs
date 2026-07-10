pub mod cli;
pub mod conn;
pub mod metrics;
pub mod proxy_protocol;

use std::{
    fmt::Display,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioTimer},
    server::conn::auto::Builder,
};
use prometheus::Registry;
use proxy_protocol::ProxyProtocolStream;
use rustls::sign::SingleCertAndKey;
use socket2::TcpKeepalive;
use strum::EnumString;
use tokio::{select, time::sleep};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{debug, info, warn};

use crate::{
    http::{Error, server::metrics::Metrics},
    network::{Addr, AsyncReadWrite, ListenerOpts, listener::Listener},
    tasks::Run,
    tls::{TlsOptions, pem_convert_to_rustls, prepare_server_config},
};

const YEAR: Duration = Duration::from_secs(86400 * 365);

/// Status of Proxy Protocol in the Server
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ProxyProtocolMode {
    Off,
    Enabled,
    Forced,
}

/// HTTP server options
#[derive(Clone, Copy)]
pub struct ServerOptions {
    pub backlog: u32,
    pub tls_handshake_timeout: Duration,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub tcp_keepalive_delay: Option<Duration>,
    pub tcp_keepalive_interval: Option<Duration>,
    pub tcp_keepalive_retries: Option<u32>,
    pub tcp_mss: Option<u32>,
    pub http1_header_read_timeout: Duration,
    pub http2_max_streams: u32,
    pub http2_keepalive_interval: Option<Duration>,
    pub http2_keepalive_timeout: Duration,
    pub grace_period: Duration,
    pub max_requests_per_conn: Option<u64>,
    pub proxy_protocol_mode: ProxyProtocolMode,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            backlog: 2048,
            tls_handshake_timeout: Duration::from_secs(15),
            read_timeout: Some(Duration::from_secs(60)),
            write_timeout: Some(Duration::from_secs(60)),
            idle_timeout: None,
            tcp_keepalive_delay: None,
            tcp_keepalive_interval: None,
            tcp_keepalive_retries: None,
            tcp_mss: None,
            http1_header_read_timeout: Duration::from_secs(10),
            http2_max_streams: 128,
            http2_keepalive_interval: None,
            http2_keepalive_timeout: Duration::from_secs(10),
            grace_period: Duration::from_secs(60),
            max_requests_per_conn: None,
            proxy_protocol_mode: ProxyProtocolMode::Off,
        }
    }
}

impl From<&ServerOptions> for TcpKeepalive {
    fn from(v: &ServerOptions) -> Self {
        let mut ka = Self::new();

        if let Some(v) = v.tcp_keepalive_delay {
            ka = ka.with_time(v);
        }
        if let Some(v) = v.tcp_keepalive_interval {
            ka = ka.with_interval(v);
        }
        if let Some(v) = v.tcp_keepalive_retries {
            ka = ka.with_retries(v);
        }

        ka
    }
}

#[derive(Clone)]
enum RequestState {
    Start,
    End,
}

/// Builder for a `Server`
pub struct ServerBuilder {
    addr: Option<Addr>,
    router: Router,
    registry: Registry,
    metrics: Option<Metrics>,
    options: ServerOptions,
    rustls_cfg: Option<rustls::ServerConfig>,
}

impl ServerBuilder {
    /// Creates a builder with a given router & defaults
    pub fn new(router: Router) -> Self {
        Self {
            addr: None,
            router,
            registry: Registry::new(),
            metrics: None,
            options: ServerOptions::default(),
            rustls_cfg: None,
        }
    }

    /// Listens on the given TCP socket
    pub fn listen_tcp(mut self, socket: SocketAddr) -> Self {
        self.addr = Some(Addr::Tcp(socket));
        self
    }

    /// Listens on the given Unix socket
    pub fn listen_unix(mut self, path: PathBuf) -> Self {
        self.addr = Some(Addr::Unix(path));
        self
    }

    /// Sets up metrics with provided Registry
    pub fn with_metrics_registry(mut self, registry: &Registry) -> Self {
        self.registry = registry.clone();
        self
    }

    /// Sets up metrics with provided Metrics.
    /// Overrides `with_metrics_registry()`.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Sets up TLS with provided ServerConfig
    pub fn with_rustls_config(mut self, rustls_cfg: rustls::ServerConfig) -> Self {
        self.rustls_cfg = Some(rustls_cfg);
        self
    }

    /// Sets up with provided Options
    pub const fn with_options(mut self, options: ServerOptions) -> Self {
        self.options = options;
        self
    }

    /// Sets up TLS with a single certificate.
    /// If metrics are needed - provide registry using `with_metrics_registry` before calling this method.
    pub fn with_rustls_single_cert(mut self, cert: PathBuf, key: PathBuf) -> Result<Self, Error> {
        let cert = std::fs::read(cert).context("unable to read cert")?;
        let key = std::fs::read(key).context("unable to read key")?;
        let cert = pem_convert_to_rustls(&key, &cert).context("unable to parse cert+key pair")?;
        let resolver = SingleCertAndKey::from(cert);
        let tls_opts = TlsOptions::default();
        let rustls_cfg = prepare_server_config(tls_opts, Arc::new(resolver), &self.registry);

        self.rustls_cfg = Some(rustls_cfg);
        Ok(self)
    }

    /// Build the Server
    pub fn build(self) -> Result<Server, Error> {
        let Some(addr) = self.addr else {
            return Err(Error::Generic(anyhow!("Listening address not specified")));
        };

        let metrics = self.metrics.unwrap_or_else(|| Metrics::new(&self.registry));

        Ok(Server::new(
            addr,
            self.router,
            self.options,
            metrics,
            self.rustls_cfg,
        ))
    }
}

/// Listens for new connections with an optional TLS and serves provided Router
pub struct Server {
    addr: Addr,
    router: Router,
    tracker: TaskTracker,
    options: ServerOptions,
    metrics: Metrics,
    builder: Builder<TokioExecutor>,
    rustls_cfg: Option<Arc<rustls::ServerConfig>>,
}

impl Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", self.addr)
    }
}

impl Server {
    /// Create a new `Server`
    pub fn new(
        addr: Addr,
        router: Router,
        options: ServerOptions,
        metrics: Metrics,
        rustls_cfg: Option<rustls::ServerConfig>,
    ) -> Self {
        // Prepare Hyper connection builder
        // It automatically figures out whether to do HTTP1 or HTTP2
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new()) // Needed for the keepalives below
            .header_read_timeout(Some(options.http1_header_read_timeout))
            .keep_alive(true)
            .http2()
            .adaptive_window(true)
            .max_concurrent_streams(Some(options.http2_max_streams))
            .timer(TokioTimer::new()) // Needed for the keepalives below
            .keep_alive_interval(options.http2_keepalive_interval)
            .keep_alive_timeout(options.http2_keepalive_timeout)
            .enable_connect_protocol(); // Needed for Websockets

        Self {
            addr,
            router,
            options,
            metrics,
            tracker: TaskTracker::new(),
            builder,
            rustls_cfg: rustls_cfg.map(Arc::new),
        }
    }

    /// Start serving with given cancellation token
    pub async fn serve(&self, token: CancellationToken) -> Result<(), Error> {
        let opts = ListenerOpts {
            backlog: self.options.backlog,
            mss: self.options.tcp_mss,
            keepalive: (&self.options).into(),
        };

        let listener =
            Listener::new(self.addr.clone(), opts).context("unable to create listener")?;
        self.serve_with_listener(listener, token).await
    }

    fn spawn_connection(
        &self,
        stream: Box<dyn AsyncReadWrite>,
        remote_addr: Addr,
        token: CancellationToken,
    ) {
        // Create a new connection
        // Router & TlsAcceptor are both Arc<> inside so it's cheap to clone
        // Builder is a bit more complex, but cloning is better than to create it again
        let conn = conn::Conn {
            addr: self.addr.clone(),
            remote_addr: remote_addr.clone(),
            router: self.router.clone(),
            builder: self.builder.clone(),
            token_graceful: token,
            token_forceful: CancellationToken::new(),
            options: self.options,
            metrics: self.metrics.clone(), // All metrics have Arc inside
            requests: AtomicU32::new(0),
            rustls_cfg: self.rustls_cfg.clone(),
        };

        // Spawn a task to handle connection & track it
        self.tracker.spawn(async move {
            if let Err(e) = conn.handle(stream).await {
                info!(
                    "[{}] <- [{remote_addr}]: failed to handle connection: {e:#}",
                    conn.addr
                );
            }

            debug!("[{}] <- [{remote_addr}]: connection finished", conn.addr);
        });
    }

    /// Start serving with a given listener & cancellation token
    pub async fn serve_with_listener(
        &self,
        listener: Listener,
        token: CancellationToken,
    ) -> Result<(), Error> {
        warn!("{self}: running (TLS: {})", self.rustls_cfg.is_some());

        loop {
            select! {
                biased; // Poll top-down

                () = token.cancelled() => {
                    // Stop accepting new connections
                    drop(listener);

                    warn!("{self}: shutting down, waiting for the active connections to close for {}s", self.options.grace_period.as_secs());
                    self.tracker.close();

                    select! {
                        () = sleep(self.options.grace_period + Duration::from_secs(5)) => {
                            warn!("{self}: connections didn't close in time, shutting down anyway");
                        },
                        () = self.tracker.wait() => {},
                    }

                    warn!("{self}: shut down");

                    // Remove the socket
                    if let Addr::Unix(v) = &self.addr {
                        let _ = std::fs::remove_file(v);
                    }

                    return Ok(());
                },

                // Try to accept the connection
                v = listener.accept() => {
                    let (stream, remote_addr) = match v {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("{self}: unable to accept connection: {e:#}");
                            // Wait few ms just in case that there's an overflown backlog
                            // so that we don't run into infinite error loop
                            sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    };

                    self.spawn_connection(stream, remote_addr, token.child_token());
                }
            }
        }
    }
}

#[async_trait]
impl Run for Server {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        self.serve(token).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use http::StatusCode;

    use crate::network::listener::listen_tcp;

    use super::*;

    #[tokio::test]
    async fn test_server() {
        let opts = ServerOptions::default();
        let listener = listen_tcp(
            "127.0.0.1:0".parse().unwrap(),
            ListenerOpts {
                backlog: 128,
                mss: None,
                keepalive: (&opts).into(),
            },
        )
        .unwrap();

        let addr = listener.local_addr().unwrap();

        let server = Server::new(
            Addr::Tcp(addr),
            Router::new(),
            opts,
            Metrics::new(&Registry::new()),
            None,
        );

        tokio::spawn(async move {
            server
                .serve_with_listener(listener.into(), CancellationToken::new())
                .await
                .unwrap();
        });

        for _ in 0..10 {
            let Ok(result) = reqwest::get(format!("http://{addr}")).await else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };

            assert_eq!(result.status(), StatusCode::NOT_FOUND);
            break;
        }
    }
}
