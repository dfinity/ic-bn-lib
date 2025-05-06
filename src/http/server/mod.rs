pub mod cli;

use std::{
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use axum::{Router, extract::Request};
use http::Response;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry,
    core::{AtomicI64, GenericGauge},
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry,
};
use rustls::{CipherSuite, ProtocolVersion, server::ServerConnection, sign::SingleCertAndKey};
use scopeguard::defer;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, UnixListener, UnixSocket},
    pin, select,
    sync::mpsc::channel,
    time::{sleep, timeout},
};
use tokio_io_timeout::TimeoutStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{ALPN_ACME, AsyncCounter, Error, Stats, body::NotifyingBody};
use crate::{
    tasks::Run,
    tls::{pem_convert_to_rustls, prepare_server_config},
};

const HANDSHAKE_DURATION_BUCKETS: &[f64] = &[0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6];
const CONN_DURATION_BUCKETS: &[f64] = &[1.0, 8.0, 32.0, 64.0, 256.0, 512.0, 1024.0];
const CONN_REQUESTS: &[f64] = &[1.0, 4.0, 8.0, 16.0, 32.0, 64.0, 256.0];

const YEAR: Duration = Duration::from_secs(86400 * 365);

// Blanket async read+write trait for streams Box-ing
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

#[derive(Clone)]
pub struct Metrics {
    conns: IntCounterVec,
    conns_open: IntGaugeVec,
    requests: IntCounterVec,
    requests_inflight: IntGaugeVec,
    bytes_sent: IntCounterVec,
    bytes_rcvd: IntCounterVec,
    conn_duration: HistogramVec,
    requests_per_conn: HistogramVec,
    conn_tls_handshake_duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const LABELS: &[&str] = &[
            "addr",
            "family",
            "tls_version",
            "tls_cipher",
            "forced_close",
            "recycled",
        ];

        Self {
            conns: register_int_counter_vec_with_registry!(
                format!("conn_total"),
                format!("Counts the number of connections"),
                LABELS,
                registry
            )
            .unwrap(),

            conns_open: register_int_gauge_vec_with_registry!(
                format!("conn_open"),
                format!("Number of currently open connections"),
                &LABELS[0..4],
                registry
            )
            .unwrap(),

            requests: register_int_counter_vec_with_registry!(
                format!("conn_requests_total"),
                format!("Counts the number of requests"),
                LABELS,
                registry
            )
            .unwrap(),

            requests_inflight: register_int_gauge_vec_with_registry!(
                format!("conn_requests_inflight"),
                format!("Counts the number of requests that are currently executed"),
                &LABELS[0..4],
                registry
            )
            .unwrap(),

            bytes_sent: register_int_counter_vec_with_registry!(
                format!("conn_bytes_sent_total"),
                format!("Counts number of bytes sent"),
                LABELS,
                registry
            )
            .unwrap(),

            bytes_rcvd: register_int_counter_vec_with_registry!(
                format!("conn_bytes_rcvd_total"),
                format!("Counts number of bytes received"),
                LABELS,
                registry
            )
            .unwrap(),

            conn_duration: register_histogram_vec_with_registry!(
                format!("conn_duration_sec"),
                format!("Records the duration of connection in seconds"),
                LABELS,
                CONN_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            requests_per_conn: register_histogram_vec_with_registry!(
                format!("conn_requests_per_conn"),
                format!("Records the number of requests per connection"),
                LABELS,
                CONN_REQUESTS.to_vec(),
                registry
            )
            .unwrap(),

            conn_tls_handshake_duration: register_histogram_vec_with_registry!(
                format!("conn_tls_handshake_duration_sec"),
                format!("Records the duration of the TLS handshake in seconds"),
                &LABELS[0..4],
                HANDSHAKE_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Options {
    pub backlog: u32,
    pub tls_handshake_timeout: Duration,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub idle_timeout: Duration,
    pub http1_header_read_timeout: Duration,
    pub http2_max_streams: u32,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
    pub grace_period: Duration,
    pub max_requests_per_conn: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            backlog: 2048,
            tls_handshake_timeout: Duration::from_secs(15),
            read_timeout: Some(Duration::from_secs(60)),
            write_timeout: Some(Duration::from_secs(60)),
            idle_timeout: Duration::from_secs(60),
            http1_header_read_timeout: Duration::from_secs(10),
            http2_max_streams: 128,
            http2_keepalive_interval: Duration::from_secs(20),
            http2_keepalive_timeout: Duration::from_secs(10),
            grace_period: Duration::from_secs(60),
            max_requests_per_conn: None,
        }
    }
}

// TLS information about the connection
#[derive(Clone, Debug)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub protocol: ProtocolVersion,
    pub cipher: CipherSuite,
    pub handshake_dur: Duration,
}

impl TryFrom<&ServerConnection> for TlsInfo {
    type Error = Error;

    fn try_from(c: &ServerConnection) -> Result<Self, Self::Error> {
        Ok(Self {
            handshake_dur: Duration::ZERO,
            sni: c.server_name().map(|x| x.to_string()),
            alpn: c
                .alpn_protocol()
                .map(|x| String::from_utf8_lossy(x).to_string()),
            protocol: c
                .protocol_version()
                .ok_or_else(|| anyhow!("No TLS protocol found"))?,
            cipher: c
                .negotiated_cipher_suite()
                .map(|x| x.suite())
                .ok_or_else(|| anyhow!("No TLS ciphersuite found"))?,
        })
    }
}

#[derive(Debug)]
pub struct ConnInfo {
    pub id: Uuid,
    pub accepted_at: Instant,
    pub remote_addr: Addr,
    pub traffic: Arc<Stats>,
    pub req_count: AtomicU64,
    pub close: CancellationToken,
}

impl Default for ConnInfo {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            accepted_at: Instant::now(),
            remote_addr: Addr::default(),
            traffic: Arc::new(Stats::new()),
            req_count: AtomicU64::new(0),
            close: CancellationToken::new(),
        }
    }
}

impl ConnInfo {
    pub fn req_count(&self) -> u64 {
        self.req_count.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        self.close.cancel();
    }
}

pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    pub fn new(addr: Addr, backlog: u32) -> Result<Self, Error> {
        Ok(match addr {
            Addr::Tcp(v) => Self::Tcp(listen_tcp_backlog(v, backlog)?),
            Addr::Unix(v) => Self::Unix(listen_unix_backlog(v, backlog)?),
        })
    }

    async fn accept(&self) -> Result<(Box<dyn AsyncReadWrite>, Addr), io::Error> {
        Ok(match self {
            Self::Tcp(v) => {
                let x = v.accept().await?;
                // Disable Nagle's algo
                x.0.set_nodelay(true)?;
                (Box::new(x.0), Addr::Tcp(x.1))
            }
            Self::Unix(v) => {
                let x = v.accept().await?;
                (
                    Box::new(x.0),
                    Addr::Unix(x.1.as_pathname().map(|x| x.into()).unwrap_or_default()),
                )
            }
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &self {
            Self::Tcp(v) => v.local_addr().ok(),
            Self::Unix(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Addr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Default for Addr {
    fn default() -> Self {
        Self::Tcp(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            666,
        )))
    }
}

impl Addr {
    pub const fn family(&self) -> &'static str {
        match self {
            Self::Tcp(v) => {
                if v.ip().to_canonical().is_ipv4() {
                    "v4"
                } else {
                    "v6"
                }
            }
            Self::Unix(_) => "unix",
        }
    }

    pub const fn ip(&self) -> IpAddr {
        match self {
            Self::Tcp(v) => v.ip().to_canonical(),
            Self::Unix(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Tcp(v) => v.to_string(),
                Self::Unix(v) => v.to_string_lossy().to_string(),
            }
        )
    }
}

#[derive(Clone)]
enum RequestState {
    Start,
    End,
}

async fn tls_handshake(
    rustls_cfg: Arc<rustls::ServerConfig>,
    stream: impl AsyncReadWrite,
) -> Result<(impl AsyncReadWrite, TlsInfo), Error> {
    let tls_acceptor = TlsAcceptor::from(rustls_cfg);

    // Perform the TLS handshake
    let start = Instant::now();
    let stream = tls_acceptor
        .accept(stream)
        .await
        .context("TLS accept failed")?;
    let duration = start.elapsed();

    let conn = stream.get_ref().1;
    let mut tls_info = TlsInfo::try_from(conn)?;
    tls_info.handshake_dur = duration;

    Ok((stream, tls_info))
}

struct Conn {
    addr: Addr,
    remote_addr: Addr,
    router: Router,
    builder: Builder<TokioExecutor>,
    token_graceful: CancellationToken,
    token_forceful: CancellationToken,
    options: Options,
    metrics: Metrics,
    requests: AtomicU32,
    rustls_cfg: Option<Arc<rustls::ServerConfig>>,
}

impl Display for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Server {}: {}", self.addr, self.remote_addr)
    }
}

impl Conn {
    async fn handle(&self, stream: Box<dyn AsyncReadWrite>) -> Result<(), Error> {
        let accepted_at = Instant::now();

        debug!("{self}: got a new connection");

        // Prepare metric labels
        let addr = self.addr.to_string();
        let labels = &mut [
            addr.as_str(),             // Listening addr
            self.remote_addr.family(), // Remote client address family
            "no",                      // TLS version
            "no",                      // TLS ciphersuite
            "no",                      // Force-closed
            "no",                      // Recycled
        ];

        // Wrap with traffic counter
        let (stream, stats) = AsyncCounter::new(stream);

        let conn_info = Arc::new(ConnInfo {
            id: Uuid::now_v7(),
            accepted_at,
            remote_addr: self.remote_addr.clone(),
            traffic: stats.clone(),
            req_count: AtomicU64::new(0),
            close: self.token_forceful.clone(),
        });

        // Perform TLS handshake if we're in TLS mode
        let (stream, tls_info): (Box<dyn AsyncReadWrite>, _) = if let Some(rustls_cfg) =
            &self.rustls_cfg
        {
            debug!("{}: performing TLS handshake", self);

            let (mut stream_tls, tls_info) = timeout(
                self.options.tls_handshake_timeout,
                tls_handshake(rustls_cfg.clone(), stream),
            )
            .await
            .context("TLS handshake timed out")?
            .context("TLS handshake failed")?;

            debug!(
                "{}: handshake finished in {}ms (server: {:?}, proto: {:?}, cipher: {:?}, ALPN: {:?})",
                self,
                tls_info.handshake_dur.as_millis(),
                tls_info.sni,
                tls_info.protocol,
                tls_info.cipher,
                tls_info.alpn,
            );

            // Close the connection if agreed ALPN is ACME - the handshake is enough for the challenge
            if tls_info
                .alpn
                .as_ref()
                .is_some_and(|x| x.as_bytes() == ALPN_ACME)
            {
                debug!("{self}: ACME ALPN - closing connection");

                timeout(Duration::from_secs(5), stream_tls.shutdown())
                    .await
                    .context("socket shutdown timed out")?
                    .context("socket shutdown failed")?;

                return Ok(());
            }

            (Box::new(stream_tls), Some(Arc::new(tls_info)))
        } else {
            (Box::new(stream), None)
        };

        // Record TLS metrics
        if let Some(v) = &tls_info {
            labels[2] = v.protocol.as_str().unwrap();
            labels[3] = v.cipher.as_str().unwrap();

            self.metrics
                .conn_tls_handshake_duration
                .with_label_values(&labels[0..4])
                .observe(v.handshake_dur.as_secs_f64());
        }

        self.metrics
            .conns_open
            .with_label_values(&labels[0..4])
            .inc();

        let requests_inflight = self
            .metrics
            .requests_inflight
            .with_label_values(&labels[0..4]);

        // Handle the connection
        let result = self
            .handle_inner(stream, conn_info.clone(), tls_info, requests_inflight)
            .await;

        // Record connection metrics
        let (sent, rcvd) = (stats.sent(), stats.rcvd());
        let dur = accepted_at.elapsed().as_secs_f64();
        let reqs = conn_info.req_count.load(Ordering::SeqCst);

        // force-closed
        if self.token_forceful.is_cancelled() {
            labels[4] = "yes";
        }
        // recycled
        if self.token_graceful.is_cancelled() {
            labels[5] = "yes";
        }

        self.metrics.conns.with_label_values(labels).inc();
        self.metrics
            .conns_open
            .with_label_values(&labels[0..4])
            .dec();
        self.metrics.requests.with_label_values(labels).inc_by(reqs);
        self.metrics
            .bytes_rcvd
            .with_label_values(labels)
            .inc_by(rcvd);
        self.metrics
            .bytes_sent
            .with_label_values(labels)
            .inc_by(sent);
        self.metrics
            .conn_duration
            .with_label_values(labels)
            .observe(dur);
        self.metrics
            .requests_per_conn
            .with_label_values(labels)
            .observe(reqs as f64);

        debug!(
            "{self}: connection closed (rcvd: {rcvd}, sent: {sent}, reqs: {reqs}, duration: {dur}, graceful: {}, forced close: {})",
            self.token_graceful.is_cancelled(),
            self.token_forceful.is_cancelled(),
        );

        result
    }

    async fn handle_inner(
        &self,
        stream: Box<dyn AsyncReadWrite>,
        conn_info: Arc<ConnInfo>,
        tls_info: Option<Arc<TlsInfo>>,
        requests_inflight: GenericGauge<AtomicI64>,
    ) -> Result<(), Error> {
        // Create a timer for idle connection tracking
        let mut idle_timer = Box::pin(sleep(self.options.idle_timeout));

        // Create channel to notify about request start/stop.
        // Use bounded but big enough so that it's larger than our concurrency.
        let (state_tx, mut state_rx) = channel(65536);

        // Apply timeouts on read/write calls
        let mut stream = TimeoutStream::new(stream);
        stream.set_read_timeout(self.options.read_timeout);
        stream.set_write_timeout(self.options.write_timeout);

        // Convert stream from Tokio to Hyper
        let stream = TokioIo::new(stream);

        // Convert router to Hyper service
        let max_requests_per_conn = self.options.max_requests_per_conn;
        let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
            // Notify that we have started processing the request
            let _ = state_tx.try_send(RequestState::Start);

            // Increase the global inflight requests counter
            requests_inflight.inc();

            // Inject connection information
            request.extensions_mut().insert(conn_info.clone());
            if let Some(v) = &tls_info {
                request.extensions_mut().insert(v.clone());
            }

            // Clone the stuff needed in the async block below
            let mut router = self.router.clone();
            let token = self.token_graceful.clone();
            let conn_info = conn_info.clone();
            let state_tx = state_tx.clone();
            let requests_inflight = requests_inflight.clone();

            // Return the future
            async move {
                // Since the future can be cancelled we need defer to decrease the counter in any case
                // to avoid leaking the inflight requests
                defer! {
                    requests_inflight.dec();
                }

                // Execute the request
                let result = router.call(request).await.map(|x| {
                    // Wrap the response body into a notifying one
                    let (parts, body) = x.into_parts();
                    let body = NotifyingBody::new(body, state_tx, RequestState::End);
                    Response::from_parts(parts, body)
                });

                // Check if we need to gracefully shutdown this connection
                if let Some(v) = max_requests_per_conn {
                    let req_count = conn_info.req_count.fetch_add(1, Ordering::SeqCst);
                    if req_count + 1 >= v {
                        token.cancel();
                    }
                }

                result
            }
        });

        // Serve the connection
        let conn = self.builder.serve_connection(Box::pin(stream), service);
        // Using mutable future reference requires pinning
        pin!(conn);

        loop {
            select! {
                biased; // Poll top-down

                // Immediately close the connection if was requested
                () = self.token_forceful.cancelled() => {
                    break;
                }

                // Start graceful shutdown of the connection
                () = self.token_graceful.cancelled() => {
                    // For H2: sends GOAWAY frames to the client
                    // For H1: disables keepalives
                    conn.as_mut().graceful_shutdown();

                    // Wait for the grace period to finish or connection to complete.
                    // Connection must still be polled for the shutdown to proceed.
                    // We don't really care for the result.
                    let _ = timeout(self.options.grace_period, conn.as_mut()).await;
                    break;
                },

                // Get request state change notifications
                Some(v) = state_rx.recv() => {
                    match v {
                        RequestState::Start => {
                            let reqs = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
                            debug!("{self}: Request started, stopping idle timer (now: {reqs})");

                            // Effectively disable the timer by setting it to 1 year into the future.
                            // TODO improve?
                            idle_timer.as_mut().reset(tokio::time::Instant::now() + YEAR);
                        },

                        RequestState::End => {
                            let reqs = self.requests.fetch_sub(1, Ordering::SeqCst) - 1;
                            debug!("{self}: Request finished (now: {reqs})");

                            // Check if the number of outstanding requests is now zero
                            if reqs == 0 {
                                debug!("{self}: No outstanding requests, starting timer");
                                // Enable the idle timer
                                idle_timer.as_mut().reset(tokio::time::Instant::now() + self.options.idle_timeout);
                            }
                        }
                    }
                },

                // See if the idle timeout has kicked in
                () = idle_timer.as_mut() => {
                    debug!("{self}: Idle timeout triggered, closing");

                    // Signal that we're closing
                    conn.as_mut().graceful_shutdown();
                    // Give the client some time to shut down
                    let _ = timeout(Duration::from_secs(5), conn.as_mut()).await;
                    break;
                },

                // Drive the connection by polling it
                v = conn.as_mut() => {
                    if let Err(e) = v {
                        return Err(anyhow!("unable to serve connection: {e:#}").into());
                    }

                    break;
                },
            }
        }

        Ok(())
    }
}

pub struct ServerBuilder {
    addr: Option<Addr>,
    router: Router,
    registry: Registry,
    metrics: Option<Metrics>,
    options: Options,
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
            options: Options::default(),
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

    /// Sets up metrics with provided Metrics
    /// Overrides `with_metrics_registry()`
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
    pub const fn with_options(mut self, options: Options) -> Self {
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
        let tls_opts = crate::tls::Options::default();
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

// Listens for new connections on addr with an optional TLS and serves provided Router
pub struct Server {
    addr: Addr,
    router: Router,
    tracker: TaskTracker,
    options: Options,
    metrics: Metrics,
    builder: Builder<TokioExecutor>,
    rustls_cfg: Option<Arc<rustls::ServerConfig>>,
}

impl Server {
    pub fn new(
        addr: Addr,
        router: Router,
        options: Options,
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
            .keep_alive_interval(Some(options.http2_keepalive_interval))
            .keep_alive_timeout(options.http2_keepalive_timeout);

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

    pub async fn serve(&self, token: CancellationToken) -> Result<(), Error> {
        let listener = Listener::new(self.addr.clone(), self.options.backlog)?;
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
        let conn = Conn {
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
                    "Server {}: {}: failed to handle connection: {e:#}",
                    conn.addr, remote_addr
                );
            }

            debug!("Server {}: {}: connection finished", conn.addr, remote_addr);
        });
    }

    pub async fn serve_with_listener(
        &self,
        listener: Listener,
        token: CancellationToken,
    ) -> Result<(), Error> {
        warn!(
            "Server {}: running (TLS: {})",
            self.addr,
            self.rustls_cfg.is_some()
        );

        loop {
            select! {
                biased; // Poll top-down

                () = token.cancelled() => {
                    // Stop accepting new connections
                    drop(listener);

                    warn!("Server {}: shutting down, waiting for the active connections to close for {}s", self.addr, self.options.grace_period.as_secs());
                    self.tracker.close();

                    select! {
                        () = sleep(self.options.grace_period + Duration::from_secs(5)) => {
                            warn!("Server {}: connections didn't close in time, shutting down anyway", self.addr);
                        },
                        () = self.tracker.wait() => {},
                    }

                    warn!("Server {}: shut down", self.addr);

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
                            warn!("Unable to accept connection: {e:#}");
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

// Creates a TCP listener with a backlog set
pub fn listen_tcp_backlog(addr: SocketAddr, backlog: u32) -> Result<TcpListener, Error> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .context("unable to open socket")?;

    socket
        .set_reuseaddr(true)
        .context("unable to set SO_REUSEADDR")?;
    socket.bind(addr).context("unable to bind socket")?;

    let socket = socket.listen(backlog).context("unable to listen socket")?;
    Ok(socket)
}

// Creates a Unix Socket listener with a backlog set
pub fn listen_unix_backlog(path: PathBuf, backlog: u32) -> Result<UnixListener, Error> {
    let socket = UnixSocket::new_stream().context("unable to open UNIX socket")?;

    if path.exists() {
        std::fs::remove_file(&path).context("unable to remove UNIX socket")?;
    }

    socket.bind(&path).context("unable to bind socket")?;

    let socket = socket.listen(backlog).context("unable to listen socket")?;

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
        .context("unable to set permissions on socket")?;

    Ok(socket)
}

#[async_trait]
impl Run for Server {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        self.serve(token).await?;
        Ok(())
    }
}
