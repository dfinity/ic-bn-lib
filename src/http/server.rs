use std::{
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use axum::{extract::Request, Router};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use prometheus::{
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
    register_int_gauge_vec_with_registry, HistogramVec, IntCounterVec, IntGaugeVec, Registry,
};
use rustls::{server::ServerConnection, CipherSuite, ProtocolVersion};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, UnixListener, UnixSocket},
    select,
    time::sleep,
};
use tokio_rustls::TlsAcceptor;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower_service::Service;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{AsyncCounter, Error, Stats, ALPN_ACME};
use crate::tasks::Run;

pub const CONN_DURATION_BUCKETS: &[f64] = &[1.0, 8.0, 32.0, 64.0, 256.0, 512.0, 1024.0];
pub const CONN_REQUESTS: &[f64] = &[1.0, 4.0, 8.0, 16.0, 32.0, 64.0, 256.0];

// Blanket async read+write trait for streams Box-ing
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

#[derive(Clone)]
pub struct Metrics {
    conns_open: IntGaugeVec,
    requests: IntCounterVec,
    bytes_sent: IntCounterVec,
    bytes_rcvd: IntCounterVec,
    conn_duration: HistogramVec,
    requests_per_conn: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const LABELS: &[&str] = &["addr", "tls", "family", "forced_close", "recycled"];

        Self {
            conns_open: register_int_gauge_vec_with_registry!(
                format!("conn_open"),
                format!("Number of currently open connections"),
                &LABELS[0..3],
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
        }
    }
}

#[derive(Clone, Copy)]
pub struct Options {
    pub backlog: u32,
    pub http1_header_read_timeout: Duration,
    pub http2_max_streams: u32,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
    pub grace_period: Duration,
    pub max_requests_per_conn: Option<u64>,
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

struct Conn {
    addr: Addr,
    remote_addr: Addr,
    router: Router,
    builder: Builder<TokioExecutor>,
    token: CancellationToken,
    token_close: CancellationToken,
    options: Options,
    metrics: Metrics,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Display for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Server {}: {}", self.addr, self.remote_addr,)
    }
}

impl Conn {
    async fn tls_handshake(
        &self,
        stream: impl AsyncReadWrite,
    ) -> Result<(impl AsyncReadWrite, TlsInfo), Error> {
        debug!("{}: performing TLS handshake", self);

        // Perform the TLS handshake
        let start = Instant::now();
        let stream = self
            .tls_acceptor
            .as_ref()
            .unwrap()
            .accept(stream)
            .await
            .context("unable to accept TLS")?;
        let duration = start.elapsed();

        let conn = stream.get_ref().1;
        let mut tls_info = TlsInfo::try_from(conn)?;
        tls_info.handshake_dur = duration;

        debug!(
            "{}: handshake finished in {}ms (server: {:?}, proto: {:?}, cipher: {:?}, ALPN: {:?})",
            self,
            duration.as_millis(),
            tls_info.sni,
            tls_info.protocol,
            tls_info.cipher,
            tls_info.alpn,
        );

        Ok((stream, tls_info))
    }

    async fn handle(&self, stream: Box<dyn AsyncReadWrite>) -> Result<(), Error> {
        let accepted_at = Instant::now();

        debug!("{}: got a new connection", self);

        // Prepare metric labels
        let addr = self.addr.to_string();
        let labels = &mut [
            addr.as_str(), // Listening addr
            if self.tls_acceptor.is_some() {
                "yes"
            } else {
                "no"
            }, // Is TLS
            self.remote_addr.family(),
            "no",
            "no",
        ];

        self.metrics
            .conns_open
            .with_label_values(&labels[0..3])
            .inc();

        // Wrap with traffic counter
        let (stream, stats) = AsyncCounter::new(stream);

        let conn_info = Arc::new(ConnInfo {
            id: Uuid::now_v7(),
            accepted_at,
            remote_addr: self.remote_addr.clone(),
            traffic: stats.clone(),
            req_count: AtomicU64::new(0),
            close: self.token_close.clone(),
        });

        let result = self.handle_inner(stream, conn_info.clone()).await;

        // Record connection metrics
        let (sent, rcvd) = (stats.sent(), stats.rcvd());
        let dur = accepted_at.elapsed().as_secs_f64();
        let reqs = conn_info.req_count.load(Ordering::SeqCst);

        // force-closed
        if self.token_close.is_cancelled() {
            labels[3] = "yes";
        }
        // recycled
        if self.token.is_cancelled() {
            labels[4] = "yes";
        }

        self.metrics
            .conns_open
            .with_label_values(&labels[0..3])
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
            self.token.is_cancelled(),
            self.token_close.is_cancelled(),
        );

        result
    }

    async fn handle_inner(
        &self,
        stream: impl AsyncReadWrite + 'static,
        conn_info: Arc<ConnInfo>,
    ) -> Result<(), Error> {
        // Perform TLS handshake if we're in TLS mode
        let (stream, tls_info): (Box<dyn AsyncReadWrite>, _) = if self.tls_acceptor.is_some() {
            let (mut stream, tls_info) = self.tls_handshake(stream).await?;

            // Close the connection if agreed ALPN is ACME - the handshake is enough for challenge
            if tls_info
                .alpn
                .as_ref()
                .is_some_and(|x| x.as_bytes() == ALPN_ACME)
            {
                debug!("{}: ACME ALPN - closing connection", self);

                stream
                    .shutdown()
                    .await
                    .context("unable to shutdown stream")?;

                return Ok(());
            }

            (Box::new(stream), Some(Arc::new(tls_info)))
        } else {
            (Box::new(stream), None)
        };

        // Convert stream from Tokio to Hyper
        let stream = TokioIo::new(stream);
        let max_requests_per_conn = self.options.max_requests_per_conn;

        // Convert router to Hyper service
        let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
            let conn_count = conn_info.req_count.fetch_add(1, Ordering::SeqCst);

            // Inject connection information
            request.extensions_mut().insert(conn_info.clone());
            if let Some(v) = &tls_info {
                request.extensions_mut().insert(v.clone());
            }

            // Serve the request
            let mut router = self.router.clone();
            let token = self.token.clone();

            async move {
                // Get the result
                let result = router.call(request).await;

                // Check if we need to gracefully shutdown this connection
                if let Some(v) = max_requests_per_conn {
                    if conn_count + 1 >= v {
                        token.cancel();
                    }
                }

                result
            }
        });

        // Serve the connection
        let conn = self.builder.serve_connection(stream, service);
        // Using mutable future reference requires pinning, otherwise .await consumes it
        tokio::pin!(conn);

        select! {
            biased; // Poll top-down

            // Immediately close the connection if was requested
            () = self.token_close.cancelled() => {
                return Ok(());
            }

            () = self.token.cancelled() => {
                // Start graceful shutdown of the connection
                // For H2: sends GOAWAY frames to the client
                // For H1: disables keepalives
                conn.as_mut().graceful_shutdown();

                // Wait for the grace period to finish or connection to complete.
                // Connection must still be polled for the shutdown to proceed.
                select! {
                    biased;
                    () = sleep(self.options.grace_period) => return Ok(()),
                    _ = conn.as_mut() => {},
                }
            }

            v = conn.as_mut() => {
                if let Err(e) = v {
                    return Err(anyhow!("unable to serve connection: {e:#}").into());
                }
            },
        }

        Ok(())
    }
}

// Listens for new connections on addr with an optional TLS and serves provided Router
pub struct Server {
    addr: Addr,
    router: Router,
    tracker: TaskTracker,
    options: Options,
    metrics: Metrics,
    tls_acceptor: Option<TlsAcceptor>,
}

impl Server {
    pub fn new(
        addr: Addr,
        router: Router,
        options: Options,
        metrics: Metrics,
        rustls_cfg: Option<rustls::ServerConfig>,
    ) -> Self {
        Self {
            addr,
            router,
            options,
            metrics,
            tracker: TaskTracker::new(),
            tls_acceptor: rustls_cfg.map(|x| TlsAcceptor::from(Arc::new(x))),
        }
    }

    pub fn new_with_registry(
        addr: Addr,
        router: Router,
        options: Options,
        registry: &Registry,
        rustls_cfg: Option<rustls::ServerConfig>,
    ) -> Self {
        Self::new(addr, router, options, Metrics::new(registry), rustls_cfg)
    }

    pub async fn serve(&self, token: CancellationToken) -> Result<(), Error> {
        let listener = Listener::new(self.addr.clone(), self.options.backlog)?;
        self.serve_with_listener(listener, token).await
    }

    pub async fn serve_with_listener(
        &self,
        listener: Listener,
        token: CancellationToken,
    ) -> Result<(), Error> {
        // Prepare Hyper connection builder
        // It automatically figures out whether to do HTTP1 or HTTP2
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(self.options.http1_header_read_timeout))
            .keep_alive(true)
            .http2()
            .adaptive_window(true)
            .max_concurrent_streams(Some(self.options.http2_max_streams))
            .timer(TokioTimer::new()) // Needed for the keepalives below
            .keep_alive_interval(Some(self.options.http2_keepalive_interval))
            .keep_alive_timeout(self.options.http2_keepalive_timeout);

        warn!(
            "Server {}: running (TLS: {})",
            self.addr,
            self.tls_acceptor.is_some()
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

                    // Create a new connection
                    // Router & TlsAcceptor are both Arc<> inside so it's cheap to clone
                    // Builder is a bit more complex, but cloning is better than to create it again
                    let conn = Conn {
                        addr: self.addr.clone(),
                        remote_addr: remote_addr.clone(),
                        router: self.router.clone(),
                        builder: builder.clone(),
                        token: token.child_token(),
                        token_close: CancellationToken::new(),
                        options: self.options,
                        metrics: self.metrics.clone(), // All metrics have Arc inside
                        tls_acceptor: self.tls_acceptor.clone(),
                    };

                    // Spawn a task to handle connection & track it
                    self.tracker.spawn(async move {
                        if let Err(e) = conn.handle(stream).await {
                            info!("Server {}: {}: failed to handle connection: {e:#}", conn.addr, remote_addr);
                        }

                        debug!(
                            "Server {}: {}: connection finished",
                            conn.addr, remote_addr
                        );
                    });
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
