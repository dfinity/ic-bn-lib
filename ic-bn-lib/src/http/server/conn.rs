use std::{
    fmt::Display,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use axum::{Router, extract::Request};
use http::Response;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use prometheus::core::{AtomicI64, GenericGauge};
use scopeguard::defer;
use tokio::{
    io::AsyncWriteExt,
    pin, select,
    sync::mpsc::channel,
    time::{sleep, timeout},
};
use tokio_io_timeout::TimeoutStream;
use tokio_util::sync::CancellationToken;
use tower_service::Service;
use tracing::debug;
use uuid::Uuid;

use crate::{
    http::{
        Error,
        body::NotifyingBody,
        server::{
            ProxyProtocolMode, ProxyProtocolStream, RequestState, ServerOptions, YEAR,
            metrics::Metrics, proxy_protocol::ProxyHeader,
        },
    },
    network::{Addr, AsyncCounter, AsyncReadWrite, Stats, TlsInfo, tls_handshake},
    tls::ALPN_ACME,
};

/// Connection information
#[derive(Debug)]
pub struct ConnInfo {
    pub id: Uuid,
    pub accepted_at: Instant,
    pub local_addr: Addr,
    pub remote_addr: Addr,
    pub traffic: Arc<Stats>,
    pub req_count: AtomicU64,
    pub close: CancellationToken,
}

impl Default for ConnInfo {
    fn default() -> Self {
        Self {
            id: Uuid::now_v7(),
            accepted_at: Instant::now(),
            local_addr: Addr::default(),
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

pub(crate) struct Conn {
    pub(crate) addr: Addr,
    pub(crate) remote_addr: Addr,
    pub(crate) router: Router,
    pub(crate) builder: Builder<TokioExecutor>,
    pub(crate) token_graceful: CancellationToken,
    pub(crate) token_forceful: CancellationToken,
    pub(crate) options: ServerOptions,
    pub(crate) metrics: Metrics,
    pub(crate) requests: AtomicU32,
    pub(crate) rustls_cfg: Option<Arc<rustls::ServerConfig>>,
}

impl Display for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] <- [{}]", self.addr, self.remote_addr)
    }
}

impl Conn {
    pub(crate) async fn handle(&self, stream: Box<dyn AsyncReadWrite>) -> Result<(), Error> {
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

        // Read & parse Proxy Protocol v2 header if configured
        let (stream, proxy_hdr): (Box<dyn AsyncReadWrite>, Option<ProxyHeader>) =
            if self.options.proxy_protocol_mode != ProxyProtocolMode::Off {
                let (stream, hdr) = ProxyProtocolStream::accept(stream)
                    .await
                    .context("unable to accept Proxy Protocol")?;

                if self.options.proxy_protocol_mode == ProxyProtocolMode::Forced && hdr.is_none() {
                    return Err(Error::NoProxyProtocolDetected);
                }

                (Box::new(stream), hdr)
            } else {
                (Box::new(stream), None)
            };

        // Use IPs from Proxy Protocol if available
        let (local_addr, remote_addr) = proxy_hdr
            .map(|x| (Addr::Tcp(x.dst), Addr::Tcp(x.src)))
            .unwrap_or_else(|| (self.addr.clone(), self.remote_addr.clone()));

        let conn_info = Arc::new(ConnInfo {
            id: Uuid::now_v7(),
            accepted_at,
            remote_addr,
            local_addr,
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
                "{}: handshake finished in {}ms (SNI: {:?}, proto: {:?}, cipher: {:?}, ALPN: {:?})",
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
        // Create a timer for idle connection tracking.
        // Falls back to 10 years if idle timer is not set (for simplicity)
        let mut idle_timer = Box::pin(sleep(self.options.idle_timeout.unwrap_or(10 * YEAR)));

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
                // Increase the global inflight requests counter
                requests_inflight.inc();

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
        let conn = self
            .builder
            .serve_connection_with_upgrades(Box::pin(stream), service);

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
                            debug!("{self}: request started");

                            // Effectively disable the timer by setting it to 10 years into the future.
                            // TODO improve?
                            if self.options.idle_timeout.is_some() {
                                debug!("{self}: stopping idle timer (now: {reqs})");
                                idle_timer.as_mut().reset(tokio::time::Instant::now() + 10 * YEAR);
                            }
                        },

                        RequestState::End => {
                            let reqs = self.requests.fetch_sub(1, Ordering::SeqCst) - 1;
                            debug!("{self}: request finished (now: {reqs})");

                            // Check if the number of outstanding requests is now zero
                            if let Some(v) = self.options.idle_timeout && reqs == 0 {
                                // Enable the idle timer
                                debug!("{self}: no outstanding requests, starting timer");
                                idle_timer.as_mut().reset(tokio::time::Instant::now() + v);
                            }
                        }
                    }
                },

                // See if the idle timeout has kicked in
                () = idle_timer.as_mut(), if self.options.idle_timeout.is_some() => {
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

#[cfg(test)]
mod test {
    use axum::{Extension, routing::get};
    use hyper_util::rt::TokioTimer;
    use ppp::v2;
    use prometheus::{
        Registry,
        proto::{Metric, MetricFamily},
    };
    use rustls::pki_types::ServerName;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::TlsConnector;

    use crate::{
        http::server::ProxyProtocolMode,
        tests::{TEST_CERT_1, TEST_KEY_1},
        tls::{ALPN_H1, ALPN_H2, resolver::StubResolver, verify::NoopServerCertVerifier},
    };

    use super::*;

    const LISTEN_ADDR: &str = "127.0.0.1:443";
    const REMOTE_ADDR: &str = "127.0.0.2:1234";

    fn install_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// Mirrors what `Server::new` does, but only the bits that matter here
    fn hyper_builder(opts: &ServerOptions) -> Builder<TokioExecutor> {
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Some(opts.http1_header_read_timeout))
            .keep_alive(true)
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(Some(opts.http2_max_streams));
        builder
    }

    /// Long network timeouts so that only the thing under test can close the connection
    fn test_opts() -> ServerOptions {
        ServerOptions {
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(30)),
            http1_header_read_timeout: Duration::from_secs(30),
            grace_period: Duration::from_secs(5),
            ..Default::default()
        }
    }

    fn make_conn(
        options: ServerOptions,
        registry: &Registry,
        router: Router,
        rustls_cfg: Option<Arc<rustls::ServerConfig>>,
    ) -> Conn {
        Conn {
            addr: Addr::Tcp(LISTEN_ADDR.parse().unwrap()),
            remote_addr: Addr::Tcp(REMOTE_ADDR.parse().unwrap()),
            router,
            builder: hyper_builder(&options),
            token_graceful: CancellationToken::new(),
            token_forceful: CancellationToken::new(),
            options,
            metrics: Metrics::new(registry),
            requests: AtomicU32::new(0),
            rustls_cfg,
        }
    }

    fn server_tls_config() -> Arc<rustls::ServerConfig> {
        install_crypto();

        let resolver = StubResolver::new(TEST_CERT_1.as_bytes(), TEST_KEY_1.as_bytes()).unwrap();
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec(), ALPN_ACME.to_vec()];

        Arc::new(cfg)
    }

    fn client_tls_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
        install_crypto();

        let mut cfg =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier::default()))
                .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|x| x.to_vec()).collect();

        Arc::new(cfg)
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), async move {
            listener.accept().await.map(|x| x.0)
        });
        (client.unwrap(), server.unwrap())
    }

    fn http_get(path: &str, close: bool) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\nHost: foo.bar\r\n{}\r\n",
            if close { "Connection: close\r\n" } else { "" }
        )
        .into_bytes()
    }

    /// Reads until the given suffix is seen, panicking on a premature EOF
    async fn read_until<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, suffix: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        let mut buf = [0u8; 4096];

        loop {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(
                n > 0,
                "premature EOF while waiting for {:?}, got: {:?}",
                String::from_utf8_lossy(suffix),
                String::from_utf8_lossy(&out)
            );

            out.extend_from_slice(&buf[..n]);
            if out.ends_with(suffix) {
                return out;
            }
        }
    }

    fn family(registry: &Registry, name: &str) -> Option<MetricFamily> {
        registry.gather().into_iter().find(|x| x.name() == name)
    }

    fn single(registry: &Registry, name: &str) -> Metric {
        let f =
            family(registry, name).unwrap_or_else(|| panic!("metric family '{name}' not found"));
        assert_eq!(
            f.get_metric().len(),
            1,
            "family '{name}' must have a single series"
        );
        f.get_metric()[0].clone()
    }

    fn label(m: &Metric, name: &str) -> String {
        m.get_label()
            .iter()
            .find(|x| x.name() == name)
            .unwrap_or_else(|| panic!("no label '{name}'"))
            .value()
            .to_string()
    }

    fn counter(registry: &Registry, name: &str) -> f64 {
        single(registry, name).get_counter().value()
    }

    fn gauge(registry: &Registry, name: &str) -> f64 {
        single(registry, name).get_gauge().value()
    }

    fn is_empty(registry: &Registry, name: &str) -> bool {
        family(registry, name).is_none_or(|x| x.get_metric().is_empty())
    }

    #[test]
    fn test_conn_info_default() {
        let ci = ConnInfo::default();

        assert_eq!(ci.req_count(), 0);
        assert!(!ci.close.is_cancelled());
        assert_eq!(ci.traffic.sent(), 0);
        assert_eq!(ci.traffic.rcvd(), 0);
        // Ids are UUIDv7 and must be unique per connection
        assert_eq!(ci.id.get_version_num(), 7);
        assert_ne!(ConnInfo::default().id, ci.id);
        assert!(ci.accepted_at.elapsed() < Duration::from_secs(5));
        assert_eq!(ci.local_addr.family(), "v4");
        assert_eq!(ci.remote_addr.family(), "v4");
    }

    #[test]
    fn test_conn_info_req_count_and_close() {
        let ci = ConnInfo::default();
        assert_eq!(ci.req_count(), 0);

        ci.req_count.fetch_add(41, Ordering::SeqCst);
        ci.req_count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(ci.req_count(), 42);

        assert!(!ci.close.is_cancelled());
        ci.close();
        assert!(ci.close.is_cancelled());
        // Idempotent
        ci.close();
        assert!(ci.close.is_cancelled());
    }

    #[test]
    fn test_conn_display() {
        let conn = make_conn(test_opts(), &Registry::new(), Router::new(), None);
        // `Addr`'s Display renders only the IP part
        assert_eq!(conn.to_string(), "[127.0.0.1] <- [127.0.0.2]");
    }

    #[tokio::test]
    async fn test_conn_handle_serves_request_and_records_metrics() {
        let registry = Registry::new();
        let router = Router::new().route("/foo", get(|| async { "hello" }));
        let conn = make_conn(test_opts(), &registry, router, None);

        let (mut client, server) = tcp_pair().await;
        let req = http_get("/foo", true);
        let req_len = req.len();

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&req).await.unwrap();
                let mut resp = vec![];
                client.read_to_end(&mut resp).await.unwrap();
                resp
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();

        let resp_len = resp.len();
        let resp = String::from_utf8_lossy(&resp).to_string();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.ends_with("hello"), "{resp}");

        // Non-TLS connection => "no" for both TLS labels, nothing forced/recycled
        let m = single(&registry, "conn_total");
        let mut labels = m
            .get_label()
            .iter()
            .map(|x| (x.name().to_string(), x.value().to_string()))
            .collect::<Vec<_>>();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                ("addr".to_string(), "127.0.0.1".to_string()),
                ("family".to_string(), "v4".to_string()),
                ("forced_close".to_string(), "no".to_string()),
                ("recycled".to_string(), "no".to_string()),
                ("tls_cipher".to_string(), "no".to_string()),
                ("tls_version".to_string(), "no".to_string()),
            ]
        );

        assert_eq!(m.get_counter().value(), 1.0);
        // NOTE: `ConnInfo::req_count` is only bumped when `max_requests_per_conn`
        // is set, so with it unset the per-connection request metrics stay at zero.
        // See `test_conn_handle_request_count_needs_max_requests_per_conn`.
        assert_eq!(counter(&registry, "conn_requests_total"), 0.0);
        // Byte counters must match exactly what crossed the socket
        assert_eq!(counter(&registry, "conn_bytes_rcvd_total"), req_len as f64);
        assert_eq!(counter(&registry, "conn_bytes_sent_total"), resp_len as f64);
        // Both gauges must be back to zero
        assert_eq!(gauge(&registry, "conn_open"), 0.0);
        assert_eq!(gauge(&registry, "conn_requests_inflight"), 0.0);

        let h = single(&registry, "conn_requests_per_conn")
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 1);
        assert_eq!(h.sample_sum(), 0.0);

        let h = single(&registry, "conn_duration_sec")
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 1);
        assert!(
            h.sample_sum() > 0.0 && h.sample_sum() < 10.0,
            "{:?}",
            h.sample_sum()
        );

        // No TLS => no handshake observation
        assert!(is_empty(&registry, "conn_tls_handshake_duration_sec"));
    }

    #[tokio::test]
    async fn test_conn_handle_keepalive_serves_multiple_requests() {
        let registry = Registry::new();
        let router = Router::new().route("/foo", get(|| async { "hello" }));
        // High enough not to trigger recycling, but enough to make the counter work
        let opts = ServerOptions {
            max_requests_per_conn: Some(100),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, router, None);

        let (mut client, server) = tcp_pair().await;

        let (res, ()) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                for _ in 0..3 {
                    client.write_all(&http_get("/foo", false)).await.unwrap();
                    read_until(&mut client, b"hello").await;
                }
                // Ask for the connection to be closed
                client.write_all(&http_get("/foo", true)).await.unwrap();
                let mut rest = vec![];
                client.read_to_end(&mut rest).await.unwrap();
                assert!(rest.ends_with(b"hello"));
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();

        assert_eq!(counter(&registry, "conn_total"), 1.0);
        assert_eq!(counter(&registry, "conn_requests_total"), 4.0);
        let h = single(&registry, "conn_requests_per_conn")
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 1);
        assert_eq!(h.sample_sum(), 4.0);
        // Not recycled - we asked to close
        assert_eq!(label(&single(&registry, "conn_total"), "recycled"), "no");
    }

    /// `ConnInfo::req_count` - and therefore the `conn_requests_total` /
    /// `conn_requests_per_conn` metrics - is only maintained when
    /// `max_requests_per_conn` is configured.
    #[tokio::test]
    async fn test_conn_handle_request_count_needs_max_requests_per_conn() {
        async fn serve_one(max: Option<u64>, registry: &Registry) -> f64 {
            let router = Router::new().route("/foo", get(|| async { "hello" }));
            let opts = ServerOptions {
                max_requests_per_conn: max,
                ..test_opts()
            };
            let conn = make_conn(opts, registry, router, None);

            let (mut client, server) = tcp_pair().await;
            let (res, ()) = timeout(Duration::from_secs(10), async {
                tokio::join!(conn.handle(Box::new(server)), async move {
                    client.write_all(&http_get("/foo", true)).await.unwrap();
                    let mut buf = vec![];
                    client.read_to_end(&mut buf).await.unwrap();
                    assert!(buf.ends_with(b"hello"));
                })
            })
            .await
            .expect("connection handling timed out");
            res.unwrap();

            counter(registry, "conn_requests_total")
        }

        let with_max = Registry::new();
        assert_eq!(serve_one(Some(100), &with_max).await, 1.0);

        let without_max = Registry::new();
        assert_eq!(serve_one(None, &without_max).await, 0.0);
    }

    #[tokio::test]
    async fn test_conn_handle_recycles_after_max_requests_per_conn() {
        let registry = Registry::new();
        let router = Router::new().route("/foo", get(|| async { "hello" }));
        let opts = ServerOptions {
            max_requests_per_conn: Some(2),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, router, None);
        let graceful = conn.token_graceful.clone();

        let (mut client, server) = tcp_pair().await;

        let (res, rest) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                // Keepalive requests - the server must recycle after exactly two of them
                client.write_all(&http_get("/foo", false)).await.unwrap();
                read_until(&mut client, b"hello").await;
                client.write_all(&http_get("/foo", false)).await.unwrap();
                read_until(&mut client, b"hello").await;

                let mut rest = vec![];
                client.read_to_end(&mut rest).await.unwrap();
                rest
            })
        })
        .await
        .expect("connection was not recycled in time");

        res.unwrap();
        assert!(
            rest.is_empty(),
            "unexpected trailing data: {:?}",
            String::from_utf8_lossy(&rest)
        );
        assert!(graceful.is_cancelled());
        assert!(!conn.token_forceful.is_cancelled());

        let m = single(&registry, "conn_total");
        assert_eq!(label(&m, "recycled"), "yes");
        assert_eq!(label(&m, "forced_close"), "no");
        assert_eq!(counter(&registry, "conn_requests_total"), 2.0);
        assert_eq!(
            single(&registry, "conn_requests_per_conn")
                .get_histogram()
                .sample_sum(),
            2.0
        );
    }

    #[tokio::test]
    async fn test_conn_handle_forceful_close() {
        let registry = Registry::new();
        let conn = make_conn(test_opts(), &registry, Router::new(), None);
        conn.token_forceful.cancel();

        let (_client, server) = tcp_pair().await;

        let res = timeout(Duration::from_secs(5), conn.handle(Box::new(server)))
            .await
            .expect("forceful close did not happen");
        res.unwrap();

        let m = single(&registry, "conn_total");
        assert_eq!(m.get_counter().value(), 1.0);
        assert_eq!(label(&m, "forced_close"), "yes");
        assert_eq!(label(&m, "recycled"), "no");

        assert_eq!(counter(&registry, "conn_requests_total"), 0.0);
        assert_eq!(counter(&registry, "conn_bytes_rcvd_total"), 0.0);
        assert_eq!(counter(&registry, "conn_bytes_sent_total"), 0.0);
        assert_eq!(gauge(&registry, "conn_open"), 0.0);

        let h = single(&registry, "conn_requests_per_conn")
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 1);
        assert_eq!(h.sample_sum(), 0.0);
    }

    #[tokio::test]
    async fn test_conn_handle_idle_timeout_closes_idle_connection() {
        let registry = Registry::new();
        let opts = ServerOptions {
            idle_timeout: Some(Duration::from_millis(100)),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, Router::new(), None);

        // The client never sends anything, so only the idle timer can close this
        let (mut client, server) = tcp_pair().await;

        let (res, leftover) = timeout(Duration::from_secs(5), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                let mut buf = vec![];
                client.read_to_end(&mut buf).await.unwrap();
                buf
            })
        })
        .await
        .expect("idle timeout did not fire");

        res.unwrap();
        assert!(leftover.is_empty());

        let m = single(&registry, "conn_total");
        assert_eq!(label(&m, "forced_close"), "no");
        assert_eq!(label(&m, "recycled"), "no");
        assert_eq!(counter(&registry, "conn_requests_total"), 0.0);
    }

    /// While a request is in flight the idle timer must be disabled, otherwise
    /// a slow request would trigger a graceful shutdown of a perfectly busy
    /// connection. Once it finishes, the timer has to be re-armed.
    #[tokio::test]
    async fn test_conn_handle_idle_timer_is_disabled_while_request_runs() {
        let registry = Registry::new();
        let router = Router::new().route(
            "/slow",
            get(|| async {
                sleep(Duration::from_millis(600)).await;
                "hello"
            }),
        );
        // Much shorter than the request itself
        let opts = ServerOptions {
            idle_timeout: Some(Duration::from_millis(300)),
            max_requests_per_conn: Some(100),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, router, None);

        let (mut client, server) = tcp_pair().await;

        let (res, (first, rest)) = timeout(Duration::from_secs(15), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                // Two back-to-back keepalive requests, each of them much longer
                // than the idle timeout
                client.write_all(&http_get("/slow", false)).await.unwrap();
                let first = read_until(&mut client, b"hello").await;
                client.write_all(&http_get("/slow", false)).await.unwrap();
                read_until(&mut client, b"hello").await;

                // ...and only now may the idle timer close the connection
                let mut rest = vec![];
                client.read_to_end(&mut rest).await.unwrap();
                (String::from_utf8_lossy(&first).to_string(), rest)
            })
        })
        .await
        .expect("idle timeout did not fire after the requests finished");

        res.unwrap();
        // The first response must be a plain keepalive one: a `connection: close`
        // in it would mean the idle timer had already started the shutdown
        assert!(
            !first.to_ascii_lowercase().contains("connection: close"),
            "{first}"
        );
        assert!(rest.is_empty(), "{:?}", String::from_utf8_lossy(&rest));
        assert_eq!(counter(&registry, "conn_requests_total"), 2.0);
        assert_eq!(gauge(&registry, "conn_requests_inflight"), 0.0);
        assert_eq!(
            label(&single(&registry, "conn_total"), "forced_close"),
            "no"
        );
    }

    #[tokio::test]
    async fn test_conn_handle_malformed_request_returns_error_but_records_metrics() {
        let registry = Registry::new();
        let conn = make_conn(test_opts(), &registry, Router::new(), None);

        let (mut client, server) = tcp_pair().await;

        let (res, _) = timeout(Duration::from_secs(5), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(b"GET\r\n\r\n").await.unwrap();
                let mut buf = vec![];
                let _ = client.read_to_end(&mut buf).await;
                buf
            })
        })
        .await
        .expect("connection handling timed out");

        let err = res.expect_err("malformed request must fail the connection");
        assert!(
            err.to_string().contains("unable to serve connection"),
            "{err:#}"
        );

        // Metrics are recorded even when serving failed
        assert_eq!(counter(&registry, "conn_total"), 1.0);
        assert_eq!(counter(&registry, "conn_requests_total"), 0.0);
        assert_eq!(counter(&registry, "conn_bytes_rcvd_total"), 7.0);
        assert_eq!(gauge(&registry, "conn_open"), 0.0);
    }

    /// Router that echoes back the addresses recorded in `ConnInfo`
    fn conn_info_router() -> Router {
        Router::new().route(
            "/addr",
            get(|Extension(ci): Extension<Arc<ConnInfo>>| async move {
                match (&ci.remote_addr, &ci.local_addr) {
                    (Addr::Tcp(r), Addr::Tcp(l)) => format!("{r}|{l}"),
                    _ => "unexpected".to_string(),
                }
            }),
        )
    }

    #[tokio::test]
    async fn test_conn_handle_injects_conn_info_with_socket_addresses() {
        let registry = Registry::new();
        let conn = make_conn(test_opts(), &registry, conn_info_router(), None);

        let (mut client, server) = tcp_pair().await;

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/addr", true)).await.unwrap();
                let mut buf = vec![];
                client.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).to_string()
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();
        assert!(resp.ends_with("127.0.0.2:1234|127.0.0.1:443"), "{resp}");
    }

    #[tokio::test]
    async fn test_conn_handle_proxy_protocol_overrides_addresses() {
        let registry = Registry::new();
        let opts = ServerOptions {
            proxy_protocol_mode: ProxyProtocolMode::Enabled,
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, conn_info_router(), None);

        let mut payload = v2::Builder::with_addresses(
            v2::Version::Two | v2::Command::Proxy,
            v2::Protocol::Stream,
            v2::IPv4::new([1, 1, 1, 1], [2, 2, 2, 2], 31337, 443),
        )
        .build()
        .unwrap();
        payload.extend_from_slice(&http_get("/addr", true));
        let payload_len = payload.len();

        let (mut client, server) = tcp_pair().await;

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&payload).await.unwrap();
                let mut buf = vec![];
                client.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).to_string()
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();
        // src -> remote, dst -> local
        assert!(resp.ends_with("1.1.1.1:31337|2.2.2.2:443"), "{resp}");
        // The Proxy Protocol header itself is counted as received traffic
        assert_eq!(
            counter(&registry, "conn_bytes_rcvd_total"),
            payload_len as f64
        );
    }

    #[tokio::test]
    async fn test_conn_handle_proxy_protocol_enabled_without_header_falls_back() {
        let registry = Registry::new();
        let opts = ServerOptions {
            proxy_protocol_mode: ProxyProtocolMode::Enabled,
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, conn_info_router(), None);

        let (mut client, server) = tcp_pair().await;

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/addr", true)).await.unwrap();
                let mut buf = vec![];
                client.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).to_string()
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();
        // No header -> the socket addresses are used
        assert!(resp.ends_with("127.0.0.2:1234|127.0.0.1:443"), "{resp}");
    }

    #[tokio::test]
    async fn test_conn_handle_proxy_protocol_forced_without_header_fails() {
        let registry = Registry::new();
        let opts = ServerOptions {
            proxy_protocol_mode: ProxyProtocolMode::Forced,
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, conn_info_router(), None);

        let (mut client, server) = tcp_pair().await;

        let (res, _) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/addr", true)).await.unwrap();
                let mut buf = vec![];
                let _ = client.read_to_end(&mut buf).await;
                buf
            })
        })
        .await
        .expect("connection handling timed out");

        assert!(
            matches!(res, Err(Error::NoProxyProtocolDetected)),
            "{res:?}"
        );

        // We bail out before any connection metrics are recorded
        assert!(is_empty(&registry, "conn_total"));
        assert!(is_empty(&registry, "conn_open"));
        assert!(is_empty(&registry, "conn_requests_total"));
    }

    #[tokio::test]
    async fn test_conn_handle_tls_records_tls_info_and_metrics() {
        let registry = Registry::new();
        let router = Router::new().route(
            "/tls",
            get(|Extension(ti): Extension<Arc<TlsInfo>>| async move {
                format!("{:?}|{:?}", ti.sni, ti.alpn)
            }),
        );
        let opts = ServerOptions {
            max_requests_per_conn: Some(100),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, router, Some(server_tls_config()));

        let (client, server) = tcp_pair().await;

        let (res, resp) = timeout(Duration::from_secs(15), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                let connector = TlsConnector::from(client_tls_config(&[ALPN_H1]));
                let mut tls = connector
                    .connect(ServerName::try_from("foo.bar").unwrap(), client)
                    .await
                    .unwrap();

                tls.write_all(&http_get("/tls", true)).await.unwrap();
                let mut buf = vec![];
                tls.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).to_string()
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();
        // The `Arc<TlsInfo>` extension must be visible to the handler
        assert!(
            resp.ends_with(r#"Some("foo.bar")|Some("http/1.1")"#),
            "{resp}"
        );

        let m = single(&registry, "conn_total");
        assert_eq!(label(&m, "tls_version"), "TLSv1_3");
        let cipher = label(&m, "tls_cipher");
        assert!(cipher.starts_with("TLS13_"), "{cipher}");
        assert_eq!(counter(&registry, "conn_requests_total"), 1.0);

        // The handshake duration is recorded with the 4-label set only
        let m = single(&registry, "conn_tls_handshake_duration_sec");
        assert_eq!(m.get_label().len(), 4);
        assert_eq!(label(&m, "tls_version"), "TLSv1_3");
        assert_eq!(m.get_histogram().sample_count(), 1);
        assert!(m.get_histogram().sample_sum() > 0.0);
    }

    #[tokio::test]
    async fn test_conn_handle_acme_alpn_closes_connection_without_metrics() {
        let registry = Registry::new();
        let conn = make_conn(
            test_opts(),
            &registry,
            Router::new(),
            Some(server_tls_config()),
        );

        let (client, server) = tcp_pair().await;

        let (res, (alpn, leftover)) = timeout(Duration::from_secs(15), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                let connector = TlsConnector::from(client_tls_config(&[ALPN_ACME]));
                let mut tls = connector
                    .connect(ServerName::try_from("foo.bar").unwrap(), client)
                    .await
                    .unwrap();

                let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                let mut buf = vec![];
                tls.read_to_end(&mut buf).await.unwrap();
                (alpn, buf)
            })
        })
        .await
        .expect("ACME connection was not closed");

        res.unwrap();
        assert_eq!(alpn, Some(ALPN_ACME.to_vec()));
        // The handshake alone is the challenge - nothing is served
        assert!(leftover.is_empty());

        // We return before any connection metrics are recorded
        assert!(is_empty(&registry, "conn_total"));
        assert!(is_empty(&registry, "conn_open"));
        assert!(is_empty(&registry, "conn_tls_handshake_duration_sec"));
    }

    /// Router with a handler that never finishes on its own
    fn stuck_router() -> Router {
        Router::new().route(
            "/slow",
            get(|| async {
                sleep(Duration::from_secs(30)).await;
                "hello"
            }),
        )
    }

    /// A graceful shutdown requested while a request is still running must not
    /// wait for it forever - the grace period caps it.
    #[tokio::test]
    async fn test_conn_handle_graceful_shutdown_is_capped_by_grace_period() {
        let registry = Registry::new();
        let opts = ServerOptions {
            grace_period: Duration::from_millis(200),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, stuck_router(), None);
        let graceful = conn.token_graceful.clone();

        let (mut client, server) = tcp_pair().await;
        let start = Instant::now();

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/slow", false)).await.unwrap();
                // Let the request actually start before asking for the shutdown
                sleep(Duration::from_millis(200)).await;
                graceful.cancel();

                let mut buf = vec![];
                let _ = client.read_to_end(&mut buf).await;
                buf
            })
        })
        .await
        .expect("graceful shutdown was not capped by the grace period");

        res.unwrap();
        // Nowhere near the handler's 30s sleep
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        // The slow response never made it out
        assert!(resp.is_empty(), "{:?}", String::from_utf8_lossy(&resp));

        let m = single(&registry, "conn_total");
        assert_eq!(label(&m, "recycled"), "yes");
        assert_eq!(label(&m, "forced_close"), "no");
        // The inflight gauge must not leak when the request future is dropped
        assert_eq!(gauge(&registry, "conn_requests_inflight"), 0.0);
        assert_eq!(gauge(&registry, "conn_open"), 0.0);
    }

    /// The forceful token wins over the grace period: it must cut an in-flight
    /// request immediately instead of waiting for it.
    #[tokio::test]
    async fn test_conn_handle_forceful_close_interrupts_inflight_request() {
        let registry = Registry::new();
        let opts = ServerOptions {
            // Long enough that only the forceful path can end this connection
            grace_period: Duration::from_secs(30),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, stuck_router(), None);
        let forceful = conn.token_forceful.clone();

        let (mut client, server) = tcp_pair().await;
        let start = Instant::now();

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/slow", false)).await.unwrap();
                sleep(Duration::from_millis(200)).await;
                forceful.cancel();

                let mut buf = vec![];
                let _ = client.read_to_end(&mut buf).await;
                buf
            })
        })
        .await
        .expect("forceful close did not interrupt the request");

        res.unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        assert!(resp.is_empty(), "{:?}", String::from_utf8_lossy(&resp));

        let m = single(&registry, "conn_total");
        assert_eq!(label(&m, "forced_close"), "yes");
        assert_eq!(label(&m, "recycled"), "no");
        assert_eq!(gauge(&registry, "conn_requests_inflight"), 0.0);
        assert_eq!(gauge(&registry, "conn_open"), 0.0);
    }

    /// `conn_open` / `conn_requests_inflight` are gauges - they must be at 1
    /// *while* the request runs and back to 0 afterwards.
    #[tokio::test]
    async fn test_conn_handle_gauges_are_live_during_request() {
        let registry = Registry::new();
        let reg = registry.clone();
        let router = Router::new().route(
            "/gauges",
            get(move || {
                let reg = reg.clone();
                async move {
                    format!(
                        "{}|{}",
                        gauge(&reg, "conn_open"),
                        gauge(&reg, "conn_requests_inflight")
                    )
                }
            }),
        );
        let conn = make_conn(test_opts(), &registry, router, None);

        let (mut client, server) = tcp_pair().await;

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/gauges", true)).await.unwrap();
                let mut buf = vec![];
                client.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).to_string()
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();
        assert!(resp.ends_with("1|1"), "{resp}");

        assert_eq!(gauge(&registry, "conn_open"), 0.0);
        assert_eq!(gauge(&registry, "conn_requests_inflight"), 0.0);
    }

    /// The `Arc<TlsInfo>` extension must be absent on a plaintext connection
    #[tokio::test]
    async fn test_conn_handle_plaintext_has_no_tls_info_extension() {
        let registry = Registry::new();
        let router = Router::new().route(
            "/tls",
            get(|ti: Option<Extension<Arc<TlsInfo>>>| async move {
                if ti.is_some() { "tls" } else { "plain" }
            }),
        );
        let conn = make_conn(test_opts(), &registry, router, None);

        let (mut client, server) = tcp_pair().await;

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/tls", true)).await.unwrap();
                let mut buf = vec![];
                client.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).to_string()
            })
        })
        .await
        .expect("connection handling timed out");

        res.unwrap();
        assert!(resp.ends_with("plain"), "{resp}");
        assert_eq!(label(&single(&registry, "conn_total"), "tls_version"), "no");
        assert_eq!(label(&single(&registry, "conn_total"), "tls_cipher"), "no");
    }

    /// HTTP/2 over cleartext (prior knowledge) - the auto-builder must detect the
    /// H2 preface and serve it. With `max_requests_per_conn` of 1 the server also
    /// has to send a GOAWAY right after the first request, which is what lets the
    /// client's connection future finish.
    #[tokio::test]
    async fn test_conn_handle_h2c_serves_request_and_goes_away_after_limit() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Empty};

        let registry = Registry::new();
        let router = Router::new().route("/foo", get(|| async { "hello" }));
        let opts = ServerOptions {
            max_requests_per_conn: Some(1),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, router, None);

        let (client, server) = tcp_pair().await;

        let (res, body) = timeout(Duration::from_secs(15), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                let (mut sender, h2) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
                    TokioExecutor::new(),
                    TokioIo::new(client),
                )
                .await
                .unwrap();
                let driver = tokio::spawn(h2);

                let req = http::Request::builder()
                    .uri("http://foo.bar/foo")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                let resp = sender.send_request(req).await.unwrap();
                assert_eq!(resp.status(), 200);
                assert_eq!(resp.version(), http::Version::HTTP_2);
                let body = resp.into_body().collect().await.unwrap().to_bytes();

                // The GOAWAY makes the client's connection future resolve
                drop(sender);
                let _ = driver.await;
                body
            })
        })
        .await
        .expect("h2c connection did not finish");

        res.unwrap();
        assert_eq!(&body[..], b"hello");

        let m = single(&registry, "conn_total");
        assert_eq!(label(&m, "recycled"), "yes");
        assert_eq!(label(&m, "forced_close"), "no");
        // No TLS was used even though this is H2
        assert_eq!(label(&m, "tls_version"), "no");
        assert_eq!(counter(&registry, "conn_requests_total"), 1.0);
        assert!(counter(&registry, "conn_bytes_rcvd_total") > 0.0);
    }

    /// Boundary case of `max_requests_per_conn`: with a limit of 1 the very first
    /// request triggers recycling, but its response must still be delivered in
    /// full because the graceful shutdown keeps polling the connection.
    #[tokio::test]
    async fn test_conn_handle_max_requests_per_conn_one() {
        let registry = Registry::new();
        let router = Router::new().route("/foo", get(|| async { "hello" }));
        let opts = ServerOptions {
            max_requests_per_conn: Some(1),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, router, None);

        let (mut client, server) = tcp_pair().await;

        let (res, resp) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                // Keepalive request - only the limit may close this connection
                client.write_all(&http_get("/foo", false)).await.unwrap();
                let mut buf = vec![];
                client.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).to_string()
            })
        })
        .await
        .expect("connection was not recycled after a single request");

        res.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.ends_with("hello"), "{resp}");
        assert!(conn.token_graceful.is_cancelled());

        let m = single(&registry, "conn_total");
        assert_eq!(label(&m, "recycled"), "yes");
        assert_eq!(counter(&registry, "conn_requests_total"), 1.0);
    }

    /// An HTTP/1 connection that goes silent after a request must be torn down by
    /// the read timeout even with no idle timeout configured. Since the timeout
    /// hits while hyper is waiting for the *next* request head, it is reported as
    /// a clean close rather than an error - unlike a mid-message failure, see
    /// `test_conn_handle_malformed_request_returns_error_but_records_metrics`.
    #[tokio::test]
    async fn test_conn_handle_read_timeout_closes_silent_connection() {
        let registry = Registry::new();
        let router = Router::new().route("/foo", get(|| async { "hello" }));
        let opts = ServerOptions {
            read_timeout: Some(Duration::from_millis(200)),
            idle_timeout: None,
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, router, None);

        let (mut client, server) = tcp_pair().await;
        let start = Instant::now();

        let (res, leftover) = timeout(Duration::from_secs(5), async {
            tokio::join!(conn.handle(Box::new(server)), async move {
                client.write_all(&http_get("/foo", false)).await.unwrap();
                read_until(&mut client, b"hello").await;
                // ...and now stay silent
                let mut buf = vec![];
                let _ = client.read_to_end(&mut buf).await;
                buf
            })
        })
        .await
        .expect("read timeout did not close the connection");

        res.unwrap();
        // The client sees a plain EOF, no extra bytes
        assert!(leftover.is_empty(), "{leftover:?}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );

        // Metrics are still recorded on the error path
        let m = single(&registry, "conn_total");
        assert_eq!(m.get_counter().value(), 1.0);
        assert_eq!(label(&m, "forced_close"), "no");
        assert_eq!(label(&m, "recycled"), "no");
        assert!(counter(&registry, "conn_bytes_sent_total") > 0.0);
        assert_eq!(gauge(&registry, "conn_open"), 0.0);
    }

    #[tokio::test]
    async fn test_conn_handle_tls_handshake_timeout() {
        let registry = Registry::new();
        let opts = ServerOptions {
            tls_handshake_timeout: Duration::from_millis(100),
            ..test_opts()
        };
        let conn = make_conn(opts, &registry, Router::new(), Some(server_tls_config()));

        // The client connects but never starts the handshake
        let (_client, server) = tcp_pair().await;

        let res = timeout(Duration::from_secs(5), conn.handle(Box::new(server)))
            .await
            .expect("TLS handshake timeout did not fire");

        let err = res.expect_err("handshake must have timed out");
        assert!(
            err.to_string().contains("TLS handshake timed out"),
            "{err:#}"
        );
        assert!(is_empty(&registry, "conn_total"));
    }
}
