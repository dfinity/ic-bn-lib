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
