use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::RandomState;
use anyhow::anyhow;
use async_trait::async_trait;
use http::uri::Scheme;
use http_body::Body;
use hyper::body::Incoming;
use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::{
    client::legacy::{Client as ClientHyper, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use moka::sync::{Cache, CacheBuilder};
use prometheus::Registry;
use rustls::pki_types::DnsName;
use scopeguard::defer;

use crate::http::dns::{CloneableHyperDnsResolver, Resolver};

use super::{ClientHttp, Error, Metrics, Options};

#[derive(Debug, Clone)]
pub struct HyperClient<B, R = Resolver> {
    cli: ClientHyper<HttpsConnector<HttpConnector<R>>, B>,
}

impl<B> Default for HyperClient<B>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn default() -> Self {
        Self::new(Options::default(), Resolver::default())
    }
}

impl<B, R> HyperClient<B, R>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    pub fn new(opts: Options, resolver: R) -> Self {
        let mut http_conn = HttpConnector::new_with_resolver(resolver);
        http_conn.set_connect_timeout(Some(opts.timeout_connect));
        http_conn.set_keepalive(opts.tcp_keepalive);
        http_conn.enforce_http(false);
        http_conn.set_nodelay(true);
        http_conn.set_reuse_address(true);

        let builder = HttpsConnector::<HttpConnector>::builder();
        let mut builder = if let Some(mut v) = opts.tls_config {
            // Hyper is sad when we set our ALPN
            v.alpn_protocols = vec![];
            builder.with_tls_config(v)
        } else {
            builder.with_webpki_roots()
        }
        .https_or_http();

        if let Some(v) = opts.tls_fixed_name {
            let name = DnsName::try_from(v).expect("able to parse as DNSName");
            builder = builder.with_server_name_resolver(FixedServerNameResolver::new(
                rustls::pki_types::ServerName::DnsName(name),
            ))
        }

        let https_conn = builder.enable_all_versions().wrap_connector(http_conn);

        let mut builder = ClientHyper::builder(TokioExecutor::new());
        builder
            .pool_max_idle_per_host(opts.pool_idle_max.unwrap_or(usize::MAX))
            .http2_adaptive_window(true)
            .http2_only(opts.http2_only)
            .pool_idle_timeout(opts.pool_idle_timeout)
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new())
            .retry_canceled_requests(true);

        if let Some(v) = opts.pool_idle_max {
            builder.pool_max_idle_per_host(v);
        }

        let cli = builder.build(https_conn);

        Self { cli }
    }
}

#[async_trait]
impl<B, R> ClientHttp<B> for HyperClient<B, R>
where
    B: Body + Send + 'static + Unpin + Debug,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    async fn execute(&self, req: http::Request<B>) -> Result<http::Response<Incoming>, Error> {
        self.cli
            .request(req)
            .await
            .map_err(|e| Error::Generic(anyhow!("Error executing HTTP request: {e:#}")))
    }
}

#[derive(Debug, Clone)]
pub struct HyperClientLeastLoaded<B, R = Resolver> {
    inner: Arc<Vec<HyperClientLeastLoadedInner<B, R>>>,
    metrics: Option<Metrics>,
}

#[derive(Debug, Clone)]
struct HyperClientLeastLoadedInner<B, R = Resolver> {
    cli: HyperClient<B, R>,
    outstanding: Cache<String, Arc<AtomicUsize>, RandomState>,
}

impl<B, R> HyperClientLeastLoaded<B, R>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    pub fn new(opts: Options, resolver: R, count: usize, registry: Option<&Registry>) -> Self {
        let inner = (0..count)
            .map(|_| HyperClientLeastLoadedInner {
                cli: HyperClient::new(opts.clone(), resolver.clone()),
                // Creates a cache with some sensible max capacity to hold target hosts.
                // If the host isn't contacted in 10min then we remove it.
                outstanding: CacheBuilder::new(16384)
                    .time_to_idle(Duration::from_secs(600))
                    .build_with_hasher(RandomState::default()),
            })
            .collect::<Vec<_>>();

        Self {
            inner: Arc::new(inner),
            metrics: registry.map(Metrics::new),
        }
    }
}

#[async_trait]
impl<B, R> ClientHttp<B> for HyperClientLeastLoaded<B, R>
where
    B: Body + Send + 'static + Unpin + Debug,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    async fn execute(&self, req: http::Request<B>) -> Result<http::Response<Incoming>, Error> {
        let uri = req.uri();
        let host = uri.host().unwrap_or_default();
        let port = uri.port_u16().unwrap_or_else(|| {
            if uri.scheme() == Some(&Scheme::HTTPS) {
                443
            } else if uri.scheme() == Some(&Scheme::HTTP) {
                80
            } else {
                0
            }
        });
        let host = format!("{host}:{port}");

        let labels = &[&host];

        self.metrics
            .as_ref()
            .inspect(|x| x.requests.with_label_values(labels).inc());

        // Select the client with least outstanding requests for the given host
        let (cli, counter) = self
            .inner
            .iter()
            .map(|x| {
                (
                    &x.cli,
                    // Get an atomic counter for the given host or create a new one
                    x.outstanding
                        .get_with_by_ref(&host, || Arc::new(AtomicUsize::new(0))),
                )
            })
            .min_by_key(|x| x.1.load(Ordering::SeqCst))
            .unwrap();

        // The future can be cancelled so we have to use defer to make sure the counter is decreased
        defer! {
            counter.fetch_sub(1, Ordering::SeqCst);
            self.metrics
                .as_ref()
                .inspect(|x| x.requests_inflight.with_label_values(labels).dec());
        }

        counter.fetch_add(1, Ordering::SeqCst);
        self.metrics
            .as_ref()
            .inspect(|x| x.requests_inflight.with_label_values(labels).inc());

        // Execute the request & observe duration
        let start = Instant::now();
        let result = cli.execute(req).await;
        self.metrics.as_ref().inspect(|x| {
            x.request_duration
                .with_label_values(labels)
                .observe(start.elapsed().as_secs_f64())
        });

        result
    }
}
