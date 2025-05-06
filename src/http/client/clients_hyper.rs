use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::RandomState;
use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use http::uri::Scheme;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client as ClientHyper, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use moka::sync::{Cache, CacheBuilder};
use prometheus::Registry;
use scopeguard::defer;

use crate::http::dns::Resolver;

use super::{ClientHttp, Error, Metrics, Options};

#[derive(Debug)]
pub struct HyperClient {
    cli: ClientHyper<HttpsConnector<HttpConnector<Resolver>>, Full<Bytes>>,
}

impl HyperClient {
    pub fn new(opts: Options<Resolver>) -> Self {
        let mut http_conn = HttpConnector::new_with_resolver(opts.dns_resolver.unwrap());
        http_conn.set_connect_timeout(Some(opts.timeout_connect));
        http_conn.set_keepalive(opts.tcp_keepalive);
        http_conn.enforce_http(false);
        http_conn.set_nodelay(true);

        let builder = HttpsConnector::<HttpConnector>::builder();
        let builder = if let Some(mut v) = opts.tls_config {
            v.alpn_protocols = vec![];
            builder.with_tls_config(v)
        } else {
            builder.with_webpki_roots()
        };

        let https_conn = builder
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http_conn);

        let mut builder = ClientHyper::builder(TokioExecutor::new());
        builder.http2_adaptive_window(true);
        builder.pool_idle_timeout(opts.pool_idle_timeout);

        if let Some(v) = opts.pool_idle_max {
            builder.pool_max_idle_per_host(v);
        }

        let cli = builder
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new())
            .build(https_conn);

        Self { cli }
    }
}

#[async_trait]
impl ClientHttp for HyperClient {
    async fn execute(
        &self,
        req: http::Request<Full<Bytes>>,
    ) -> Result<http::Response<Incoming>, Error> {
        self.cli
            .request(req)
            .await
            .map_err(|e| Error::Generic(anyhow!("Error executing HTTP request: {e:#}")))
    }
}

#[derive(Clone, Debug)]
pub struct HyperClientLeastLoaded {
    inner: Arc<Vec<HyperClientLeastLoadedInner>>,
    metrics: Option<Metrics>,
}

#[derive(Debug)]
struct HyperClientLeastLoadedInner {
    cli: HyperClient,
    outstanding: Cache<String, Arc<AtomicUsize>, RandomState>,
}

impl HyperClientLeastLoaded {
    pub fn new(
        opts: Options<Resolver>,
        count: usize,
        registry: Option<&Registry>,
    ) -> Result<Self, Error> {
        let inner = (0..count)
            .map(|_| -> Result<_, _> {
                Ok::<_, Error>(HyperClientLeastLoadedInner {
                    cli: HyperClient::new(opts.clone()),
                    // Creates a cache with some sensible max capacity to hold target hosts.
                    // If the host isn't contacted in 10min then we remove it.
                    outstanding: CacheBuilder::new(16384)
                        .time_to_idle(Duration::from_secs(600))
                        .build_with_hasher(RandomState::default()),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            inner: Arc::new(inner),
            metrics: registry.map(Metrics::new),
        })
    }
}

#[async_trait]
impl ClientHttp for HyperClientLeastLoaded {
    async fn execute(
        &self,
        req: http::Request<Full<Bytes>>,
    ) -> Result<http::Response<Incoming>, Error> {
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
