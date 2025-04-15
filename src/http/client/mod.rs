pub mod cli;

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::RandomState;
use anyhow::Context;
use async_trait::async_trait;
use http::header::HeaderValue;
use moka::sync::{Cache, CacheBuilder};
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use reqwest::{Request, Response, dns::Resolve};
use scopeguard::defer;
use url::Url;

use super::Error;

fn extract_host(url: &Url) -> String {
    format!(
        "{}:{}",
        url.host_str()
            .unwrap_or_default()
            .split('@')
            .last()
            .unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default()
    )
}

/// Generic HTTP client trait
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Client: Send + Sync + fmt::Debug {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error>;
}

#[derive(Debug, Clone)]
pub struct ClientStats {
    pub pool_size: usize,
    pub outstanding: usize,
}

pub trait Stats {
    fn stats(&self) -> ClientStats;
}

pub trait ClientWithStats: Client + Stats {
    fn to_client(self: Arc<Self>) -> Arc<dyn Client>;
}

pub trait CloneableDnsResolver: Resolve + Clone + fmt::Debug + 'static {}

#[derive(Clone, Debug)]
struct Metrics {
    requests: IntCounterVec,
    requests_inflight: IntGaugeVec,
    request_duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const LABELS: &[&str] = &["host"];

        Self {
            requests: register_int_counter_vec_with_registry!(
                format!("http_client_requests_total"),
                format!("Counts the number of requests"),
                LABELS,
                registry
            )
            .unwrap(),

            requests_inflight: register_int_gauge_vec_with_registry!(
                format!("http_client_requests_inflight"),
                format!("Counts the number of requests that are currently executed"),
                LABELS,
                registry
            )
            .unwrap(),

            request_duration: register_histogram_vec_with_registry!(
                format!("http_client_request_duration_sec"),
                format!("Records the duration of requests in seconds"),
                LABELS,
                [0.01, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2].to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

/// HTTP client options
#[derive(Debug, Clone)]
pub struct Options<R: CloneableDnsResolver> {
    pub timeout_connect: Duration,
    pub timeout_read: Duration,
    pub timeout: Duration,
    pub pool_idle_timeout: Option<Duration>,
    pub pool_idle_max: Option<usize>,
    pub tcp_keepalive: Option<Duration>,
    pub http2_keepalive: Option<Duration>,
    pub http2_keepalive_timeout: Duration,
    pub http2_keepalive_idle: bool,
    pub user_agent: String,
    pub tls_config: Option<rustls::ClientConfig>,
    pub dns_resolver: Option<R>,
}

pub fn new<R: CloneableDnsResolver>(opts: Options<R>) -> Result<reqwest::Client, Error> {
    let mut client = reqwest::Client::builder()
        .connect_timeout(opts.timeout_connect)
        .read_timeout(opts.timeout_read)
        .timeout(opts.timeout)
        .pool_idle_timeout(opts.pool_idle_timeout)
        .tcp_nodelay(true)
        .tcp_keepalive(opts.tcp_keepalive)
        .http2_keep_alive_interval(opts.http2_keepalive)
        .http2_keep_alive_timeout(opts.http2_keepalive_timeout)
        .http2_keep_alive_while_idle(opts.http2_keepalive_idle)
        .http2_adaptive_window(true)
        .user_agent(opts.user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();

    if let Some(v) = opts.pool_idle_max {
        client = client.pool_max_idle_per_host(v);
    }

    if let Some(v) = opts.tls_config {
        client = client.use_preconfigured_tls(v);
    }

    if let Some(v) = opts.dns_resolver {
        client = client.dns_resolver(Arc::new(v));
    }

    Ok(client.build().context("unable to create reqwest client")?)
}

#[derive(Clone, Debug)]
pub struct ReqwestClient(reqwest::Client);

impl ReqwestClient {
    pub fn new<R: CloneableDnsResolver>(opts: Options<R>) -> Result<Self, Error> {
        Ok(Self(new(opts)?))
    }
}

#[async_trait]
impl Client for ReqwestClient {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error> {
        self.0.execute(req).await
    }
}

#[derive(Clone, Debug)]
pub struct ReqwestClientRoundRobin {
    inner: Arc<ReqwestClientRoundRobinInner>,
}

#[derive(Debug)]
struct ReqwestClientRoundRobinInner {
    cli: Vec<reqwest::Client>,
    next: AtomicUsize,
}

impl ReqwestClientRoundRobin {
    pub fn new<R: CloneableDnsResolver>(opts: Options<R>, count: usize) -> Result<Self, Error> {
        let inner = ReqwestClientRoundRobinInner {
            cli: (0..count)
                .map(|_| new(opts.clone()))
                .collect::<Result<Vec<_>, _>>()?,
            next: AtomicUsize::new(0),
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

#[async_trait]
impl Client for ReqwestClientRoundRobin {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error> {
        let next = self.inner.next.fetch_add(1, Ordering::SeqCst) % self.inner.cli.len();
        self.inner.cli[next].execute(req).await
    }
}

#[derive(Clone, Debug)]
pub struct ReqwestClientLeastLoaded {
    inner: Arc<Vec<ReqwestClientLeastLoadedInner>>,
    metrics: Option<Metrics>,
}

#[derive(Debug)]
struct ReqwestClientLeastLoadedInner {
    cli: reqwest::Client,
    outstanding: Cache<String, Arc<AtomicUsize>, RandomState>,
}

impl ReqwestClientLeastLoaded {
    pub fn new<R: CloneableDnsResolver>(
        opts: Options<R>,
        count: usize,
        registry: Option<&Registry>,
    ) -> Result<Self, Error> {
        let inner = (0..count)
            .map(|_| -> Result<_, _> {
                Ok::<_, Error>(ReqwestClientLeastLoadedInner {
                    cli: new(opts.clone())?,
                    // Creates a cache with some sensible max capacity to hold target hosts.
                    // If the host isn't contacted in 10min then we remove it.
                    // TODO should we make this configurable? Probably ok like this
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
impl Client for ReqwestClientLeastLoaded {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error> {
        // Extract host:port from the request URL
        let host = extract_host(req.url());
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

impl Stats for ReqwestClientLeastLoaded {
    fn stats(&self) -> ClientStats {
        ClientStats {
            pool_size: self.inner.len(),
            outstanding: self
                .inner
                .iter()
                .flat_map(|x| x.outstanding.iter().map(|x| x.1.load(Ordering::SeqCst)))
                .sum(),
        }
    }
}

impl ClientWithStats for ReqwestClientLeastLoaded {
    fn to_client(self: Arc<Self>) -> Arc<dyn Client> {
        self
    }
}

pub fn basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
    U: fmt::Display,
    P: fmt::Display,
{
    use base64::prelude::BASE64_STANDARD;
    use base64::write::EncoderWriter;
    use std::io::Write;

    let mut buf = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
        let _ = write!(encoder, "{username}:");
        if let Some(password) = password {
            let _ = write!(encoder, "{password}");
        }
    }

    let mut header = HeaderValue::from_bytes(&buf).expect("base64 is always valid HeaderValue");
    header.set_sensitive(true);
    header
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host(&Url::parse("https://foo:123/bar/beef").unwrap()),
            "foo:123"
        );

        assert_eq!(
            extract_host(&Url::parse("https://foo:443/bar/beef").unwrap()),
            "foo:443"
        );

        assert_eq!(
            extract_host(&Url::parse("http://foo:80/bar/beef").unwrap()),
            "foo:80"
        );

        assert_eq!(
            extract_host(&Url::parse("https://top:secret@foo:123/bar/beef").unwrap()),
            "foo:123"
        );
    }
}
