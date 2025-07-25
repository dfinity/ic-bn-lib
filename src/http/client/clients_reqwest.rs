use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::RandomState;
use anyhow::Context;
use async_trait::async_trait;
use moka::sync::{Cache, CacheBuilder};
use prometheus::Registry;
use reqwest::{Request, Response};
use scopeguard::defer;
use url::Url;

use crate::http::dns::CloneableDnsResolver;

use super::{Client, ClientStats, ClientWithStats, Error, Metrics, Options, Stats};

// Extracts host:port from the URL
fn extract_host(url: &Url) -> String {
    format!(
        "{}:{}",
        url.host_str()
            .and_then(|x| x.split('@').next_back())
            .unwrap_or_default(),
        url.port_or_known_default().unwrap_or_default()
    )
}

pub fn new<R: CloneableDnsResolver>(
    opts: Options,
    resolver: Option<R>,
) -> Result<reqwest::Client, Error> {
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

    if opts.http2_only {
        client = client.http2_prior_knowledge();
    }

    if let Some(v) = opts.pool_idle_max {
        client = client.pool_max_idle_per_host(v);
    }

    if let Some(v) = opts.tls_config {
        client = client.use_preconfigured_tls(v);
    }

    if let Some(v) = resolver {
        client = client.dns_resolver(Arc::new(v));
    }

    Ok(client.build().context("unable to create reqwest client")?)
}

#[derive(Clone, Debug)]
pub struct ReqwestClient(reqwest::Client);

impl ReqwestClient {
    pub fn new<R: CloneableDnsResolver>(opts: Options, resolver: Option<R>) -> Result<Self, Error> {
        Ok(Self(new(opts, resolver)?))
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
    pub fn new<R: CloneableDnsResolver>(
        opts: Options,
        resolver: Option<R>,
        count: usize,
    ) -> Result<Self, Error> {
        let inner = ReqwestClientRoundRobinInner {
            cli: (0..count)
                .map(|_| new(opts.clone(), resolver.clone()))
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
        opts: Options,
        resolver: Option<R>,
        count: usize,
        registry: Option<&Registry>,
    ) -> Result<Self, Error> {
        let inner = (0..count)
            .map(|_| -> Result<_, _> {
                Ok::<_, Error>(ReqwestClientLeastLoadedInner {
                    cli: new(opts.clone(), resolver.clone())?,
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
            extract_host(&Url::parse("https://foo/bar/beef").unwrap()),
            "foo:443"
        );

        assert_eq!(
            extract_host(&Url::parse("http://foo:80/bar/beef").unwrap()),
            "foo:80"
        );

        assert_eq!(
            extract_host(&Url::parse("http://foo/bar/beef").unwrap()),
            "foo:80"
        );

        assert_eq!(
            extract_host(&Url::parse("https://top:secret@foo:123/bar/beef").unwrap()),
            "foo:123"
        );
    }
}
