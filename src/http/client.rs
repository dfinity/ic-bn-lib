use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use async_trait::async_trait;
use http::header::HeaderValue;
use mockall::automock;
use rand::{rngs::OsRng, seq::IteratorRandom};
use reqwest::{dns::Resolve, Request, Response};

use super::Error;

/// Generic HTTP client trait
#[automock]
#[async_trait]
pub trait Client: Send + Sync + fmt::Debug {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error>;
}

pub trait CloneableDnsResolver: Resolve + Clone {}

/// HTTP client options
#[derive(Debug, Clone)]
pub struct Options<R: Resolve + fmt::Debug + Clone + 'static> {
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

pub fn new<R: Resolve + fmt::Debug + Clone + 'static>(
    opts: Options<R>,
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
    pub fn new<R: Resolve + fmt::Debug + Clone + 'static>(opts: Options<R>) -> Result<Self, Error> {
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
    pub fn new<R: Resolve + fmt::Debug + Clone + 'static>(
        opts: Options<R>,
        count: usize,
    ) -> Result<Self, Error> {
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
}

#[derive(Debug)]
struct ReqwestClientLeastLoadedInner {
    cli: reqwest::Client,
    outstanding: AtomicUsize,
}

impl ReqwestClientLeastLoaded {
    pub fn new<R: Resolve + fmt::Debug + Clone + 'static>(
        opts: Options<R>,
        count: usize,
    ) -> Result<Self, Error> {
        let inner = (0..count)
            .map(|_| -> Result<_, _> {
                Ok::<_, Error>(ReqwestClientLeastLoadedInner {
                    cli: new(opts.clone())?,
                    outstanding: AtomicUsize::new(0),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

#[async_trait]
impl Client for ReqwestClientLeastLoaded {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error> {
        let cli = self
            .inner
            .iter()
            .min_by_key(|x| x.outstanding.load(Ordering::SeqCst))
            .unwrap();

        cli.outstanding.fetch_add(1, Ordering::SeqCst);
        let res = cli.cli.execute(req).await;
        cli.outstanding.fetch_sub(1, Ordering::SeqCst);

        res
    }
}

#[derive(Debug)]
pub struct ReqwestClientDynamic {
    generator: fn() -> Result<Arc<dyn Client>, Error>,
    max_clients: usize,
    max_outstanding: usize,
    idle_timeout: Duration,
    pool: Mutex<Vec<Arc<ReqwestClientDynamicInner>>>,
}

#[derive(Debug)]
struct ReqwestClientDynamicInner {
    cli: Arc<dyn Client>,
    outstanding: AtomicUsize,
    last_request: RwLock<Instant>,
}

impl ReqwestClientDynamicInner {
    fn new(cli: Arc<dyn Client>) -> Self {
        Self {
            cli,
            outstanding: AtomicUsize::new(0),
            last_request: RwLock::new(Instant::now()),
        }
    }
}

impl ReqwestClientDynamic {
    pub fn new(
        generator: fn() -> Result<Arc<dyn Client>, Error>,
        max_clients: usize,
        max_outstanding: usize,
        idle_timeout: Duration,
    ) -> Result<Self, Error> {
        let inner = Arc::new(ReqwestClientDynamicInner::new(generator()?));
        let mut pool = Vec::with_capacity(max_clients);
        pool.push(inner);

        Ok(Self {
            generator,
            max_clients,
            max_outstanding,
            idle_timeout,
            pool: Mutex::new(pool),
        })
    }

    fn get_client(&self) -> Arc<ReqwestClientDynamicInner> {
        let mut pool = self.pool.lock().unwrap();

        // Drop unused clients while leaving one always available
        // TODO find a better way?
        let mut to_drop = Vec::with_capacity(self.max_clients - 1);
        for (i, v) in pool.iter().enumerate() {
            if i > 0
                && v.outstanding.load(Ordering::SeqCst) == 0
                && v.last_request.read().unwrap().elapsed() < self.idle_timeout
            {
                to_drop.push(i);
            }
        }
        for i in to_drop.into_iter().rev() {
            pool.remove(i);
        }

        pool.iter()
            // First try to find an existing client with spare capacity
            .find_map(|x| {
                (x.outstanding.load(Ordering::SeqCst) < self.max_outstanding).then(|| x.clone())
            })
            // Otherwise see if we have spare space in the pool
            .unwrap_or_else(|| {
                // If not - just pick a random client
                if pool.len() >= self.max_clients {
                    pool.iter().choose(&mut OsRng).unwrap().clone()
                } else {
                    // Otherwise generate a new client and use it
                    // The error is checked only in new() for now.
                    let cli = (self.generator)().unwrap();
                    let inner = Arc::new(ReqwestClientDynamicInner::new(cli));
                    pool.push(inner.clone());
                    inner
                }
            })
    }
}

#[async_trait]
impl Client for ReqwestClientDynamic {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error> {
        let inner = self.get_client();

        *inner.last_request.write().unwrap() = Instant::now();
        inner.outstanding.fetch_add(1, Ordering::SeqCst);
        let res = inner.cli.execute(req).await;
        inner.outstanding.fetch_sub(1, Ordering::SeqCst);

        res
    }
}

pub fn basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
    U: std::fmt::Display,
    P: std::fmt::Display,
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
    use futures::future::join_all;

    use super::*;

    #[derive(Debug)]
    struct TestClient;

    #[async_trait]
    impl Client for TestClient {
        async fn execute(
            &self,
            _req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            let resp = ::http::Response::new(vec![]);
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(resp.into())
        }
    }

    #[tokio::test]
    async fn test_dynamic_client() {
        let cli = Arc::new(
            ReqwestClientDynamic::new(|| Ok(Arc::new(TestClient)), 10, 10, Duration::from_secs(90))
                .unwrap(),
        );

        let mut futs = vec![];
        for _ in 0..200 {
            let req =
                reqwest::Request::new(reqwest::Method::GET, url::Url::parse("http://foo").unwrap());

            let cli = cli.clone();
            futs.push(async move { cli.execute(req).await });
        }

        join_all(futs).await;
        let pool = cli.pool.lock().unwrap();

        assert_eq!(pool.len(), 10);

        for x in pool.iter() {
            assert_eq!(x.outstanding.load(Ordering::SeqCst), 0);
        }
    }
}
