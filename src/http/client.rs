use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, RwLock,
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

pub trait ClientWithStats: Client + Stats {
    fn to_client(self: Arc<Self>) -> Arc<dyn Client>;
}

pub trait CloneableDnsResolver: Resolve + Clone + fmt::Debug + 'static {}

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
}

#[derive(Debug)]
struct ReqwestClientLeastLoadedInner {
    cli: reqwest::Client,
    outstanding: AtomicUsize,
}

impl ReqwestClientLeastLoaded {
    pub fn new<R: CloneableDnsResolver>(opts: Options<R>, count: usize) -> Result<Self, Error> {
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

pub trait GeneratesClients: Send + Sync + fmt::Debug + 'static {
    fn generate(&self) -> Result<Arc<dyn Client>, Error>;
}

pub trait GeneratesClientsWithStats: Send + Sync + fmt::Debug + 'static {
    fn generate(&self) -> Result<Arc<dyn ClientWithStats>, Error>;
}

#[derive(Debug, Clone)]
pub struct ClientStats {
    pub pool_size: usize,
    pub outstanding: usize,
}

pub trait Stats {
    fn stats(&self) -> ClientStats;
}

#[derive(Debug)]
pub struct ReqwestClientDynamic<G: GeneratesClients> {
    generator: G,
    min_clients: usize,
    max_clients: usize,
    max_outstanding: usize,
    idle_timeout: Duration,
    pool: Mutex<Vec<Arc<ReqwestClientDynamicInner>>>,
}

impl<G: GeneratesClients> ClientWithStats for ReqwestClientDynamic<G> {
    fn to_client(self: Arc<Self>) -> Arc<dyn Client> {
        self
    }
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

impl<G: GeneratesClients> ReqwestClientDynamic<G> {
    pub fn new(
        generator: G,
        min_clients: usize,
        max_clients: usize,
        max_outstanding: usize,
        idle_timeout: Duration,
    ) -> Result<Self, Error> {
        let mut pool = Vec::with_capacity(max_clients);

        for _ in 0..min_clients {
            let inner = Arc::new(ReqwestClientDynamicInner::new(generator.generate()?));
            pool.push(inner);
        }

        Ok(Self {
            generator,
            min_clients,
            max_clients,
            max_outstanding,
            idle_timeout,
            pool: Mutex::new(pool),
        })
    }

    /// Drop unused clients while leaving min_clients always available.
    /// Algo mimics Vec::retain().
    /// TODO find a better way?
    fn cleanup(&self, pool: &mut MutexGuard<'_, Vec<Arc<ReqwestClientDynamicInner>>>) {
        let mut j = self.min_clients;
        for i in self.min_clients..pool.len() {
            if !(pool[i].outstanding.load(Ordering::SeqCst) == 0
                && pool[i].last_request.read().unwrap().elapsed() > self.idle_timeout)
            {
                pool.swap(i, j);
                j += 1
            }
        }
        pool.truncate(j);
    }

    fn get_client(&self) -> Arc<ReqwestClientDynamicInner> {
        let mut pool = self.pool.lock().unwrap();
        self.cleanup(&mut pool);

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
                    let cli = self.generator.generate().unwrap();
                    let inner = Arc::new(ReqwestClientDynamicInner::new(cli));
                    pool.push(inner.clone());
                    inner
                }
            })
    }
}

impl<G: GeneratesClients> Stats for ReqwestClientDynamic<G> {
    fn stats(&self) -> ClientStats {
        let pool = self.pool.lock().unwrap();

        let outstanding: usize = pool
            .iter()
            .map(|x| x.outstanding.load(Ordering::SeqCst))
            .sum();

        ClientStats {
            pool_size: pool.len(),
            outstanding,
        }
    }
}

#[async_trait]
impl<G: GeneratesClients> Client for ReqwestClientDynamic<G> {
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

    #[derive(Debug)]
    struct TestClientGenerator;
    impl GeneratesClients for TestClientGenerator {
        fn generate(&self) -> Result<Arc<dyn Client>, Error> {
            Ok(Arc::new(TestClient))
        }
    }

    #[tokio::test]
    async fn test_dynamic_client() {
        let cli = Arc::new(
            ReqwestClientDynamic::new(TestClientGenerator, 1, 10, 10, Duration::ZERO).unwrap(),
        );

        let mut futs = vec![];
        for _ in 0..200 {
            let req =
                reqwest::Request::new(reqwest::Method::GET, url::Url::parse("http://foo").unwrap());

            let cli = cli.clone();
            futs.push(async move { cli.execute(req).await });
        }

        join_all(futs).await;
        let mut pool = cli.pool.lock().unwrap();
        assert_eq!(pool.len(), 10);

        for x in pool.iter() {
            assert_eq!(x.outstanding.load(Ordering::SeqCst), 0);
        }

        cli.cleanup(&mut pool);
        assert_eq!(pool.len(), 1);
    }
}
