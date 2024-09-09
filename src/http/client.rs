use std::{
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use http::header::HeaderValue;
use mockall::automock;
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
#[derive(Clone)]
pub struct Options<R: Resolve + Clone + 'static> {
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

pub fn new<R: Resolve + Clone + 'static>(opts: Options<R>) -> Result<reqwest::Client, Error> {
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
    pub fn new<R: Resolve + Clone + 'static>(opts: Options<R>) -> Result<Self, Error> {
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
    pub fn new<R: Resolve + Clone + 'static>(
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
    pub fn new<R: Resolve + Clone + 'static>(
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
