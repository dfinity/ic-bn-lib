pub mod cli;
#[cfg(feature = "clients-hyper")]
pub mod clients_hyper;
pub mod clients_reqwest;

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::dns::Name as HyperName;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use reqwest::{Request, Response, dns::Resolve};
use tower::Service;

use super::Error;

/// Generic HTTP client trait that is using Reqwest types
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Client: Send + Sync + fmt::Debug {
    async fn execute(&self, req: Request) -> Result<Response, reqwest::Error>;
}

/// Generic HTTP client trait that is using HTTP types
#[async_trait]
pub trait ClientHttp: Send + Sync + fmt::Debug {
    async fn execute(
        &self,
        req: http::Request<Full<Bytes>>,
    ) -> Result<http::Response<Incoming>, Error>;
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

pub trait CloneableHyperDnsResolver: Service<HyperName> + Clone + fmt::Debug + 'static {}

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

impl<R: CloneableDnsResolver> Default for Options<R> {
    fn default() -> Self {
        Self {
            timeout_connect: Duration::from_secs(10),
            timeout_read: Duration::from_secs(60),
            timeout: Duration::from_secs(120),
            pool_idle_timeout: None,
            pool_idle_max: None,
            tcp_keepalive: None,
            http2_keepalive: None,
            http2_keepalive_timeout: Duration::from_secs(30),
            http2_keepalive_idle: false,
            user_agent: "Crab".into(),
            tls_config: None,
            dns_resolver: None,
        }
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
