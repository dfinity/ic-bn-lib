pub mod cli;
#[cfg(feature = "clients-hyper")]
pub mod clients_hyper;
pub mod clients_reqwest;

use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use http::HeaderValue;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use strum::{Display, EnumString};

use crate::http::Error;

/// Generic HTTP client trait that is using Reqwest types
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Client: Send + Sync + fmt::Debug {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error>;
}

/// Generic HTTP client trait that is using `http` crate types
#[async_trait]
pub trait ClientHttp<B1, B2 = axum::body::Body>: Send + Sync + fmt::Debug {
    async fn execute(&self, req: http::Request<B1>) -> Result<http::Response<B2>, Error>;
}

/// HTTP versions to use
#[derive(Debug, Clone, Copy, Eq, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum HttpVersion {
    Http1,
    Http2,
    All,
}

/// HTTP client options
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub timeout_connect: Duration,
    pub timeout_read: Duration,
    pub timeout: Duration,
    pub pool_idle_timeout: Option<Duration>,
    pub pool_idle_max: Option<usize>,
    pub tcp_keepalive_delay: Option<Duration>,
    pub tcp_keepalive_interval: Option<Duration>,
    pub tcp_keepalive_retries: Option<u32>,
    pub http2_keepalive: Option<Duration>,
    pub http2_keepalive_timeout: Option<Duration>,
    pub http2_keepalive_idle: bool,
    pub happy_eyeballs_timeout: Duration,
    pub http_version: HttpVersion,
    pub user_agent: String,
    pub tls_config: Option<rustls::ClientConfig>,
    pub tls_fixed_name: Option<String>,
    pub dns_overrides: Vec<(String, SocketAddr)>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            timeout_connect: Duration::from_secs(10),
            timeout_read: Duration::from_secs(60),
            timeout: Duration::from_secs(120),
            pool_idle_timeout: None,
            pool_idle_max: None,
            tcp_keepalive_delay: None,
            tcp_keepalive_interval: None,
            tcp_keepalive_retries: None,
            http2_keepalive: None,
            http2_keepalive_timeout: None,
            http2_keepalive_idle: false,
            happy_eyeballs_timeout: Duration::from_millis(500),
            http_version: HttpVersion::All,
            user_agent: "Crab".into(),
            tls_config: None,
            tls_fixed_name: None,
            dns_overrides: vec![],
        }
    }
}

/// HTTP Client stats
#[derive(Debug, Clone)]
pub struct ClientStats {
    pub pool_size: usize,
    pub outstanding: usize,
}

/// Trait to get `ClientStats`
pub trait Stats {
    fn stats(&self) -> ClientStats;
}

/// `Client` that also emits `Stats`
pub trait ClientWithStats: Client + Stats {
    fn to_client(self: Arc<Self>) -> Arc<dyn Client>;
}

/// HTTP Client metrics
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

/// Create an HTTP header for Basic auth
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
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_basic_auth() {
        // RFC 7617's own example vector
        assert_eq!(
            basic_auth("Aladdin", Some("open sesame")),
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );

        assert_eq!(basic_auth("user", Some("pass")), "Basic dXNlcjpwYXNz");

        // A missing password still has to emit the ":" separator...
        assert_eq!(basic_auth("user", None::<&str>), "Basic dXNlcjo=");
        // ...which makes it indistinguishable from an empty one
        assert_eq!(
            basic_auth("user", Some("")),
            basic_auth("user", None::<&str>)
        );

        // Empty username
        assert_eq!(basic_auth("", Some("pass")), "Basic OnBhc3M=");
        assert_eq!(basic_auth("", None::<&str>), "Basic Og==");

        // Any Display type is accepted, not just strings
        assert_eq!(basic_auth(42, Some(7)), "Basic NDI6Nw==");

        // Non-ASCII is passed through as UTF-8 bytes before base64
        assert_eq!(basic_auth("üser", Some("päss")), "Basic w7xzZXI6cMOkc3M=");
    }

    #[test]
    fn test_basic_auth_is_sensitive() {
        assert!(basic_auth("user", Some("pass")).is_sensitive());
        assert!(basic_auth("user", None::<&str>).is_sensitive());
    }

    #[test]
    fn test_http_version_display_from_str_roundtrip() {
        for (v, s) in [
            (HttpVersion::Http1, "http1"),
            (HttpVersion::Http2, "http2"),
            (HttpVersion::All, "all"),
        ] {
            assert_eq!(v.to_string(), s);
            assert_eq!(HttpVersion::from_str(s).unwrap(), v);
            assert_eq!(HttpVersion::from_str(&v.to_string()).unwrap(), v);
        }

        // Only the snake_case spellings are accepted
        assert!(HttpVersion::from_str("Http1").is_err());
        assert!(HttpVersion::from_str("http3").is_err());
        assert!(HttpVersion::from_str("").is_err());
        assert!(HttpVersion::from_str("ALL").is_err());
    }

    #[test]
    fn test_client_options_default() {
        let o = ClientOptions::default();

        assert_eq!(o.timeout_connect, Duration::from_secs(10));
        assert_eq!(o.timeout_read, Duration::from_secs(60));
        assert_eq!(o.timeout, Duration::from_secs(120));
        assert_eq!(o.happy_eyeballs_timeout, Duration::from_millis(500));
        assert_eq!(o.http_version, HttpVersion::All);
        assert_eq!(o.user_agent, "Crab");

        assert_eq!(o.pool_idle_timeout, None);
        assert_eq!(o.pool_idle_max, None);
        assert_eq!(o.tcp_keepalive_delay, None);
        assert_eq!(o.tcp_keepalive_interval, None);
        assert_eq!(o.tcp_keepalive_retries, None);
        assert_eq!(o.http2_keepalive, None);
        assert_eq!(o.http2_keepalive_timeout, None);
        assert!(!o.http2_keepalive_idle);
        assert!(o.tls_config.is_none());
        assert_eq!(o.tls_fixed_name, None);
        assert!(o.dns_overrides.is_empty());
    }

    #[test]
    fn test_metrics_registration() {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry);

        // Touch every metric so the families carry a child with our label
        metrics.requests.with_label_values(&["foo:443"]).inc_by(3);
        metrics
            .requests_inflight
            .with_label_values(&["foo:443"])
            .set(5);
        metrics
            .request_duration
            .with_label_values(&["foo:443"])
            .observe(0.5);

        let families = registry.gather();
        let mut names = families
            .iter()
            .map(|x| x.name().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![
                "http_client_request_duration_sec",
                "http_client_requests_inflight",
                "http_client_requests_total",
            ]
        );

        // Every metric is labelled by host and only by host
        for f in &families {
            assert_eq!(f.get_metric().len(), 1);
            let labels = f.get_metric()[0].get_label();
            assert_eq!(labels.len(), 1);
            assert_eq!(labels[0].name(), "host");
            assert_eq!(labels[0].value(), "foo:443");
        }

        let by_name = |name: &str| {
            families
                .iter()
                .find(|x| x.name() == name)
                .unwrap()
                .get_metric()[0]
                .clone()
        };

        assert_eq!(
            by_name("http_client_requests_total").get_counter().value(),
            3.0
        );
        assert_eq!(
            by_name("http_client_requests_inflight").get_gauge().value(),
            5.0
        );

        let hist = by_name("http_client_request_duration_sec");
        let hist = hist.get_histogram();
        assert_eq!(hist.get_sample_count(), 1);
        assert_eq!(
            hist.get_bucket()
                .iter()
                .map(|x| x.upper_bound())
                .collect::<Vec<_>>(),
            vec![0.01, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2]
        );
    }
}
