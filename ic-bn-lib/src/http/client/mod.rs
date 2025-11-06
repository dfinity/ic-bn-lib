#[cfg(feature = "clients-hyper")]
pub mod clients_hyper;
pub mod clients_reqwest;

use std::{fmt, sync::Arc};

use http::HeaderValue;
use ic_bn_lib_common::traits::http::Client;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};

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
