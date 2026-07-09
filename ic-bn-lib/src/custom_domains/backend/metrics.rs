use std::{sync::Arc, time::Instant};

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, Registry, TextEncoder,
    register_histogram_vec_with_registry, register_int_counter_vec_with_registry,
};
pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 1.0, 2.0];

use crate::reqwest::StatusCode;

#[derive(Clone)]
pub struct HttpMetrics {
    pub requests: IntCounterVec,
    pub duration: HistogramVec,
}

impl HttpMetrics {
    pub fn new(registry: Registry) -> Self {
        Self {
            requests: register_int_counter_vec_with_registry!(
                format!("custom_domains_http_requests_total"),
                format!("Custom Domains: Total number of HTTP requests"),
                &["method", "endpoint", "status"],
                registry
            )
            .unwrap(),
            duration: register_histogram_vec_with_registry!(
                format!("custom_domains_http_request_duration_seconds"),
                format!("Custom Domains: HTTP request latency in seconds"),
                &["method", "endpoint"],
                HTTP_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

pub async fn metrics_middleware(
    State(state): State<Arc<HttpMetrics>>,
    matched_path: Option<MatchedPath>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = matched_path
        .as_ref()
        .map(|mp| mp.as_str())
        .unwrap_or("unknown");
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();

    state
        .requests
        .with_label_values(&[method.as_str(), path, status.as_str()])
        .inc();

    state
        .duration
        .with_label_values(&[method.as_str(), path])
        .observe(start.elapsed().as_secs_f64());

    response
}

pub async fn metrics_handler(State(registry): State<Registry>) -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    (StatusCode::OK, buffer)
}
