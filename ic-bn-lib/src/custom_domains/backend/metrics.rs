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

use crate::reqwest::StatusCode;

pub const HTTP_DURATION_BUCKETS: &[f64] = &[0.05, 0.2, 1.0, 2.0];

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

#[cfg(test)]
mod test {
    use axum::{
        Router,
        http::Request,
        middleware::from_fn_with_state,
        routing::{get, post},
    };
    use prometheus::proto::{Metric, MetricFamily};
    use tower::util::ServiceExt;

    use super::*;

    const REQUESTS: &str = "custom_domains_http_requests_total";
    const DURATION: &str = "custom_domains_http_request_duration_seconds";

    fn family<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|x| x.name() == name)
            .unwrap_or_else(|| {
                panic!(
                    "metric {name} not found, got: {:?}",
                    families.iter().map(MetricFamily::name).collect::<Vec<_>>()
                )
            })
    }

    fn labels(metric: &Metric) -> Vec<(String, String)> {
        metric
            .label
            .iter()
            .map(|x| (x.name().to_string(), x.value().to_string()))
            .collect()
    }

    /// Label name/value pairs of the single series in the given family.
    fn only_labels(families: &[MetricFamily], name: &str) -> Vec<(String, String)> {
        let metrics = &family(families, name).metric;
        assert_eq!(metrics.len(), 1, "expected exactly one {name} series");
        labels(&metrics[0])
    }

    fn app(registry: &Registry) -> Router {
        Router::new()
            .route("/v1/{id}", post(|| async { StatusCode::ACCEPTED }))
            .route("/v1/{id}/validate", get(|| async { StatusCode::OK }))
            .layer(from_fn_with_state(
                Arc::new(HttpMetrics::new(registry.clone())),
                metrics_middleware,
            ))
    }

    async fn call(router: &Router, method: &str, uri: &str) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        router.clone().oneshot(req).await.unwrap().status()
    }

    #[test]
    fn new_registers_both_metrics_with_expected_names_help_and_labels() {
        let registry = Registry::new();
        let metrics = HttpMetrics::new(registry.clone());

        metrics
            .requests
            .with_label_values(&["GET", "/v1/{id}", "200"])
            .inc();
        metrics
            .duration
            .with_label_values(&["GET", "/v1/{id}"])
            .observe(0.5);

        let families = registry.gather();

        let requests = family(&families, REQUESTS);
        assert_eq!(
            requests.help(),
            "Custom Domains: Total number of HTTP requests"
        );
        assert_eq!(
            only_labels(&families, REQUESTS),
            vec![
                ("endpoint".to_string(), "/v1/{id}".to_string()),
                ("method".to_string(), "GET".to_string()),
                ("status".to_string(), "200".to_string()),
            ]
        );
        assert!((requests.metric[0].counter.value() - 1.0).abs() < f64::EPSILON);

        let duration = family(&families, DURATION);
        assert_eq!(
            duration.help(),
            "Custom Domains: HTTP request latency in seconds"
        );
        // The latency histogram is intentionally not labelled by status.
        assert_eq!(
            only_labels(&families, DURATION),
            vec![
                ("endpoint".to_string(), "/v1/{id}".to_string()),
                ("method".to_string(), "GET".to_string()),
            ]
        );

        let histogram = &duration.metric[0].histogram;
        assert_eq!(histogram.sample_count(), 1);
        assert!((histogram.sample_sum() - 0.5).abs() < 1e-9);
        assert_eq!(
            histogram
                .bucket
                .iter()
                .map(|x| x.upper_bound())
                .collect::<Vec<_>>(),
            HTTP_DURATION_BUCKETS.to_vec()
        );
        // 0.5 is only counted by the cumulative buckets from 1.0 upwards.
        assert_eq!(
            histogram
                .bucket
                .iter()
                .map(|x| x.cumulative_count())
                .collect::<Vec<_>>(),
            vec![0, 0, 1, 1]
        );
    }

    #[tokio::test]
    async fn middleware_labels_series_with_matched_path_method_and_status() {
        let registry = Registry::new();
        let router = app(&registry);

        assert_eq!(
            call(&router, "POST", "/v1/example.org").await,
            StatusCode::ACCEPTED
        );

        let families = registry.gather();
        // The endpoint label must be the route template, not the concrete path,
        // otherwise this would be a high-cardinality label.
        assert_eq!(
            only_labels(&families, REQUESTS),
            vec![
                ("endpoint".to_string(), "/v1/{id}".to_string()),
                ("method".to_string(), "POST".to_string()),
                ("status".to_string(), "202".to_string()),
            ]
        );
        assert_eq!(
            only_labels(&families, DURATION),
            vec![
                ("endpoint".to_string(), "/v1/{id}".to_string()),
                ("method".to_string(), "POST".to_string()),
            ]
        );
        assert_eq!(
            family(&families, DURATION).metric[0]
                .histogram
                .sample_count(),
            1
        );
    }

    #[tokio::test]
    async fn middleware_counts_repeated_requests_in_the_same_series() {
        let registry = Registry::new();
        let router = app(&registry);

        for _ in 0..3 {
            call(&router, "POST", "/v1/example.org").await;
        }

        let families = registry.gather();
        let requests = family(&families, REQUESTS);
        assert_eq!(requests.metric.len(), 1);
        assert!(
            (requests.metric[0].counter.value() - 3.0).abs() < f64::EPSILON,
            "got {}",
            requests.metric[0].counter.value()
        );
        assert_eq!(
            family(&families, DURATION).metric[0]
                .histogram
                .sample_count(),
            3
        );
    }

    #[tokio::test]
    async fn middleware_keeps_distinct_endpoints_in_distinct_series() {
        let registry = Registry::new();
        let router = app(&registry);

        call(&router, "POST", "/v1/example.org").await;
        call(&router, "GET", "/v1/example.org/validate").await;

        let families = registry.gather();
        let mut series = family(&families, REQUESTS)
            .metric
            .iter()
            .map(|m| {
                let rendered = labels(m)
                    .into_iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(",");
                (rendered, m.counter.value())
            })
            .collect::<Vec<_>>();
        series.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(
            series,
            vec![
                ("endpoint=/v1/{id},method=POST,status=202".to_string(), 1.0),
                (
                    "endpoint=/v1/{id}/validate,method=GET,status=200".to_string(),
                    1.0
                ),
            ]
        );
    }

    #[tokio::test]
    async fn middleware_labels_unmatched_paths_as_unknown() {
        let registry = Registry::new();
        let router = app(&registry);

        assert_eq!(
            call(&router, "GET", "/does/not/exist").await,
            StatusCode::NOT_FOUND
        );

        let families = registry.gather();
        assert_eq!(
            only_labels(&families, REQUESTS),
            vec![
                ("endpoint".to_string(), "unknown".to_string()),
                ("method".to_string(), "GET".to_string()),
                ("status".to_string(), "404".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn metrics_handler_encodes_the_registry_in_text_format() {
        let registry = Registry::new();
        let metrics = HttpMetrics::new(registry.clone());
        metrics
            .requests
            .with_label_values(&["GET", "/v1/{id}", "200"])
            .inc_by(7);
        metrics
            .duration
            .with_label_values(&["GET", "/v1/{id}"])
            .observe(0.1);

        let resp = metrics_handler(State(registry)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            body.contains(&format!("# TYPE {REQUESTS} counter")),
            "got: {body}"
        );
        assert!(
            body.contains(&format!(
                "{REQUESTS}{{endpoint=\"/v1/{{id}}\",method=\"GET\",status=\"200\"}} 7"
            )),
            "got: {body}"
        );
        assert!(
            body.contains(&format!("# TYPE {DURATION} histogram")),
            "got: {body}"
        );
        // 0.1 lands in the 0.2 bucket, so the 0.05 one stays empty.
        assert!(
            body.contains(&format!(
                "{DURATION}_bucket{{endpoint=\"/v1/{{id}}\",method=\"GET\",le=\"0.05\"}} 0"
            )),
            "got: {body}"
        );
        assert!(
            body.contains(&format!(
                "{DURATION}_count{{endpoint=\"/v1/{{id}}\",method=\"GET\"}} 1"
            )),
            "got: {body}"
        );
    }

    #[tokio::test]
    async fn metrics_handler_on_an_empty_registry_returns_an_empty_body() {
        let resp = metrics_handler(State(Registry::new()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn clones_share_the_same_underlying_collectors() {
        // `HttpMetrics` is cloned into the middleware state, so a clone must feed the
        // already-registered series rather than a private copy.
        let registry = Registry::new();
        let metrics = HttpMetrics::new(registry.clone());
        let clone = metrics.clone();

        metrics
            .requests
            .with_label_values(&["GET", "/v1/{id}", "200"])
            .inc();
        clone
            .requests
            .with_label_values(&["GET", "/v1/{id}", "200"])
            .inc_by(4);
        clone
            .duration
            .with_label_values(&["GET", "/v1/{id}"])
            .observe(0.01);
        metrics
            .duration
            .with_label_values(&["GET", "/v1/{id}"])
            .observe(0.02);

        let families = registry.gather();
        let requests = family(&families, REQUESTS);
        assert_eq!(requests.metric.len(), 1, "clone created a second series");
        assert!(
            (requests.metric[0].counter.value() - 5.0).abs() < f64::EPSILON,
            "got {}",
            requests.metric[0].counter.value()
        );

        let histogram = &family(&families, DURATION).metric[0].histogram;
        assert_eq!(histogram.sample_count(), 2);
        assert!((histogram.sample_sum() - 0.03).abs() < 1e-9);
    }

    #[test]
    #[should_panic(expected = "AlreadyReg")]
    fn new_panics_if_the_same_registry_is_used_twice() {
        // Registration `unwrap()`s, so a duplicate `HttpMetrics` for one registry is a
        // hard failure rather than a silently shadowed metric.
        let registry = Registry::new();
        let _first = HttpMetrics::new(registry.clone());
        let _second = HttpMetrics::new(registry);
    }
}
