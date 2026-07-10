use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};

/// HTTP server metrics
#[derive(Clone)]
pub struct Metrics {
    pub conns: IntCounterVec,
    pub conns_open: IntGaugeVec,
    pub requests: IntCounterVec,
    pub requests_inflight: IntGaugeVec,
    pub bytes_sent: IntCounterVec,
    pub bytes_rcvd: IntCounterVec,
    pub conn_duration: HistogramVec,
    pub requests_per_conn: HistogramVec,
    pub conn_tls_handshake_duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const HANDSHAKE_DURATION_BUCKETS: &[f64] =
            &[0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6];
        const CONN_DURATION_BUCKETS: &[f64] = &[1.0, 8.0, 32.0, 64.0, 256.0, 512.0, 1024.0];
        const CONN_REQUESTS: &[f64] = &[1.0, 4.0, 8.0, 16.0, 32.0, 64.0, 256.0];

        const LABELS: &[&str] = &[
            "addr",
            "family",
            "tls_version",
            "tls_cipher",
            "forced_close",
            "recycled",
        ];

        Self {
            conns: register_int_counter_vec_with_registry!(
                format!("conn_total"),
                format!("Counts the number of connections"),
                LABELS,
                registry
            )
            .unwrap(),

            conns_open: register_int_gauge_vec_with_registry!(
                format!("conn_open"),
                format!("Number of currently open connections"),
                &LABELS[0..4],
                registry
            )
            .unwrap(),

            requests: register_int_counter_vec_with_registry!(
                format!("conn_requests_total"),
                format!("Counts the number of requests"),
                LABELS,
                registry
            )
            .unwrap(),

            requests_inflight: register_int_gauge_vec_with_registry!(
                format!("conn_requests_inflight"),
                format!("Counts the number of requests that are currently executed"),
                &LABELS[0..4],
                registry
            )
            .unwrap(),

            bytes_sent: register_int_counter_vec_with_registry!(
                format!("conn_bytes_sent_total"),
                format!("Counts number of bytes sent"),
                LABELS,
                registry
            )
            .unwrap(),

            bytes_rcvd: register_int_counter_vec_with_registry!(
                format!("conn_bytes_rcvd_total"),
                format!("Counts number of bytes received"),
                LABELS,
                registry
            )
            .unwrap(),

            conn_duration: register_histogram_vec_with_registry!(
                format!("conn_duration_sec"),
                format!("Records the duration of connection in seconds"),
                LABELS,
                CONN_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            requests_per_conn: register_histogram_vec_with_registry!(
                format!("conn_requests_per_conn"),
                format!("Records the number of requests per connection"),
                LABELS,
                CONN_REQUESTS.to_vec(),
                registry
            )
            .unwrap(),

            conn_tls_handshake_duration: register_histogram_vec_with_registry!(
                format!("conn_tls_handshake_duration_sec"),
                format!("Records the duration of the TLS handshake in seconds"),
                &LABELS[0..4],
                HANDSHAKE_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}
