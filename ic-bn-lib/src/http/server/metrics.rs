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

#[cfg(test)]
mod test {
    use prometheus::proto::MetricFamily;

    use super::*;

    const L: [&str; 6] = [
        "127.0.0.1:443",
        "v4",
        "TLSv1_3",
        "TLS13_AES_256_GCM_SHA384",
        "no",
        "yes",
    ];

    /// Families that carry the full 6-label set
    const FULL: &[&str] = &[
        "conn_total",
        "conn_requests_total",
        "conn_bytes_sent_total",
        "conn_bytes_rcvd_total",
        "conn_duration_sec",
        "conn_requests_per_conn",
    ];

    /// Families that carry only the first 4 labels
    const SHORT: &[&str] = &[
        "conn_open",
        "conn_requests_inflight",
        "conn_tls_handshake_duration_sec",
    ];

    /// Creates a child for every metric so that the families show up in `gather()`
    fn touch_all(m: &Metrics) {
        m.conns.with_label_values(&L);
        m.requests.with_label_values(&L);
        m.bytes_sent.with_label_values(&L);
        m.bytes_rcvd.with_label_values(&L);
        m.conn_duration.with_label_values(&L);
        m.requests_per_conn.with_label_values(&L);
        m.conns_open.with_label_values(&L[0..4]);
        m.requests_inflight.with_label_values(&L[0..4]);
        m.conn_tls_handshake_duration.with_label_values(&L[0..4]);
    }

    fn family(registry: &Registry, name: &str) -> MetricFamily {
        registry
            .gather()
            .into_iter()
            .find(|x| x.name() == name)
            .unwrap_or_else(|| panic!("metric family '{name}' not registered"))
    }

    fn label_names(registry: &Registry, name: &str) -> Vec<String> {
        let f = family(registry, name);
        let mut v = f.get_metric()[0]
            .get_label()
            .iter()
            .map(|x| x.name().to_string())
            .collect::<Vec<_>>();
        v.sort();
        v
    }

    fn buckets(registry: &Registry, name: &str) -> Vec<(f64, u64)> {
        family(registry, name).get_metric()[0]
            .get_histogram()
            .get_bucket()
            .iter()
            .map(|x| (x.upper_bound(), x.cumulative_count()))
            .collect()
    }

    #[test]
    fn test_metrics_registers_expected_names() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);
        touch_all(&m);

        let mut names = registry
            .gather()
            .iter()
            .map(|x| x.name().to_string())
            .collect::<Vec<_>>();
        names.sort();

        assert_eq!(
            names,
            vec![
                "conn_bytes_rcvd_total",
                "conn_bytes_sent_total",
                "conn_duration_sec",
                "conn_open",
                "conn_requests_inflight",
                "conn_requests_per_conn",
                "conn_requests_total",
                "conn_tls_handshake_duration_sec",
                "conn_total",
            ]
        );

        // Nothing else must have been registered
        assert_eq!(registry.gather().len(), 9);
    }

    #[test]
    fn test_metrics_label_names() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);
        touch_all(&m);

        let full = vec![
            "addr".to_string(),
            "family".to_string(),
            "forced_close".to_string(),
            "recycled".to_string(),
            "tls_cipher".to_string(),
            "tls_version".to_string(),
        ];
        for name in FULL {
            assert_eq!(label_names(&registry, name), full, "family '{name}'");
        }

        let short = vec![
            "addr".to_string(),
            "family".to_string(),
            "tls_cipher".to_string(),
            "tls_version".to_string(),
        ];
        for name in SHORT {
            assert_eq!(label_names(&registry, name), short, "family '{name}'");
        }
    }

    #[test]
    fn test_metrics_label_arity_is_enforced() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        // The full-label metrics accept exactly 6 values
        assert!(m.conns.get_metric_with_label_values(&L).is_ok());
        assert!(m.conns.get_metric_with_label_values(&L[0..4]).is_err());
        assert!(m.conns.get_metric_with_label_values(&L[0..5]).is_err());
        assert!(m.requests.get_metric_with_label_values(&L[0..4]).is_err());
        assert!(m.bytes_sent.get_metric_with_label_values(&L[0..4]).is_err());
        assert!(m.bytes_rcvd.get_metric_with_label_values(&L[0..4]).is_err());
        assert!(
            m.conn_duration
                .get_metric_with_label_values(&L[0..4])
                .is_err()
        );
        assert!(
            m.requests_per_conn
                .get_metric_with_label_values(&L[0..4])
                .is_err()
        );

        // ...and the short ones exactly 4
        assert!(m.conns_open.get_metric_with_label_values(&L[0..4]).is_ok());
        assert!(m.conns_open.get_metric_with_label_values(&L).is_err());
        assert!(
            m.requests_inflight
                .get_metric_with_label_values(&L[0..4])
                .is_ok()
        );
        assert!(
            m.requests_inflight
                .get_metric_with_label_values(&L)
                .is_err()
        );
        assert!(
            m.conn_tls_handshake_duration
                .get_metric_with_label_values(&L[0..4])
                .is_ok()
        );
        assert!(
            m.conn_tls_handshake_duration
                .get_metric_with_label_values(&L)
                .is_err()
        );
    }

    #[test]
    fn test_metrics_counters_and_gauges_record() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        m.conns.with_label_values(&L).inc();
        m.requests.with_label_values(&L).inc_by(7);
        m.bytes_sent.with_label_values(&L).inc_by(1234);
        m.bytes_rcvd.with_label_values(&L).inc_by(4321);

        m.conns_open.with_label_values(&L[0..4]).inc();
        m.conns_open.with_label_values(&L[0..4]).inc();
        m.conns_open.with_label_values(&L[0..4]).dec();

        m.requests_inflight.with_label_values(&L[0..4]).inc();
        m.requests_inflight.with_label_values(&L[0..4]).inc();
        m.requests_inflight.with_label_values(&L[0..4]).inc();

        let value = |name: &str| {
            family(&registry, name).get_metric()[0]
                .get_counter()
                .value()
        };
        assert_eq!(value("conn_total"), 1.0);
        assert_eq!(value("conn_requests_total"), 7.0);
        assert_eq!(value("conn_bytes_sent_total"), 1234.0);
        assert_eq!(value("conn_bytes_rcvd_total"), 4321.0);

        let gauge = |name: &str| family(&registry, name).get_metric()[0].get_gauge().value();
        assert_eq!(gauge("conn_open"), 1.0);
        assert_eq!(gauge("conn_requests_inflight"), 3.0);

        // Label values are carried through
        let labels = family(&registry, "conn_total").get_metric()[0]
            .get_label()
            .iter()
            .map(|x| (x.name().to_string(), x.value().to_string()))
            .collect::<Vec<_>>();
        assert!(labels.contains(&("addr".to_string(), "127.0.0.1:443".to_string())));
        assert!(labels.contains(&("recycled".to_string(), "yes".to_string())));
        assert!(labels.contains(&("forced_close".to_string(), "no".to_string())));
    }

    #[test]
    fn test_metrics_distinct_label_sets_are_separate_series() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        m.conns.with_label_values(&L).inc();
        let mut other = L;
        other[4] = "yes";
        m.conns.with_label_values(&other).inc_by(5);

        let f = family(&registry, "conn_total");
        assert_eq!(f.get_metric().len(), 2);

        let by_forced = |v: &str| {
            f.get_metric()
                .iter()
                .find(|m| {
                    m.get_label()
                        .iter()
                        .any(|l| l.name() == "forced_close" && l.value() == v)
                })
                .unwrap()
                .get_counter()
                .value()
        };
        assert_eq!(by_forced("no"), 1.0);
        assert_eq!(by_forced("yes"), 5.0);
    }

    #[test]
    fn test_metrics_conn_duration_buckets() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        m.conn_duration.with_label_values(&L).observe(9.0);

        let h = family(&registry, "conn_duration_sec").get_metric()[0]
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 1);
        assert_eq!(h.sample_sum(), 9.0);
        assert_eq!(
            buckets(&registry, "conn_duration_sec"),
            vec![
                (1.0, 0),
                (8.0, 0),
                (32.0, 1),
                (64.0, 1),
                (256.0, 1),
                (512.0, 1),
                (1024.0, 1),
            ]
        );
    }

    #[test]
    fn test_metrics_requests_per_conn_buckets() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        // Two connections: one served nothing, one served 7 requests
        m.requests_per_conn.with_label_values(&L).observe(0.0);
        m.requests_per_conn.with_label_values(&L).observe(7.0);

        let h = family(&registry, "conn_requests_per_conn").get_metric()[0]
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 2);
        assert_eq!(h.sample_sum(), 7.0);
        assert_eq!(
            buckets(&registry, "conn_requests_per_conn"),
            vec![
                (1.0, 1),
                (4.0, 1),
                (8.0, 2),
                (16.0, 2),
                (32.0, 2),
                (64.0, 2),
                (256.0, 2),
            ]
        );
    }

    #[test]
    fn test_metrics_tls_handshake_buckets() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        m.conn_tls_handshake_duration
            .with_label_values(&L[0..4])
            .observe(0.015);

        let h = family(&registry, "conn_tls_handshake_duration_sec").get_metric()[0]
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 1);
        assert_eq!(h.sample_sum(), 0.015);
        assert_eq!(
            buckets(&registry, "conn_tls_handshake_duration_sec"),
            vec![
                (0.005, 0),
                (0.01, 0),
                (0.02, 1),
                (0.05, 1),
                (0.1, 1),
                (0.2, 1),
                (0.4, 1),
                (0.8, 1),
                (1.6, 1),
            ]
        );
    }

    /// Prometheus buckets are `le` (less-or-equal), so an observation that lands
    /// exactly on a boundary must be counted in that bucket, not the next one.
    #[test]
    fn test_metrics_bucket_upper_bound_is_inclusive() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        m.conn_duration.with_label_values(&L).observe(8.0);

        assert_eq!(
            buckets(&registry, "conn_duration_sec"),
            vec![
                (1.0, 0),
                (8.0, 1),
                (32.0, 1),
                (64.0, 1),
                (256.0, 1),
                (512.0, 1),
                (1024.0, 1),
            ]
        );
    }

    /// An observation above the highest bucket only lands in the implicit `+Inf`
    /// one, so `sample_count` is bigger than the last bucket's count.
    #[test]
    fn test_metrics_observation_above_top_bucket() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        m.requests_per_conn.with_label_values(&L).observe(1000.0);

        let h = family(&registry, "conn_requests_per_conn").get_metric()[0]
            .get_histogram()
            .clone();
        assert_eq!(h.sample_count(), 1);
        assert_eq!(h.sample_sum(), 1000.0);
        // Every explicit bucket stayed empty
        assert!(
            buckets(&registry, "conn_requests_per_conn")
                .iter()
                .all(|(_, c)| *c == 0),
            "{:?}",
            buckets(&registry, "conn_requests_per_conn")
        );
    }

    /// `Metrics::new` registers into the registry it is given, so two independent
    /// registries must each get their own set without colliding.
    #[test]
    fn test_metrics_two_registries_are_independent() {
        let r1 = Registry::new();
        let r2 = Registry::new();
        let m1 = Metrics::new(&r1);
        let m2 = Metrics::new(&r2);

        m1.conns.with_label_values(&L).inc_by(3);
        m2.conns.with_label_values(&L).inc_by(11);

        let value = |r: &Registry| {
            family(r, "conn_total").get_metric()[0]
                .get_counter()
                .value()
        };
        assert_eq!(value(&r1), 3.0);
        assert_eq!(value(&r2), 11.0);
    }

    /// Guards against a counter silently becoming a gauge (or vice versa) - that
    /// would break every dashboard/alert built on top of these.
    #[test]
    fn test_metrics_types_and_help() {
        use prometheus::proto::MetricType;

        let registry = Registry::new();
        let m = Metrics::new(&registry);
        touch_all(&m);

        let expected = [
            ("conn_total", MetricType::COUNTER),
            ("conn_requests_total", MetricType::COUNTER),
            ("conn_bytes_sent_total", MetricType::COUNTER),
            ("conn_bytes_rcvd_total", MetricType::COUNTER),
            ("conn_open", MetricType::GAUGE),
            ("conn_requests_inflight", MetricType::GAUGE),
            ("conn_duration_sec", MetricType::HISTOGRAM),
            ("conn_requests_per_conn", MetricType::HISTOGRAM),
            ("conn_tls_handshake_duration_sec", MetricType::HISTOGRAM),
        ];

        for (name, typ) in expected {
            let f = family(&registry, name);
            assert_eq!(f.get_field_type(), typ, "family '{name}'");
            assert!(!f.help().is_empty(), "family '{name}' has no help text");
        }
    }

    #[test]
    fn test_metrics_use_a_fresh_registry() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);
        // A different registry must stay untouched
        let other = Registry::new();
        touch_all(&m);
        assert!(other.gather().is_empty());
        assert_eq!(registry.gather().len(), 9);
    }

    /// Metric names must be registered in the provided registry,
    /// so registering the same set twice has to be rejected.
    #[test]
    #[should_panic(expected = "AlreadyReg")]
    fn test_metrics_duplicate_registration_panics() {
        let registry = Registry::new();
        let _m1 = Metrics::new(&registry);
        let _m2 = Metrics::new(&registry);
    }

    #[test]
    fn test_metrics_clone_shares_state() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);
        let m2 = m.clone();

        m.conns.with_label_values(&L).inc();
        m2.conns.with_label_values(&L).inc();

        assert_eq!(
            family(&registry, "conn_total").get_metric()[0]
                .get_counter()
                .value(),
            2.0
        );
    }
}
