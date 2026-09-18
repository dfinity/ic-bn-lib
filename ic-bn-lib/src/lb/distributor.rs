use std::{
    fmt::{Debug, Display},
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Instant,
};

use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use scopeguard::defer;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use super::{ExecutesRequest, wrr::Wrr};

#[derive(Clone, Debug)]
pub struct Metrics {
    inflight: IntGaugeVec,
    requests: IntCounterVec,
    duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            inflight: register_int_gauge_vec_with_registry!(
                format!("distributor_inflight"),
                format!("Stores the current number of in-flight requests"),
                &["target"],
                registry
            )
            .unwrap(),

            requests: register_int_counter_vec_with_registry!(
                format!("distributor_requests"),
                format!("Counts the number of requests and results"),
                &["target", "result"],
                registry
            )
            .unwrap(),

            duration: register_histogram_vec_with_registry!(
                format!("distributor_duration"),
                format!("Records the duration of requests in seconds"),
                &["target"],
                [0.01, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2].to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

/// Distribution strategy to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    #[strum(serialize = "wrr")]
    #[serde(alias = "wrr")]
    WeightedRoundRobin,
    #[strum(serialize = "lor")]
    #[serde(alias = "lor")]
    LeastOutstandingRequests,
}

/// Backend that represents a target that receives the request
#[derive(Debug, Clone)]
pub struct Backend<T> {
    backend: T,
    name: String,
    weight: usize,
    inflight: Arc<AtomicUsize>,
}

impl<T: Display + Send + Sync> Backend<T> {
    pub fn new(backend: T, weight: usize) -> Self {
        Self {
            name: backend.to_string(),
            backend,
            weight,
            inflight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Distributes the requests over backends using the given `Strategy`
#[derive(Debug)]
pub struct Distributor<T, RQ = (), RS = (), E = ()> {
    backends: Vec<Backend<T>>,
    strategy: Strategy,
    executor: Arc<dyn ExecutesRequest<T, Request = RQ, Response = RS, Error = E>>,
    wrr: Wrr<Backend<T>>,
    metrics: Metrics,
}

impl<T, RQ, RS, E> Distributor<T, RQ, RS, E>
where
    T: Clone + Display + Send + Sync,
    RQ: Send,
    RS: Send,
    E: Send,
{
    pub fn new(
        backends: &[(usize, T)],
        strategy: Strategy,
        executor: Arc<dyn ExecutesRequest<T, Request = RQ, Response = RS, Error = E>>,
        metrics: Metrics,
    ) -> Self {
        if backends.is_empty() {
            panic!("There must be at least one backend");
        }

        let backends = backends
            .iter()
            .map(|(w, b)| Backend::new(b.clone(), *w))
            .collect::<Vec<_>>();

        let wrr = Wrr::new(
            backends
                .clone()
                .into_iter()
                .map(|x| (x.weight, x))
                .collect(),
        );

        Self {
            backends,
            strategy,
            executor,
            wrr,
            metrics,
        }
    }

    /// Picks the next backend to execute the request using WRR algorigthm.
    /// Based on http://kb.linuxvirtualserver.org/wiki/Weighted_Round-Robin_Scheduling
    fn next_wrr(&self) -> &Backend<T> {
        self.wrr.next()
    }

    /// Picks the next backend to execute the request using Least Outstanding Requests algorigthm.
    fn next_lor(&self) -> &Backend<T> {
        self.backends
            .iter()
            .min_by_key(|x| x.inflight.load(Ordering::SeqCst))
            .unwrap()
    }

    /// Execute the request using the next server picked by selected algorithm
    pub async fn execute(&self, request: RQ) -> Result<RS, E> {
        let backend = match self.strategy {
            Strategy::LeastOutstandingRequests => self.next_lor(),
            Strategy::WeightedRoundRobin => self.next_wrr(),
        };

        backend.inflight.fetch_add(1, Ordering::SeqCst);
        self.metrics
            .inflight
            .with_label_values(&[&backend.name])
            .inc();

        let start = Instant::now();
        let ok = Arc::new(AtomicU8::new(0));
        let ok_clone = ok.clone();

        // Record metrics under defer to make sure they're recorded in case of future cancellation
        defer! {
            backend.inflight.fetch_sub(1, Ordering::SeqCst);
            self.metrics.inflight.with_label_values(&[&backend.name]).dec();
            self.metrics
                .duration
                .with_label_values(&[&backend.name])
                .observe(start.elapsed().as_secs_f64());
            self.metrics
                .requests
                .with_label_values(&[
                    backend.name.as_str(),
                    match ok_clone.load(Ordering::SeqCst) {
                        1 => "ok",
                        2 => "fail",
                        _ => "cancel"
                    }])
                .inc();
        }

        let res = self.executor.execute(&backend.backend, request).await;
        ok.store(if res.is_ok() { 1 } else { 2 }, Ordering::SeqCst);
        res
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::{collections::HashMap, sync::Mutex, time::Duration};

    use async_trait::async_trait;
    use tokio::{sync::Notify, task::JoinSet};

    use super::*;

    #[derive(Debug)]
    pub struct TestExecutor(pub Duration, pub Mutex<HashMap<String, usize>>);

    #[async_trait]
    impl ExecutesRequest<String> for TestExecutor {
        type Error = ();
        type Request = ();
        type Response = ();

        async fn execute(
            &self,
            backend: &String,
            _req: Self::Request,
        ) -> Result<Self::Response, Self::Error> {
            *self.1.lock().unwrap().entry(backend.clone()).or_insert(0) += 1;
            if self.0 > Duration::ZERO {
                tokio::time::sleep(self.0).await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_distributor_wrr() {
        let backends = vec![
            (2, "foo".to_string()),
            (3, "bar".to_string()),
            (5, "baz".to_string()),
        ];

        let executor = Arc::new(TestExecutor(Duration::ZERO, Mutex::new(HashMap::new())));
        let metrics = Metrics::new(&Registry::new());
        let d = Distributor::new(
            &backends,
            Strategy::WeightedRoundRobin,
            executor.clone(),
            metrics,
        );

        // Do 1k backend selections
        for _ in 0..1000 {
            let _ = d.execute(()).await;
        }

        // Make sure that we get the distribution according to the weights
        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 200);
        assert_eq!(h["bar"], 300);
        assert_eq!(h["baz"], 500);
        drop(h)
    }

    #[tokio::test(start_paused = true)]
    async fn test_distributor_lor() {
        let backends = vec![
            (2, "foo".to_string()),
            (3, "bar".to_string()),
            (5, "baz".to_string()),
        ];

        let executor = Arc::new(TestExecutor(
            Duration::from_secs(1),
            Mutex::new(HashMap::new()),
        ));

        let metrics = Metrics::new(&Registry::new());
        let d = Arc::new(Distributor::new(
            &backends,
            Strategy::LeastOutstandingRequests,
            executor.clone(),
            metrics,
        ));

        let mut js = JoinSet::new();
        // Do 1k backend selections
        for _ in 0..60 {
            let d = d.clone();
            js.spawn(async move {
                let _ = d.execute(()).await;
            });
        }

        js.join_all().await;

        // Make sure that we get even distribution since the requests are accumulated on each node evenly
        // due to sleep
        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 20);
        assert_eq!(h["bar"], 20);
        assert_eq!(h["baz"], 20);
        drop(h)
    }

    /// Executor that always fails, naming the backend it was given
    #[derive(Debug)]
    pub struct FailingExecutor;

    #[async_trait]
    impl ExecutesRequest<String> for FailingExecutor {
        type Error = String;
        type Request = ();
        type Response = ();

        async fn execute(
            &self,
            backend: &String,
            _req: Self::Request,
        ) -> Result<Self::Response, Self::Error> {
            Err(format!("boom: {backend}"))
        }
    }

    /// Executor that parks inside `execute` until the gate is opened, so that
    /// tests can observe in-flight state deterministically without any sleeping.
    #[derive(Debug, Default)]
    pub struct GateExecutor {
        pub gate: Arc<Notify>,
        pub started: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ExecutesRequest<String> for GateExecutor {
        type Error = ();
        type Request = ();
        type Response = ();

        async fn execute(
            &self,
            _backend: &String,
            _req: Self::Request,
        ) -> Result<Self::Response, Self::Error> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.gate.notified().await;
            Ok(())
        }
    }

    pub fn counting_executor() -> Arc<TestExecutor> {
        Arc::new(TestExecutor(Duration::ZERO, Mutex::new(HashMap::new())))
    }

    #[test]
    fn test_strategy_display_and_from_str() {
        // The `strum(serialize = ...)` overrides are what Display emits
        assert_eq!(Strategy::WeightedRoundRobin.to_string(), "wrr");
        assert_eq!(Strategy::LeastOutstandingRequests.to_string(), "lor");

        assert_eq!(
            "wrr".parse::<Strategy>().unwrap(),
            Strategy::WeightedRoundRobin
        );
        assert_eq!(
            "lor".parse::<Strategy>().unwrap(),
            Strategy::LeastOutstandingRequests
        );

        // Display -> FromStr round-trip
        for s in [
            Strategy::WeightedRoundRobin,
            Strategy::LeastOutstandingRequests,
        ] {
            assert_eq!(s.to_string().parse::<Strategy>().unwrap(), s);
        }

        // The override replaces the variant name and parsing is case-sensitive
        assert!("WeightedRoundRobin".parse::<Strategy>().is_err());
        assert!("WRR".parse::<Strategy>().is_err());
        assert!("".parse::<Strategy>().is_err());
        assert!("weighted".parse::<Strategy>().is_err());
    }

    #[test]
    fn test_strategy_serde() {
        // Serde uses the snake_case variant names, not the short strum ones
        assert_eq!(
            serde_json::to_string(&Strategy::WeightedRoundRobin).unwrap(),
            r#""weighted_round_robin""#
        );
        assert_eq!(
            serde_json::to_string(&Strategy::LeastOutstandingRequests).unwrap(),
            r#""least_outstanding_requests""#
        );

        // Both the canonical names and the short aliases deserialize
        for (json, expect) in [
            (r#""weighted_round_robin""#, Strategy::WeightedRoundRobin),
            (r#""wrr""#, Strategy::WeightedRoundRobin),
            (
                r#""least_outstanding_requests""#,
                Strategy::LeastOutstandingRequests,
            ),
            (r#""lor""#, Strategy::LeastOutstandingRequests),
        ] {
            assert_eq!(serde_json::from_str::<Strategy>(json).unwrap(), expect);
            // ...and round-trips back
            assert_eq!(
                serde_json::from_str::<Strategy>(&serde_json::to_string(&expect).unwrap()).unwrap(),
                expect
            );
        }

        assert!(serde_json::from_str::<Strategy>(r#""WeightedRoundRobin""#).is_err());
        assert!(serde_json::from_str::<Strategy>(r#""nope""#).is_err());
    }

    #[test]
    #[should_panic(expected = "There must be at least one backend")]
    fn test_distributor_no_backends_panics() {
        let _ = Distributor::<String>::new(
            &[],
            Strategy::WeightedRoundRobin,
            counting_executor(),
            Metrics::new(&Registry::new()),
        );
    }

    #[test]
    fn test_backend_new() {
        #[derive(Clone, Debug)]
        struct Node(u16);

        impl Display for Node {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "node-{}", self.0)
            }
        }

        // The metric label comes from Display, not from Debug
        let b = Backend::new(Node(42), 7);
        assert_eq!(b.name, "node-42");
        assert_eq!(b.weight, 7);
        assert_eq!(b.inflight.load(Ordering::SeqCst), 0);

        // A cloned backend shares the in-flight counter, which is what lets
        // the WRR copy inside `Wrr` and the one in `backends` stay in sync.
        let c = b.clone();
        b.inflight.fetch_add(1, Ordering::SeqCst);
        assert_eq!(c.inflight.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_distributor_lor_picks_least_loaded() {
        let backends = vec![
            (1, "foo".to_string()),
            (1, "bar".to_string()),
            (1, "baz".to_string()),
        ];

        let d = Distributor::<String>::new(
            &backends,
            Strategy::LeastOutstandingRequests,
            counting_executor(),
            Metrics::new(&Registry::new()),
        );

        d.backends[0].inflight.store(5, Ordering::SeqCst);
        d.backends[1].inflight.store(1, Ordering::SeqCst);
        d.backends[2].inflight.store(3, Ordering::SeqCst);
        assert_eq!(d.next_lor().name, "bar");

        // Loading up the previous winner moves the selection
        d.backends[1].inflight.store(9, Ordering::SeqCst);
        assert_eq!(d.next_lor().name, "baz");

        // Ties are broken by position, so the choice stays deterministic
        for b in &d.backends {
            b.inflight.store(4, Ordering::SeqCst);
        }
        assert_eq!(d.next_lor().name, "foo");
    }

    #[tokio::test]
    async fn test_distributor_lor_ignores_weights() {
        let backends = vec![
            (1, "foo".to_string()),
            (100, "bar".to_string()),
            (100, "baz".to_string()),
        ];

        let executor = counting_executor();
        let d = Distributor::new(
            &backends,
            Strategy::LeastOutstandingRequests,
            executor.clone(),
            Metrics::new(&Registry::new()),
        );

        // Requests issued one at a time always see all counters at zero, so the
        // tie-break sends everything to the first backend - weights are not consulted.
        for _ in 0..10 {
            d.execute(()).await.unwrap();
        }

        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 10);
        assert_eq!(h.len(), 1);
    }

    #[tokio::test]
    async fn test_distributor_wrr_single_and_zero_weight_backends() {
        // A lone backend gets everything, even with a zero weight
        for w in [0, 3] {
            let executor = counting_executor();
            let d = Distributor::new(
                &[(w, "solo".to_string())],
                Strategy::WeightedRoundRobin,
                executor.clone(),
                Metrics::new(&Registry::new()),
            );

            for _ in 0..5 {
                d.execute(()).await.unwrap();
            }

            assert_eq!(executor.1.lock().unwrap()["solo"], 5);
        }

        // Next to a positive weight, a zero-weighted backend is never picked
        let executor = counting_executor();
        let d = Distributor::new(
            &[(0, "off".to_string()), (1, "on".to_string())],
            Strategy::WeightedRoundRobin,
            executor.clone(),
            Metrics::new(&Registry::new()),
        );

        for _ in 0..20 {
            d.execute(()).await.unwrap();
        }

        let h = executor.1.lock().unwrap();
        assert_eq!(h["on"], 20);
        assert!(!h.contains_key("off"));
    }

    #[tokio::test]
    async fn test_distributor_wrr_weights_change_on_rebuild() {
        // Weight/membership changes are applied by building a new Distributor,
        // which is exactly what BackendRouter does when health state changes.
        let executor = counting_executor();

        let d = Distributor::new(
            &[(1, "foo".to_string()), (1, "bar".to_string())],
            Strategy::WeightedRoundRobin,
            executor.clone(),
            Metrics::new(&Registry::new()),
        );
        for _ in 0..100 {
            d.execute(()).await.unwrap();
        }
        {
            let h = executor.1.lock().unwrap();
            assert_eq!(h["foo"], 50);
            assert_eq!(h["bar"], 50);
        }

        let d = Distributor::new(
            &[(1, "foo".to_string()), (3, "bar".to_string())],
            Strategy::WeightedRoundRobin,
            executor.clone(),
            Metrics::new(&Registry::new()),
        );
        for _ in 0..100 {
            d.execute(()).await.unwrap();
        }

        // The second batch is split 25/75 on top of the even first batch
        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 75);
        assert_eq!(h["bar"], 125);
    }

    #[tokio::test]
    async fn test_distributor_metrics_success() {
        let executor = counting_executor();
        let metrics = Metrics::new(&Registry::new());
        let d = Distributor::new(
            &[(1, "foo".to_string())],
            Strategy::WeightedRoundRobin,
            executor,
            metrics.clone(),
        );

        for _ in 0..3 {
            d.execute(()).await.unwrap();
        }

        assert_eq!(metrics.requests.with_label_values(&["foo", "ok"]).get(), 3);
        assert_eq!(
            metrics.requests.with_label_values(&["foo", "fail"]).get(),
            0
        );
        assert_eq!(
            metrics.requests.with_label_values(&["foo", "cancel"]).get(),
            0
        );
        // Every request is timed...
        assert_eq!(
            metrics
                .duration
                .with_label_values(&["foo"])
                .get_sample_count(),
            3
        );
        // ...and the in-flight accounting is balanced again
        assert_eq!(metrics.inflight.with_label_values(&["foo"]).get(), 0);
        assert_eq!(d.backends[0].inflight.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_distributor_metrics_failure() {
        let metrics = Metrics::new(&Registry::new());
        let d: Distributor<String, (), (), String> = Distributor::new(
            &[(1, "foo".to_string())],
            Strategy::WeightedRoundRobin,
            Arc::new(FailingExecutor),
            metrics.clone(),
        );

        // The executor error is passed through verbatim
        assert_eq!(d.execute(()).await.unwrap_err(), "boom: foo");

        assert_eq!(
            metrics.requests.with_label_values(&["foo", "fail"]).get(),
            1
        );
        assert_eq!(metrics.requests.with_label_values(&["foo", "ok"]).get(), 0);
        assert_eq!(metrics.inflight.with_label_values(&["foo"]).get(), 0);
        assert_eq!(d.backends[0].inflight.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_distributor_metrics_cancellation() {
        let executor = Arc::new(GateExecutor::default());
        let metrics = Metrics::new(&Registry::new());
        let d: Distributor<String> = Distributor::new(
            &[(1, "foo".to_string())],
            Strategy::WeightedRoundRobin,
            executor.clone(),
            metrics.clone(),
        );

        let mut fut = tokio_test::task::spawn(d.execute(()));

        // The request is now in flight, parked inside the executor
        assert!(fut.poll().is_pending());
        assert_eq!(executor.started.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.inflight.with_label_values(&["foo"]).get(), 1);
        assert_eq!(d.backends[0].inflight.load(Ordering::SeqCst), 1);

        // Dropping the future mid-flight must still release the in-flight slot
        // and record the request as cancelled (that's what the `defer!` is for)
        drop(fut);
        assert_eq!(
            metrics.requests.with_label_values(&["foo", "cancel"]).get(),
            1
        );
        assert_eq!(metrics.requests.with_label_values(&["foo", "ok"]).get(), 0);
        assert_eq!(
            metrics.requests.with_label_values(&["foo", "fail"]).get(),
            0
        );
        assert_eq!(metrics.inflight.with_label_values(&["foo"]).get(), 0);
        assert_eq!(d.backends[0].inflight.load(Ordering::SeqCst), 0);
        assert_eq!(
            metrics
                .duration
                .with_label_values(&["foo"])
                .get_sample_count(),
            1
        );
    }

    #[tokio::test]
    async fn test_distributor_inflight_tracks_concurrency() {
        let executor = Arc::new(GateExecutor::default());
        let metrics = Metrics::new(&Registry::new());
        let d: Arc<Distributor<String>> = Arc::new(Distributor::new(
            &[(1, "foo".to_string()), (1, "bar".to_string())],
            Strategy::WeightedRoundRobin,
            executor.clone(),
            metrics.clone(),
        ));

        let mut js = JoinSet::new();
        for _ in 0..4 {
            let d = d.clone();
            js.spawn(async move { d.execute(()).await });
        }

        // Wait until all of them are parked in the executor
        while executor.started.load(Ordering::SeqCst) < 4 {
            tokio::task::yield_now().await;
        }

        // WRR keeps handing out backends in turn regardless of the load on them,
        // so the four in-flight requests are split evenly
        assert_eq!(metrics.inflight.with_label_values(&["foo"]).get(), 2);
        assert_eq!(metrics.inflight.with_label_values(&["bar"]).get(), 2);
        assert_eq!(d.backends[0].inflight.load(Ordering::SeqCst), 2);
        assert_eq!(d.backends[1].inflight.load(Ordering::SeqCst), 2);

        executor.gate.notify_waiters();
        assert_eq!(js.join_all().await, vec![Ok(()); 4]);

        for b in ["foo", "bar"] {
            assert_eq!(metrics.inflight.with_label_values(&[b]).get(), 0);
            assert_eq!(metrics.requests.with_label_values(&[b, "ok"]).get(), 2);
        }
    }

    /// Executor that echoes the backend it was handed together with the request
    #[derive(Debug)]
    struct EchoExecutor;

    #[async_trait]
    impl ExecutesRequest<String> for EchoExecutor {
        type Error = ();
        type Request = String;
        type Response = String;

        async fn execute(
            &self,
            backend: &String,
            req: Self::Request,
        ) -> Result<Self::Response, Self::Error> {
            Ok(format!("{backend}:{req}"))
        }
    }

    #[tokio::test]
    async fn test_distributor_passes_request_and_response_through() {
        let d: Distributor<String, String, String, ()> = Distributor::new(
            &[(1, "foo".to_string()), (1, "bar".to_string())],
            Strategy::WeightedRoundRobin,
            Arc::new(EchoExecutor),
            Metrics::new(&Registry::new()),
        );

        // The request body reaches the executor untouched, paired with the
        // backend WRR picked, and the response comes back verbatim
        assert_eq!(d.execute("hello".to_string()).await.unwrap(), "foo:hello");
        assert_eq!(d.execute("world".to_string()).await.unwrap(), "bar:world");
        // ...including an empty payload
        assert_eq!(d.execute(String::new()).await.unwrap(), "foo:");
    }

    #[tokio::test]
    async fn test_distributor_metrics_are_labelled_per_picked_target() {
        let executor = counting_executor();
        let metrics = Metrics::new(&Registry::new());
        let d = Distributor::new(
            &[(1, "foo".to_string()), (3, "bar".to_string())],
            Strategy::WeightedRoundRobin,
            executor.clone(),
            metrics.clone(),
        );

        // Two full WRR periods of 4 picks: 1 x foo + 3 x bar each
        for _ in 0..8 {
            d.execute(()).await.unwrap();
        }

        // Every metric is attributed to the backend that actually ran the
        // request rather than to a single fixed label
        assert_eq!(metrics.requests.with_label_values(&["foo", "ok"]).get(), 2);
        assert_eq!(metrics.requests.with_label_values(&["bar", "ok"]).get(), 6);
        assert_eq!(
            metrics
                .duration
                .with_label_values(&["foo"])
                .get_sample_count(),
            2
        );
        assert_eq!(
            metrics
                .duration
                .with_label_values(&["bar"])
                .get_sample_count(),
            6
        );
        for b in ["foo", "bar"] {
            assert_eq!(metrics.inflight.with_label_values(&[b]).get(), 0);
        }

        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 2);
        assert_eq!(h["bar"], 6);
    }
}
