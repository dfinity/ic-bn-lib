use std::{
    fmt::{Debug, Display},
    sync::Arc,
    time::Duration,
};

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::{select, sync::watch::Receiver};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::{
    ChecksTarget, ExecutesRequest, TargetState,
    distributor::{self, Distributor, Strategy},
    health_check::{self, HealthChecker},
};

#[derive(thiserror::Error)]
pub enum Error<E> {
    #[error("No healthy nodes")]
    NoHealthyNodes,
    #[error("{0}")]
    Inner(E),
}

struct Actor<T, RQ = (), RS = (), E = ()> {
    weights: Vec<usize>,
    health_checker: Arc<HealthChecker<T>>,
    strategy: Strategy,
    executor: Arc<dyn ExecutesRequest<T, Request = RQ, Response = RS, Error = E>>,
    distributor: Arc<ArcSwapOption<Distributor<T, RQ, RS, E>>>,
    distributor_metrics: distributor::Metrics,
    healthy: Arc<ArcSwap<Vec<T>>>,
}

impl<T, RQ, RS, E> Actor<T, RQ, RS, E>
where
    T: Clone + Display + Debug + Send + Sync + 'static,
    RQ: Send + 'static,
    RS: Send + 'static,
    E: Send + 'static,
{
    /// Create a new Distributor with a healthy node set
    async fn process(&self, backends: Arc<Vec<(T, TargetState)>>) {
        // Combine the nodes with their weights
        // and filter out unhealthy ones.
        let healthy = backends
            .iter()
            .zip(&self.weights)
            .filter(|x| x.0.1 == TargetState::Healthy)
            .map(|x| (*x.1, x.0.0.clone()))
            .collect::<Vec<_>>();

        // If there are no healthy nodes - remove the distributor
        if healthy.is_empty() {
            self.distributor.store(None);
            return;
        }

        let distributor = Distributor::new(
            &healthy,
            self.strategy,
            self.executor.clone(),
            self.distributor_metrics.clone(),
        );
        self.distributor.store(Some(Arc::new(distributor)));
        self.healthy
            .store(Arc::new(healthy.into_iter().map(|x| x.1).collect()));
    }

    async fn run(&self, token: CancellationToken) {
        // Subscribe to state notifications from HealthChecker
        let mut rx = self.health_checker.subscribe();

        loop {
            select! {
                biased;

                // Check if we need to shut down
                _ = token.cancelled() => {
                    self.health_checker.stop().await;
                    return;
                }

                // Process the changes in the set of healthy backends
                Ok(()) = rx.changed() => {
                    let backends = rx.borrow_and_update().clone();
                    self.process(backends).await;
                }
            }
        }
    }
}

/// Routes the request to healthy nodes provided by HealthChecker.
/// Uses Distributor with given Strategy to distribute them.
#[derive(Debug)]
pub struct BackendRouter<T, RQ = (), RS = (), E = ()> {
    token: CancellationToken,
    tracker: TaskTracker,
    distributor: Arc<ArcSwapOption<Distributor<T, RQ, RS, E>>>,
    notify: Receiver<Arc<Vec<(T, TargetState)>>>,
    healthy: Arc<ArcSwap<Vec<T>>>,
}

impl<T, RQ, RS, E> BackendRouter<T, RQ, RS, E>
where
    T: Clone + Display + Debug + Send + Sync + 'static,
    RQ: Send + 'static,
    RS: Send + 'static,
    E: Send + 'static,
{
    /// Create a new BackendRouter
    pub fn new(
        backends: &[(T, usize)],
        executor: Arc<dyn ExecutesRequest<T, Request = RQ, Response = RS, Error = E>>,
        checker: Arc<dyn ChecksTarget<T>>,
        strategy: Strategy,
        check_interval: Duration,
        health_check_metrics: health_check::Metrics,
        distributor_metrics: distributor::Metrics,
    ) -> Self {
        // Collect the weights for the Actor
        let weights = backends.iter().map(|x| x.1).collect();
        // Collect backends w/o weights for the HealthChecker
        let backends = backends.iter().map(|x| x.0.clone()).collect::<Vec<_>>();

        let health_checker = Arc::new(HealthChecker::new(
            &backends,
            checker,
            check_interval,
            health_check_metrics,
        ));
        let notify = health_checker.subscribe();

        let distributor = Arc::new(ArcSwapOption::empty());
        let healthy = Arc::new(ArcSwap::new(Arc::new(vec![])));

        let actor = Actor {
            weights,
            health_checker,
            strategy,
            executor,
            distributor: distributor.clone(),
            distributor_metrics,
            healthy: healthy.clone(),
        };

        let token = CancellationToken::new();
        let tracker = TaskTracker::new();

        let child_token = token.child_token();
        tracker.spawn(async move {
            actor.run(child_token).await;
        });

        Self {
            token,
            tracker,
            distributor,
            notify,
            healthy,
        }
    }

    /// Executes the request
    pub async fn execute(&self, request: RQ) -> Result<RS, Error<E>> {
        let Some(distributor) = self.distributor.load_full() else {
            return Err(Error::NoHealthyNodes);
        };

        distributor
            .execute(request)
            .await
            .map_err(|e| Error::Inner(e))
    }

    /// Subscribes to notifications when the set of healthy nodes changes.
    /// Returns a channel which emits a new set of healthy nodes.
    pub fn subscribe(&self) -> Receiver<Arc<Vec<(T, TargetState)>>> {
        self.notify.clone()
    }

    /// Returns the current set of healthy targets
    pub fn get_healthy(&self) -> Arc<Vec<T>> {
        self.healthy.load_full()
    }

    /// Stops the router
    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use async_trait::async_trait;
    use prometheus::Registry;
    use tokio::sync::Notify;

    use super::distributor::test::{
        FailingExecutor, GateExecutor, TestExecutor, counting_executor,
    };

    use super::*;

    struct TestChecker;

    #[async_trait]
    impl ChecksTarget<String> for TestChecker {
        async fn check(&self, target: &String) -> TargetState {
            if ["foo", "bar"].contains(&target.as_str()) {
                TargetState::Healthy
            } else {
                TargetState::Degraded
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_request_router_somewhat_healthy() {
        let executor = Arc::new(TestExecutor(Duration::ZERO, Mutex::new(HashMap::new())));

        let router = BackendRouter::new(
            &[
                ("foo".to_string(), 1),
                ("bar".to_string(), 2),
                ("baz".to_string(), 3),
            ],
            executor.clone(),
            Arc::new(TestChecker),
            Strategy::WeightedRoundRobin,
            Duration::from_millis(1),
            health_check::Metrics::new(&Registry::new()),
            distributor::Metrics::new(&Registry::new()),
        );

        // Wait a bit for health checks to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Do 900 requests
        for _ in 0..900 {
            assert!(router.execute(()).await.is_ok());
        }

        // Make sure that we get the distribution according to the weights
        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 300);
        assert_eq!(h["bar"], 600);
        // This one is unhealthy and shouldn't get any requests
        assert!(!h.contains_key("baz"));
        drop(h)
    }

    #[tokio::test(start_paused = true)]
    async fn test_request_router_unhealthy() {
        let executor = Arc::new(TestExecutor(Duration::ZERO, Mutex::new(HashMap::new())));

        let router = BackendRouter::new(
            &[("baz".to_string(), 3)],
            executor.clone(),
            Arc::new(TestChecker),
            Strategy::WeightedRoundRobin,
            Duration::from_millis(1),
            health_check::Metrics::new(&Registry::new()),
            distributor::Metrics::new(&Registry::new()),
        );

        // Wait a bit for health checks to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(matches!(
            router.execute(()).await.unwrap_err(),
            Error::NoHealthyNodes
        ));
    }

    /// Checker that reports only the given targets as healthy
    struct SetChecker(Vec<String>);

    impl SetChecker {
        fn new(healthy: &[&str]) -> Self {
            Self(healthy.iter().map(|x| (*x).to_string()).collect())
        }
    }

    #[async_trait]
    impl ChecksTarget<String> for SetChecker {
        async fn check(&self, target: &String) -> TargetState {
            if self.0.contains(target) {
                TargetState::Healthy
            } else {
                TargetState::Degraded
            }
        }
    }

    /// Checker where the verdict for a single target is controlled by a flag,
    /// while all the other targets are always healthy.
    struct FlipChecker {
        flaky: String,
        healthy: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ChecksTarget<String> for FlipChecker {
        async fn check(&self, target: &String) -> TargetState {
            if *target == self.flaky && !self.healthy.load(Ordering::SeqCst) {
                TargetState::Degraded
            } else {
                TargetState::Healthy
            }
        }
    }

    /// Checker that never returns a verdict until the gate is opened, and
    /// answers immediately from then on.
    ///
    /// The "from then on" part matters: `HealthChecker` awaits `check()` inside
    /// a `select!` arm, so a check that is still running cannot be cancelled and
    /// would keep `stop()` waiting forever (see
    /// `test_router_stop_hangs_while_a_check_is_in_flight`).
    struct GatedChecker {
        gate: Arc<Notify>,
        open: Arc<AtomicBool>,
    }

    impl GatedChecker {
        fn new() -> (Self, Arc<Notify>) {
            let gate = Arc::new(Notify::new());
            (
                Self {
                    gate: gate.clone(),
                    open: Arc::new(AtomicBool::new(false)),
                },
                gate,
            )
        }

        /// A gate that is never opened, so every check hangs
        fn never() -> Self {
            Self::new().0
        }
    }

    #[async_trait]
    impl ChecksTarget<String> for GatedChecker {
        async fn check(&self, _target: &String) -> TargetState {
            if !self.open.load(Ordering::SeqCst) {
                self.gate.notified().await;
                self.open.store(true, Ordering::SeqCst);
            }

            TargetState::Healthy
        }
    }

    fn backends(v: &[(&str, usize)]) -> Vec<(String, usize)> {
        v.iter().map(|(n, w)| ((*n).to_string(), *w)).collect()
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    /// Builds a router with a 1ms check interval and fresh metrics registries
    fn router(
        backends: &[(String, usize)],
        executor: Arc<TestExecutor>,
        checker: Arc<dyn ChecksTarget<String>>,
        strategy: Strategy,
    ) -> BackendRouter<String> {
        BackendRouter::new(
            backends,
            executor,
            checker,
            strategy,
            Duration::from_millis(1),
            health_check::Metrics::new(&Registry::new()),
            distributor::Metrics::new(&Registry::new()),
        )
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::<String>::NoHealthyNodes.to_string(),
            "No healthy nodes"
        );
        // The inner error is rendered transparently
        assert_eq!(Error::Inner("boom".to_string()).to_string(), "boom");
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_no_backends_before_first_check_result() {
        let (checker, gate) = GatedChecker::new();
        let executor = counting_executor();
        let router = router(
            &backends(&[("foo", 1)]),
            executor.clone(),
            Arc::new(checker),
            Strategy::WeightedRoundRobin,
        );

        // The health check is still in progress, so nothing is routable yet
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(router.get_healthy().is_empty());
        assert!(matches!(
            router.execute(()).await.unwrap_err(),
            Error::NoHealthyNodes
        ));

        // Let the check finish - the backend must become routable
        gate.notify_waiters();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*router.get_healthy(), names(&["foo"]));
        assert!(router.execute(()).await.is_ok());
        assert_eq!(executor.1.lock().unwrap()["foo"], 1);

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_weights_follow_backend_positions() {
        let executor = counting_executor();
        let router = router(
            &backends(&[("foo", 1), ("bar", 2), ("baz", 3)]),
            executor.clone(),
            Arc::new(SetChecker::new(&["bar", "baz"])),
            Strategy::WeightedRoundRobin,
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*router.get_healthy(), names(&["bar", "baz"]));

        for _ in 0..1000 {
            assert!(router.execute(()).await.is_ok());
        }

        // The healthy backends keep their own weights (2 and 3 -> 40%/60%)
        // instead of being re-zipped with the head of the weight list.
        let h = executor.counts();
        assert_eq!(h["bar"], 400);
        assert_eq!(h["baz"], 600);
        assert!(!h.contains_key("foo"));

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_zero_weight_backend_is_starved() {
        let executor = counting_executor();
        let router = router(
            &backends(&[("off", 0), ("on", 1)]),
            executor.clone(),
            Arc::new(SetChecker::new(&["off", "on"])),
            Strategy::WeightedRoundRobin,
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        // It is healthy and advertised...
        assert_eq!(*router.get_healthy(), names(&["off", "on"]));

        for _ in 0..20 {
            assert!(router.execute(()).await.is_ok());
        }

        // ...but WRR never sends it anything while a weighted peer exists
        let h = executor.counts();
        assert_eq!(h["on"], 20);
        assert!(!h.contains_key("off"));

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_lor_strategy() {
        let executor = counting_executor();
        let router = router(
            &backends(&[("foo", 1), ("bar", 5), ("baz", 5)]),
            executor.clone(),
            Arc::new(SetChecker::new(&["foo", "bar", "baz"])),
            Strategy::LeastOutstandingRequests,
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        for _ in 0..20 {
            assert!(router.execute(()).await.is_ok());
        }

        // Sequential requests leave every backend at zero in-flight, so LOR
        // deterministically takes the first one and ignores the weights.
        let h = executor.counts();
        assert_eq!(h["foo"], 20);
        assert_eq!(h.len(), 1);

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_subscribe_propagates_all_target_states() {
        let executor = counting_executor();
        let router = router(
            &backends(&[("foo", 1), ("bar", 1)]),
            executor,
            Arc::new(SetChecker::new(&["foo"])),
            Strategy::WeightedRoundRobin,
        );

        let mut rx = router.subscribe();
        // Nothing has been checked yet
        assert!(rx.borrow_and_update().is_empty());

        tokio::time::sleep(Duration::from_millis(100)).await;

        // The feed carries every target with its state, degraded ones included
        rx.changed().await.unwrap();
        assert_eq!(
            **rx.borrow_and_update(),
            [
                ("foo".to_string(), TargetState::Healthy),
                ("bar".to_string(), TargetState::Degraded),
            ]
        );

        // A subscriber attached after the fact sees the latest state immediately
        let mut late = router.subscribe();
        late.changed().await.unwrap();
        assert_eq!(*late.borrow_and_update(), *rx.borrow());

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_picks_up_recovered_backend() {
        let flag = Arc::new(AtomicBool::new(false));
        let executor = counting_executor();
        let router = router(
            &backends(&[("foo", 1), ("bar", 1)]),
            executor.clone(),
            Arc::new(FlipChecker {
                flaky: "bar".to_string(),
                healthy: flag.clone(),
            }),
            Strategy::WeightedRoundRobin,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*router.get_healthy(), names(&["foo"]));

        for _ in 0..10 {
            assert!(router.execute(()).await.is_ok());
        }
        {
            let h = executor.counts();
            assert_eq!(h["foo"], 10);
            assert!(!h.contains_key("bar"));
        }

        // "bar" recovers: the distributor must be rebuilt with both backends
        flag.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*router.get_healthy(), names(&["foo", "bar"]));

        for _ in 0..10 {
            assert!(router.execute(()).await.is_ok());
        }

        let h = executor.counts();
        assert_eq!(h["foo"], 15);
        assert_eq!(h["bar"], 5);

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_stops_routing_when_last_backend_fails() {
        let flag = Arc::new(AtomicBool::new(true));
        let executor = counting_executor();
        let router = router(
            &backends(&[("foo", 1)]),
            executor.clone(),
            Arc::new(FlipChecker {
                flaky: "foo".to_string(),
                healthy: flag.clone(),
            }),
            Strategy::WeightedRoundRobin,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(router.execute(()).await.is_ok());

        // The only backend goes down -> the distributor is dropped and requests
        // are refused again instead of being sent to a dead backend.
        flag.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(matches!(
            router.execute(()).await.unwrap_err(),
            Error::NoHealthyNodes
        ));
        assert_eq!(executor.1.lock().unwrap()["foo"], 1);

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_propagates_executor_error() {
        let router: BackendRouter<String, (), (), String> = BackendRouter::new(
            &backends(&[("foo", 1)]),
            Arc::new(FailingExecutor),
            Arc::new(SetChecker::new(&["foo"])),
            Strategy::WeightedRoundRobin,
            Duration::from_millis(1),
            health_check::Metrics::new(&Registry::new()),
            distributor::Metrics::new(&Registry::new()),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let err = router.execute(()).await.err().unwrap();
        assert!(matches!(err, Error::Inner(_)));
        assert_eq!(err.to_string(), "boom: foo");

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_stop() {
        let flag = Arc::new(AtomicBool::new(false));
        let executor = counting_executor();
        let router = router(
            &backends(&[("foo", 1), ("bar", 1)]),
            executor.clone(),
            Arc::new(FlipChecker {
                flaky: "bar".to_string(),
                healthy: flag.clone(),
            }),
            Strategy::WeightedRoundRobin,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*router.get_healthy(), names(&["foo"]));

        router.stop().await;
        // Stopping twice must neither panic nor hang
        router.stop().await;

        // Health checking has stopped, so the recovery is never observed
        flag.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*router.get_healthy(), names(&["foo"]));

        // The last known-good distributor is kept, so already-issued requests
        // can still be routed after the shutdown.
        assert!(router.execute(()).await.is_ok());
        let h = executor.counts();
        assert_eq!(h["foo"], 1);
        assert!(!h.contains_key("bar"));
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_with_no_backends_at_all() {
        let router = router(
            &[],
            counting_executor(),
            Arc::new(SetChecker::new(&["foo"])),
            Strategy::WeightedRoundRobin,
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Nothing is checked and nothing is routable, but the router still
        // starts, answers and shuts down cleanly instead of panicking.
        assert!(router.get_healthy().is_empty());
        let rx = router.subscribe();
        assert!(rx.borrow().is_empty());
        assert!(matches!(
            router.execute(()).await.unwrap_err(),
            Error::NoHealthyNodes
        ));

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_inflight_request_outlives_distributor_swap() {
        let flag = Arc::new(AtomicBool::new(true));
        let executor = Arc::new(GateExecutor::default());
        let router: Arc<BackendRouter<String>> = Arc::new(BackendRouter::new(
            &backends(&[("foo", 1)]),
            executor.clone(),
            Arc::new(FlipChecker {
                flaky: "foo".to_string(),
                healthy: flag.clone(),
            }),
            Strategy::WeightedRoundRobin,
            Duration::from_millis(1),
            health_check::Metrics::new(&Registry::new()),
            distributor::Metrics::new(&Registry::new()),
        ));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(*router.get_healthy(), names(&["foo"]));

        // Park a request inside the executor
        let r = router.clone();
        let handle = tokio::spawn(async move { r.execute(()).await });
        while executor.started.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }

        // The only backend goes down while that request is still in flight
        flag.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(matches!(
            router.execute(()).await.unwrap_err(),
            Error::NoHealthyNodes
        ));
        // `process()` returns early once nothing is healthy, so the advertised
        // healthy set is left at its last non-empty value even though routing
        // is already refused. Pinned as current behaviour, not as desirable.
        assert!(router.get_healthy().contains(&"foo".to_string()));
        assert_eq!(executor.started.load(Ordering::SeqCst), 1);

        // `execute` holds its own Arc to the distributor, so dropping the
        // distributor does not cancel or fail the request already running.
        executor.gate.notify_waiters();
        assert!(handle.await.unwrap().is_ok());

        router.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_router_stop_hangs_while_a_check_is_in_flight() {
        let router = router(
            &backends(&[("foo", 1)]),
            counting_executor(),
            Arc::new(GatedChecker::never()),
            Strategy::WeightedRoundRobin,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        // The very first check is still running, so nothing is routable yet
        assert!(router.get_healthy().is_empty());

        // `HealthChecker` awaits the check inside a `select!` arm, which means
        // the cancellation token cannot interrupt a check that is already
        // running: shutdown blocks until that check returns on its own. Pinned
        // as current behaviour - turn this into a plain `router.stop().await`
        // once in-flight checks become cancellable (or get a timeout).
        assert!(
            tokio::time::timeout(Duration::from_secs(30), router.stop())
                .await
                .is_err()
        );
    }
}
