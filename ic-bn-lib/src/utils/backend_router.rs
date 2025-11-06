use std::{
    fmt::{Debug, Display},
    sync::Arc,
    time::Duration,
};

use arc_swap::{ArcSwap, ArcSwapOption};
use ic_bn_lib_common::{
    traits::utils::{ChecksTarget, ExecutesRequest},
    types::utils::TargetState,
};
use tokio::{select, sync::watch::Receiver};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::utils::{
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
            .map(|x| (x.0.0.clone(), *x.1))
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
            .store(Arc::new(healthy.into_iter().map(|x| x.0).collect()));
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
    use std::{collections::HashMap, sync::Mutex};

    use async_trait::async_trait;
    use prometheus::Registry;

    use crate::utils::distributor::test::TestExecutor;

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

    #[tokio::test]
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

    #[tokio::test]
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
}
