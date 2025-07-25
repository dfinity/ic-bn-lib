use std::{
    fmt::{Debug, Display},
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use strum::{Display, IntoStaticStr};
use tokio::{
    select,
    sync::{mpsc, watch},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TargetState {
    Unknown,
    Degraded,
    Healthy,
}

#[async_trait]
pub trait ChecksTarget<T: Clone + Display + Debug>: Send + Sync + 'static {
    async fn check(&self, target: &T) -> TargetState;
}

#[derive(Clone, Debug)]
pub struct Metrics {
    state: IntGaugeVec,
    checks: IntCounterVec,
    duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            state: register_int_gauge_vec_with_registry!(
                format!("health_checker_state"),
                format!("Stores the current health state of targets"),
                &["target"],
                registry
            )
            .unwrap(),

            checks: register_int_counter_vec_with_registry!(
                format!("health_checker_checks"),
                format!("Counts the number of health check results"),
                &["target", "result"],
                registry
            )
            .unwrap(),

            duration: register_histogram_vec_with_registry!(
                format!("health_checker_duration"),
                format!("Records the duration of health checks in seconds"),
                &["target"],
                [0.01, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2].to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

struct Actor<T> {
    idx: usize,
    target: T,
    target_name: String,
    checker: Arc<dyn ChecksTarget<T>>,
    state: TargetState,
    tx: mpsc::Sender<(usize, TargetState)>,
    metrics: Metrics,
}

impl<T> Actor<T>
where
    T: Clone + Display + Debug + Send + Sync + 'static,
{
    async fn check(&mut self) {
        let start = Instant::now();
        let state = self.checker.check(&self.target).await;
        self.metrics
            .duration
            .with_label_values(&[&self.target_name])
            .observe(start.elapsed().as_secs_f64());

        let state_num: i64 = match state {
            TargetState::Unknown => -1,
            TargetState::Degraded => 0,
            TargetState::Healthy => 1,
        };

        self.metrics
            .state
            .with_label_values(&[&self.target_name])
            .set(state_num);

        let state_str: &'static str = state.into();
        self.metrics
            .checks
            .with_label_values(&[self.target_name.as_str(), state_str])
            .inc();

        if self.state != state {
            warn!(
                "Target {} state changed: {} -> {}",
                self.target, self.state, state
            );

            self.state = state;
            let _ = self.tx.send((self.idx, state)).await;
        }
    }

    async fn run(mut self, interval: Duration, token: CancellationToken) {
        let mut interval = tokio::time::interval(interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            select! {
                biased;

                // Check if we need to shut down
                _ = token.cancelled() => {
                    return;
                }

                // Run the check with given interval
                _ = interval.tick() => self.check().await,
            }
        }
    }
}

/// Director takes care of managing Actors and receives health messages from them
struct Director<T> {
    targets: Vec<T>,
    targets_healthy: Arc<ArcSwapOption<Vec<T>>>,
    states: Vec<TargetState>,
    token: CancellationToken,
    tracker: TaskTracker,
    rx: mpsc::Receiver<(usize, TargetState)>,
    notify_tx: watch::Sender<Arc<Vec<(T, TargetState)>>>,
}

impl<T> Director<T>
where
    T: Clone + Display + Debug + Send + Sync + 'static,
{
    fn new(
        targets: Vec<T>,
        targets_healthy: Arc<ArcSwapOption<Vec<T>>>,
        checker: Arc<dyn ChecksTarget<T>>,
        interval: Duration,
        notify_tx: watch::Sender<Arc<Vec<(T, TargetState)>>>,
        metrics: Metrics,
    ) -> Self {
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let (tx, rx) = mpsc::channel(8192);

        for (idx, v) in targets.iter().enumerate() {
            let actor = Actor {
                idx,
                target: v.clone(),
                target_name: v.to_string(),
                checker: checker.clone(),
                state: TargetState::Unknown,
                tx: tx.clone(),
                metrics: metrics.clone(),
            };

            let token = token.child_token();
            tracker.spawn(async move {
                actor.run(interval, token).await;
            });
        }

        Self {
            states: vec![TargetState::Unknown; targets.len()],
            targets,
            targets_healthy,
            token,
            tracker,
            rx,
            notify_tx,
        }
    }

    fn process(&mut self, i: usize, state: TargetState) {
        self.states[i] = state;

        let with_state = self
            .targets
            .clone()
            .into_iter()
            .zip(self.states.clone())
            .collect::<Vec<_>>();

        let healthy = Arc::new(
            with_state
                .clone()
                .into_iter()
                .filter(|x| x.1 == TargetState::Healthy)
                .map(|x| x.0)
                .collect::<Vec<_>>(),
        );

        // Set the list of healthy targets to be available to HealthChecker
        self.targets_healthy.store(Some(healthy));

        // Send the list of targets & their states to listeners
        self.notify_tx.send_replace(Arc::new(with_state));
    }

    async fn run(mut self, token: CancellationToken) {
        loop {
            select! {
                biased;

                // Check if we need to shut down
                _ = token.cancelled() => {
                    self.token.cancel();
                    self.tracker.close();
                    self.tracker.wait().await;
                    return;
                }

                // Process the state changes
                Some((idx, state)) = self.rx.recv() => self.process(idx, state)
            }
        }
    }
}

/// Generic health-checker that runs health checks against its targets
/// in parallel using actors.
pub struct HealthChecker<T> {
    targets_healthy: Arc<ArcSwapOption<Vec<T>>>,
    token: CancellationToken,
    tracker: TaskTracker,
    notify_rx: watch::Receiver<Arc<Vec<(T, TargetState)>>>,
}

impl<T> HealthChecker<T>
where
    T: Clone + Display + Debug + Send + Sync + 'static,
{
    /// Create a new Checker
    pub fn new(
        targets: &[T],
        target_checker: Arc<dyn ChecksTarget<T>>,
        interval: Duration,
        metrics: Metrics,
    ) -> Self {
        let targets = targets.to_vec();

        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let (notify_tx, notify_rx) = watch::channel(Arc::new(vec![]));

        let targets_healthy = Arc::new(ArcSwapOption::empty());
        let director = Director::new(
            targets,
            targets_healthy.clone(),
            target_checker,
            interval,
            notify_tx,
            metrics,
        );

        let child_token = token.child_token();
        tracker.spawn(async move {
            director.run(child_token).await;
        });

        Self {
            targets_healthy,
            token,
            tracker,
            notify_rx,
        }
    }

    /// Returns a list of healthy targets
    pub fn get_healthy_targets(&self) -> Option<Arc<Vec<T>>> {
        self.targets_healthy.load_full()
    }

    /// Subscribes to notifications when the set of healthy nodes changes.
    /// Returns a channel which emits a new set of healthy nodes.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Vec<(T, TargetState)>>> {
        self.notify_rx.clone()
    }

    /// Shuts down this instance of Checker
    pub async fn stop(&self) {
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestChecker;

    #[async_trait]
    impl ChecksTarget<u8> for TestChecker {
        async fn check(&self, target: &u8) -> TargetState {
            if target % 2 == 0 {
                TargetState::Degraded
            } else {
                TargetState::Healthy
            }
        }
    }

    #[tokio::test]
    async fn test_health_checker() {
        // Some are healthy
        let target_checker = Arc::new(TestChecker);
        let metrics = Metrics::new(&Registry::new());

        let checker = HealthChecker::new(
            &[0, 1, 2, 3],
            target_checker,
            Duration::from_millis(1),
            metrics.clone(),
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        let healthy = checker.get_healthy_targets();
        let expect = Arc::new(vec![1, 3]);
        assert_eq!(healthy, Some(expect.clone()));
        let mut ch = checker.subscribe();
        ch.changed().await.unwrap();
        assert_eq!(
            ch.borrow_and_update().clone(),
            Arc::new(vec![
                (0, TargetState::Degraded),
                (1, TargetState::Healthy),
                (2, TargetState::Degraded),
                (3, TargetState::Healthy)
            ])
        );

        checker.stop().await;

        // All are down
        let target_checker = Arc::new(TestChecker);
        let checker =
            HealthChecker::new(&[0, 2], target_checker, Duration::from_millis(1), metrics);

        tokio::time::sleep(Duration::from_millis(100)).await;

        let healthy = checker.get_healthy_targets();
        assert_eq!(healthy, Some(Arc::new(vec![])));
        let mut ch = checker.subscribe();
        ch.changed().await.unwrap();
        assert_eq!(
            ch.borrow_and_update().clone(),
            Arc::new(vec![(0, TargetState::Degraded), (2, TargetState::Degraded)])
        );

        checker.stop().await;
    }
}
