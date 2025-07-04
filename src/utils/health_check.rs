use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use tokio::{select, sync::mpsc};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Degraded,
    Healthy,
}

#[async_trait]
pub trait ChecksTarget: Send + Sync + 'static {
    type Target;

    async fn check(&self, target: &Arc<Self::Target>) -> TargetState;
}

struct Actor<T> {
    idx: usize,
    target: Arc<T>,
    target_checker: Arc<dyn ChecksTarget<Target = T>>,
    state: TargetState,
    tx: mpsc::Sender<(usize, TargetState)>,
}

impl<T: Send + Sync + 'static> Actor<T> {
    async fn check(&mut self) {
        let state = self.target_checker.check(&self.target).await;

        if self.state != state {
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

struct Director<T> {
    targets: Vec<Arc<T>>,
    targets_healthy: Arc<ArcSwapOption<Vec<Arc<T>>>>,
    states: Vec<Option<TargetState>>,
    token: CancellationToken,
    tracker: TaskTracker,
    rx: mpsc::Receiver<(usize, TargetState)>,
}

impl<T: Send + Sync + 'static> Director<T> {
    fn new(
        targets: Vec<Arc<T>>,
        targets_healthy: Arc<ArcSwapOption<Vec<Arc<T>>>>,
        target_checker: Arc<dyn ChecksTarget<Target = T>>,
        interval: Duration,
    ) -> Self {
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let (tx, rx) = mpsc::channel(8192);

        for (idx, v) in targets.iter().enumerate() {
            let actor = Actor {
                idx,
                target: v.clone(),
                target_checker: target_checker.clone(),
                state: TargetState::Degraded,
                tx: tx.clone(),
            };

            let token = token.child_token();
            tracker.spawn(async move {
                actor.run(interval, token).await;
            });
        }

        Self {
            states: vec![None; targets.len()],
            targets,
            targets_healthy,
            token,
            tracker,
            rx,
        }
    }

    fn process(&mut self, i: usize, state: TargetState) {
        self.states[i] = Some(state);

        let healthy = self
            .targets
            .iter()
            .enumerate()
            .filter(|(i, _v)| self.states[*i] == Some(TargetState::Healthy))
            .map(|x| x.1.clone())
            .collect();

        self.targets_healthy.store(Some(Arc::new(healthy)));
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

pub struct Checker<T> {
    targets_healthy: Arc<ArcSwapOption<Vec<Arc<T>>>>,
    token: CancellationToken,
    tracker: TaskTracker,
}

impl<T: Send + Sync + 'static> Checker<T> {
    pub fn new(
        targets: Vec<Arc<T>>,
        target_checker: Arc<dyn ChecksTarget<Target = T>>,
        interval: Duration,
    ) -> Self {
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();

        let targets_healthy = Arc::new(ArcSwapOption::empty());
        let director = Director::new(targets, targets_healthy.clone(), target_checker, interval);

        let child_token = token.child_token();
        tracker.spawn(async move {
            director.run(child_token).await;
        });

        Self {
            targets_healthy,
            token,
            tracker,
        }
    }

    pub fn get_healthy_targets(&self) -> Option<Arc<Vec<Arc<T>>>> {
        self.targets_healthy.load_full()
    }

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
    impl ChecksTarget for TestChecker {
        type Target = u8;

        async fn check(&self, target: &Arc<Self::Target>) -> TargetState {
            if target.as_ref() % 2 == 0 {
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
        let checker = Checker::new(
            vec![0, 1, 2, 3].into_iter().map(Arc::new).collect(),
            target_checker,
            Duration::from_millis(1),
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        let healthy = checker.get_healthy_targets();
        assert_eq!(healthy, Some(Arc::new(vec![Arc::new(1), Arc::new(3)])));

        checker.stop().await;

        // All are down
        let target_checker = Arc::new(TestChecker);
        let checker = Checker::new(
            vec![0, 2].into_iter().map(Arc::new).collect(),
            target_checker,
            Duration::from_millis(1),
        );

        tokio::time::sleep(Duration::from_millis(100)).await;

        let healthy = checker.get_healthy_targets();
        assert_eq!(healthy, None);

        checker.stop().await;
    }
}
