use std::{fmt::Display, sync::Arc, time::Duration};

use async_trait::async_trait;
use derive_new::new;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, warn};

// A runnable task that can be cancelled by a token
#[async_trait]
pub trait Run: Send + Sync {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error>;
}

#[derive(Clone)]
struct Task(String, Arc<dyn Run>);

impl Display for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Runs given task periodically
struct IntervalRunner(Duration, Task);

#[async_trait]
impl Run for IntervalRunner {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        warn!(
            "Task '{}': running with interval {}s",
            self.1,
            self.0.as_secs()
        );

        let mut interval = tokio::time::interval(self.0);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                () = token.cancelled() => {
                    warn!("Task '{}': stopped", self.1);
                    return Ok(());
                },

                _ = interval.tick() => {
                    if let Err(e) = self.1.1.run(token.child_token()).await {
                        warn!("Task '{}': {e:#}", self.1);
                    }
                }
            }
        }
    }
}

/// Starts & tracks Tasks that implement Run
#[derive(new)]
pub struct TaskManager {
    #[new(default)]
    tracker: TaskTracker,
    #[new(default)]
    tasks: Vec<Task>,
    #[new(default)]
    token: CancellationToken,
}

impl TaskManager {
    /// Add a task to run only once.
    /// It needs to implement its own internal repeat logic if need be.
    pub fn add(&mut self, name: &str, task: Arc<dyn Run>) {
        self.tasks.push(Task(name.into(), task));
    }

    /// Add a task to run with a given interval.
    /// Errors are printed with a WARN level and then ignored.
    pub fn add_interval(&mut self, name: &str, task: Arc<dyn Run>, interval: Duration) {
        let runner = IntervalRunner(interval, Task(name.into(), task));
        self.tasks.push(Task(name.into(), Arc::new(runner)));
    }

    /// Start the tasks
    pub fn start(&self) {
        warn!("TaskManager: starting {} tasks", self.tasks.len());

        for task in self.tasks.clone() {
            let token = self.token.child_token();
            self.tracker.spawn(async move {
                if let Err(e) = task.1.run(token).await {
                    error!("TaskManager: task '{}' exited with an error: {e:#}", task.0);
                }
            });
        }
    }

    /// Signal the tasks to stop and wait until they do.
    /// If one or more tasks aren't acting on the token cancellation signal then this will hang forever.
    pub async fn stop(&self) {
        warn!("TaskManager: stopping {} tasks", self.tasks.len());
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }

    /// Return a cancellation token that can be used to signal external tasks when `TaskManager` is stopping.
    pub fn token(&self) -> CancellationToken {
        self.token.child_token()
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingTask(Arc<AtomicUsize>);

    #[async_trait]
    impl Run for CountingTask {
        async fn run(&self, _token: CancellationToken) -> Result<(), anyhow::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct WaitsForCancellation(Arc<AtomicUsize>);

    #[async_trait]
    impl Run for WaitsForCancellation {
        async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
            token.cancelled().await;
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_add_runs_task_once() {
        let count = Arc::new(AtomicUsize::new(0));

        let mut mgr = TaskManager::new();
        mgr.add("counter", Arc::new(CountingTask(count.clone())));
        mgr.start();

        // Give the spawned task a chance to run
        tokio::time::sleep(Duration::from_millis(50)).await;
        mgr.stop().await;

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_add_interval_runs_task_repeatedly() {
        let count = Arc::new(AtomicUsize::new(0));

        let mut mgr = TaskManager::new();
        mgr.add_interval(
            "interval",
            Arc::new(CountingTask(count.clone())),
            Duration::from_millis(20),
        );
        mgr.start();

        tokio::time::sleep(Duration::from_millis(110)).await;
        mgr.stop().await;

        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "expected at least 2 ticks, got {}",
            count.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn test_stop_cancels_running_tasks() {
        let count = Arc::new(AtomicUsize::new(0));

        let mut mgr = TaskManager::new();
        mgr.add("waiter", Arc::new(WaitsForCancellation(count.clone())));
        mgr.start();

        // Task should still be waiting on cancellation
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);

        // stop() cancels the token and awaits task completion
        mgr.stop().await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_token_is_child_of_manager_token() {
        let mgr = TaskManager::new();
        let child = mgr.token();
        assert!(!child.is_cancelled());

        mgr.stop().await;
        assert!(child.is_cancelled());
    }
}
