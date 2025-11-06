use std::{fmt::Display, sync::Arc, time::Duration};

use async_trait::async_trait;
use derive_new::new;
use ic_bn_lib_common::traits::Run;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, warn};

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

// Starts & tracks Tasks that implement Run
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
