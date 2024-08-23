use std::sync::Arc;

use anyhow::Error;
use async_trait::async_trait;
use derive_new::new;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{error, warn};

// Long running task that can be cancelled by a token
#[async_trait]
pub trait Run: Send + Sync {
    async fn run(&self, token: CancellationToken) -> Result<(), Error>;
}

#[derive(Clone)]
struct Task(String, Arc<dyn Run>);

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
    pub fn add(&mut self, name: &str, task: Arc<dyn Run>) {
        self.tasks.push(Task(name.into(), task));
    }

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

    pub async fn stop(&self) {
        warn!("TaskManager: stopping {} tasks", self.tasks.len());
        self.token.cancel();
        self.tracker.close();
        self.tracker.wait().await;
    }

    pub fn token(&self) -> CancellationToken {
        self.token.child_token()
    }
}
