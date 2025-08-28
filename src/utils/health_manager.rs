use std::sync::Arc;

use crate::types::Healthy;

/// Aggregates objects that implement Healhy trait.
/// It is healthy when all inner services are healthy.
#[derive(Debug, Default)]
pub struct HealthManager {
    services: Vec<Arc<dyn Healthy>>,
}

impl HealthManager {
    pub fn add(&mut self, svc: Arc<dyn Healthy>) {
        self.services.push(svc);
    }
}

impl Healthy for HealthManager {
    fn healthy(&self) -> bool {
        self.services.iter().all(|x| x.healthy())
    }
}
