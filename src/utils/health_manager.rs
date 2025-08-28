use std::sync::{Arc, RwLock};

use crate::types::Healthy;

/// Aggregates objects that implement Healhy trait.
/// It is healthy when all inner services are healthy.
#[derive(Debug, Default)]
pub struct HealthManager {
    services: RwLock<Vec<Arc<dyn Healthy>>>,
}

impl HealthManager {
    pub fn add(&self, svc: Arc<dyn Healthy>) {
        self.services.write().unwrap().push(svc);
    }
}

impl Healthy for HealthManager {
    fn healthy(&self) -> bool {
        self.services.read().unwrap().iter().all(|x| x.healthy())
    }
}
