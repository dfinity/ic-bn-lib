use std::sync::{Arc, Mutex};

use crate::types::Healthy;

/// Aggregates objects that implement Healhy trait.
/// It is healthy when all inner services are healthy.
#[derive(Debug, Default)]
pub struct HealthManager {
    services: Mutex<Vec<Arc<dyn Healthy>>>,
}

impl HealthManager {
    pub fn add(&self, svc: Arc<dyn Healthy>) {
        self.services.lock().unwrap().push(svc);
    }
}

impl Healthy for HealthManager {
    fn healthy(&self) -> bool {
        self.services.lock().unwrap().iter().all(|x| x.healthy())
    }
}
