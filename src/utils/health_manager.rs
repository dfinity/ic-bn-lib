use std::sync::{Arc, RwLock};

use ic_agent::agent::route_provider::RouteProvider;

use crate::types::Healthy;

/// Aggregates objects that implement Healthy trait.
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

impl Healthy for Arc<dyn RouteProvider> {
    fn healthy(&self) -> bool {
        // We're healthy if there's at least one healthy Boundary Node
        self.routes_stats().healthy.unwrap_or_default() > 0
    }
}
