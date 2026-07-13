use std::{
    fmt::Debug,
    sync::{Arc, RwLock},
};

use ic_agent::agent::route_provider::RouteProvider;

/// Generic trait that allows components to signal their health status
pub trait Healthy: Send + Sync + Debug + 'static {
    fn healthy(&self) -> bool;
}

impl Healthy for Arc<dyn RouteProvider> {
    fn healthy(&self) -> bool {
        // Returns true for route providers that support health checks if at least one node is healthy,
        // otherwise for providers that don't support health checks (e.g., RoundRobinRouteProvider) it just returns true.
        self.routes_stats()
            .healthy
            .is_none_or(|healthy_nodes| healthy_nodes > 0)
    }
}

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
