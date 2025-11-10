pub mod acme;
pub mod custom_domains;
pub mod dns;
pub mod http;
pub mod pubsub;
pub mod shed;
pub mod tls;
pub mod utils;

use std::{fmt::Debug, sync::Arc};

use anyhow::Error;
use async_trait::async_trait;
use ic_agent::agent::route_provider::RouteProvider;
use tokio_util::sync::CancellationToken;

// A task that can be cancelled by a token
#[async_trait]
pub trait Run: Send + Sync {
    async fn run(&self, token: CancellationToken) -> Result<(), Error>;
}

/// Generic trait that allows components to signal their health status
pub trait Healthy: Send + Sync + Debug + 'static {
    fn healthy(&self) -> bool;
}

impl Healthy for Arc<dyn RouteProvider> {
    fn healthy(&self) -> bool {
        // We're healthy if there's at least one healthy Boundary Node
        self.routes_stats().healthy.unwrap_or_default() > 0
    }
}
