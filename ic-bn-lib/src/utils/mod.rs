use std::fmt::{Debug, Display};

use async_trait::async_trait;
use strum::{Display, IntoStaticStr};

pub mod backend_router;
pub mod distributor;
pub mod health_check;
pub mod health_manager;
#[cfg(all(target_os = "linux", feature = "sev-snp"))]
pub mod sev_snp;
pub mod wrr;

/// Target health state for Health Checker
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TargetState {
    Unknown,
    Degraded,
    Healthy,
}

/// Trait that executes the requests.
/// Akin to Tower's Service, but generic over the backend.
#[async_trait]
pub trait ExecutesRequest<T>: Send + Sync + Debug {
    type Request;
    type Response;
    type Error;

    async fn execute(&self, backend: &T, req: Self::Request)
    -> Result<Self::Response, Self::Error>;
}

/// Checks if given target is healthy
#[async_trait]
pub trait ChecksTarget<T: Clone + Display + Debug>: Send + Sync + 'static {
    async fn check(&self, target: &T) -> TargetState;
}
