use std::fmt::{Debug, Display};

use async_trait::async_trait;

use crate::types::utils::TargetState;

/// Trait that executes the requests.
/// Akin to Tower's Service, but generic over backend.
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
