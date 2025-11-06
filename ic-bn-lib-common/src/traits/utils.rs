use std::{
    fmt::{Debug, Display},
    time::Duration,
};

use async_trait::async_trait;
use clap::Args;
use humantime::parse_duration;

use crate::{parse_size, types::utils::TargetState};

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

#[derive(Args)]
pub struct SevSnpCli {
    /// Enable SEV-SNP measurement reporting
    #[clap(env, long)]
    pub sev_snp_enable: bool,

    /// Cache TTL for SEV-SNP reports
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub sev_snp_cache_ttl: Duration,

    /// Max cache size for SEV-SNP reports
    #[clap(env, long, default_value = "10m", value_parser = parse_size)]
    pub sev_snp_cache_size: u64,
}
