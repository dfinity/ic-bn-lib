use std::time::Duration;

use clap::Args;
use humantime::parse_duration;
use strum::{Display, IntoStaticStr};

use crate::parse_size;

/// Target health state for Health Checker
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TargetState {
    Unknown,
    Degraded,
    Healthy,
}

/// SEV-SNP CLI
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
