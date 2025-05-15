#[cfg(feature = "acme_dns")]
pub mod acme;
#[cfg(feature = "acme_alpn")]
pub mod alpn;
#[cfg(feature = "acme_dns")]
pub mod dns;

use std::path::PathBuf;

use anyhow::Error;
use async_trait::async_trait;
use derive_new::new;
use strum_macros::{Display, EnumString};

#[cfg(feature = "acme_dns")]
pub use instant_acme;

#[derive(Clone, Display, EnumString, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum Challenge {
    Alpn,
    Dns,
}

#[async_trait]
pub trait TokenManager: Sync + Send {
    async fn set(&self, id: &str, token: &str) -> Result<(), Error>;
    async fn unset(&self, id: &str) -> Result<(), Error>;
    async fn verify(&self, id: &str, token: &str) -> Result<(), Error>;
}

#[derive(new)]
pub struct AcmeOptions {
    domains: Vec<String>,
    cache_path: PathBuf,
    #[cfg(feature = "acme_dns")]
    renew_before: std::time::Duration,
    #[cfg(feature = "acme_dns")]
    wildcard: bool,
    staging: bool,
    contact: String,
}
