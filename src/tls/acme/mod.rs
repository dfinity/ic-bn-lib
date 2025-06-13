#[cfg(feature = "acme_alpn")]
pub mod alpn;
#[cfg(feature = "acme_client")]
pub mod client;
#[cfg(any(test, feature = "acme_dns"))]
pub mod dns;

use anyhow::Error;
use async_trait::async_trait;
use strum_macros::{Display, EnumString};

#[cfg(feature = "acme_client")]
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
