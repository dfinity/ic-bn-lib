use anyhow::Error;
use async_trait::async_trait;

use crate::types::CustomDomain;

/// Provides a list of custom domains
#[async_trait]
pub trait ProvidesCustomDomains: Sync + Send + std::fmt::Debug {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error>;
}
