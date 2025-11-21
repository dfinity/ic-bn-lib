use async_trait::async_trait;
use instant_acme::RevocationRequest;

use crate::types::acme::{AcmeCert, Error, Record};

/// ACME token manager trait to manage challenges
#[async_trait]
pub trait TokenManager: Sync + Send {
    async fn set(&self, id: &str, token: &str) -> Result<(), anyhow::Error>;
    async fn unset(&self, id: &str) -> Result<(), anyhow::Error>;
    async fn verify(&self, id: &str, token: &str) -> Result<(), anyhow::Error>;
}

/// ACME trait to manage DNS entries
#[async_trait]
pub trait DnsManager: Sync + Send {
    async fn create(
        &self,
        zone: &str,
        name: &str,
        record: Record,
        ttl: u32,
    ) -> Result<(), anyhow::Error>;
    async fn delete(&self, zone: &str, name: &str) -> Result<(), anyhow::Error>;
}

/// ACME client trait to issue and revoke certificates
#[async_trait]
pub trait AcmeCertificateClient: Sync + Send {
    /// Issue the certificate with provided names and an optional private key.
    async fn issue(
        &self,
        names: Vec<String>,
        private_key: Option<Vec<u8>>,
    ) -> Result<AcmeCert, Error>;

    /// Revoke the certificate according to the provided request
    async fn revoke<'a>(&self, request: &RevocationRequest<'a>) -> Result<(), Error>;
}
