use async_trait::async_trait;
use candid::Principal;
use fqdn::FQDN;
use thiserror::Error;

/// Errors that can occur during domain validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// A DNS TXT record for canister ID already exists at the specified location
    #[error("existing DNS TXT _canister-id record at {src}")]
    ExistingDnsTxtCanisterId { src: String },
    /// A DNS TXT record for ACME challenge already exists at the specified location
    #[error("existing DNS TXT challenge record at {src}")]
    ExistingDnsTxtChallenge { src: String },
    /// Required DNS CNAME record is missing
    #[error("missing DNS CNAME record from {src} to {dst}")]
    MissingDnsCname { src: String, dst: String },
    /// Required DNS TXT record with canister ID is missing
    #[error("missing DNS TXT record from {src} to a canister id")]
    MissingDnsTxtCanisterId { src: String },
    /// Multiple DNS TXT records found when only one is expected
    #[error("multiple DNS TXT records for canister id at {src}: {records:?}")]
    MultipleDnsTxtCanisterId { src: String, records: Vec<String> },
    /// DNS TXT record contains invalid canister ID
    #[error("invalid DNS TXT record from {src} to {id}")]
    InvalidDnsTxtCanisterId { src: String, id: String },
    /// Cannot retrieve known domains from the canister
    #[error("failed to retrieve known domains from canister {id}: {error}")]
    KnownDomainsUnavailable { id: String, error: String },
    /// Domain is not listed in the canister's known domains
    #[error("domain is missing from canister {id} list of known domains")]
    MissingKnownDomains { id: String },
    /// Unexpected error during validation
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

/// Trait for validating domain configurations for certificate issuance and management.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait ValidatesDomains: Send + Sync {
    /// Validates that a domain can be registered or updated.
    ///
    /// Performs comprehensive checks including DNS configuration,
    /// canister ownership verification, and ACME challenge setup.
    async fn validate(&self, domain: &FQDN) -> Result<Principal, ValidationError>;

    /// Validates that a domain can be safely deleted.
    ///
    /// Ensures DNS records are properly cleaned up before certificate revocation.
    async fn validate_deletion(&self, domain: &FQDN) -> Result<(), ValidationError>;
}
