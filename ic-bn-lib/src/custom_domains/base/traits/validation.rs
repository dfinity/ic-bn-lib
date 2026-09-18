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
    #[error("failed to retrieve known domains from the canister {id}: {error}")]
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

    /// Validates that a domain can be registered or updated.
    ///
    /// Skips certain checks compared to `validate()`:
    /// * Canister ownership verification (.well-known/ic-domains)
    /// * DNS TXT record verification for canister ID
    async fn validate_limited(&self, domain: &FQDN) -> Result<(), ValidationError>;

    /// Validates that a domain can be safely deleted.
    ///
    /// Ensures DNS records are properly cleaned up before certificate revocation.
    async fn validate_deletion(&self, domain: &FQDN) -> Result<(), ValidationError>;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        assert_eq!(
            ValidationError::ExistingDnsTxtCanisterId {
                src: "_canister-id.foo.bar".into()
            }
            .to_string(),
            "existing DNS TXT _canister-id record at _canister-id.foo.bar"
        );

        assert_eq!(
            ValidationError::ExistingDnsTxtChallenge {
                src: "_acme-challenge.foo.bar".into()
            }
            .to_string(),
            "existing DNS TXT challenge record at _acme-challenge.foo.bar"
        );

        assert_eq!(
            ValidationError::MissingDnsCname {
                src: "foo.bar".into(),
                dst: "ic0.app".into()
            }
            .to_string(),
            "missing DNS CNAME record from foo.bar to ic0.app"
        );

        assert_eq!(
            ValidationError::MissingDnsTxtCanisterId {
                src: "_canister-id.foo.bar".into()
            }
            .to_string(),
            "missing DNS TXT record from _canister-id.foo.bar to a canister id"
        );

        // The record list is rendered with Debug formatting
        assert_eq!(
            ValidationError::MultipleDnsTxtCanisterId {
                src: "_canister-id.foo.bar".into(),
                records: vec!["aaaaa-aa".into(), "2vxsx-fae".into()]
            }
            .to_string(),
            r#"multiple DNS TXT records for canister id at _canister-id.foo.bar: ["aaaaa-aa", "2vxsx-fae"]"#
        );

        // ... including when it's empty
        assert_eq!(
            ValidationError::MultipleDnsTxtCanisterId {
                src: "foo.bar".into(),
                records: vec![]
            }
            .to_string(),
            "multiple DNS TXT records for canister id at foo.bar: []"
        );

        assert_eq!(
            ValidationError::InvalidDnsTxtCanisterId {
                src: "_canister-id.foo.bar".into(),
                id: "not-a-principal".into()
            }
            .to_string(),
            "invalid DNS TXT record from _canister-id.foo.bar to not-a-principal"
        );

        assert_eq!(
            ValidationError::KnownDomainsUnavailable {
                id: "aaaaa-aa".into(),
                error: "timed out".into()
            }
            .to_string(),
            "failed to retrieve known domains from the canister aaaaa-aa: timed out"
        );

        assert_eq!(
            ValidationError::MissingKnownDomains {
                id: "aaaaa-aa".into()
            }
            .to_string(),
            "domain is missing from canister aaaaa-aa list of known domains"
        );
    }

    /// `UnexpectedError` is transparent: it must show the inner error as-is,
    /// with no prefix of its own, and be convertible from `anyhow::Error`.
    #[test]
    fn test_validation_error_unexpected() {
        let err: ValidationError = anyhow::anyhow!("something went wrong").into();
        assert!(matches!(err, ValidationError::UnexpectedError(_)));
        assert_eq!(err.to_string(), "something went wrong");

        // Context of the inner error is preserved
        let inner = anyhow::anyhow!("root cause").context("while doing stuff");
        assert_eq!(
            ValidationError::from(inner).to_string(),
            "while doing stuff"
        );
    }
}
