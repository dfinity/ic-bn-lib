use std::str::FromStr;

use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_custom_domains_canister_api::{
    DomainStatus as ApiDomainStatus, RegisteredDomain as ApiRegisteredDomain,
    RegistrationStatus as ApiRegistrationStatus,
};
use serde::{Deserialize, Serialize, Serializer};

/// Represents a fully registered domain with encrypted certificate and private key.
#[derive(Debug, Clone, new)]
pub struct RegisteredDomain {
    /// The fully qualified domain name
    pub domain: FQDN,
    /// The canister ID associated with this domain
    pub canister_id: Principal,
    /// Certificate data
    pub cert: Vec<u8>,
    /// Private key data
    pub priv_key: Vec<u8>,
}

/// Represents the status of a domain registration process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "custom-domains-openapi", derive(utoipa::ToSchema))]
pub enum RegistrationStatus {
    /// The registration is currently being processed
    Registering,
    /// The domain has been successfully registered and has a valid certificate
    Registered,
    /// The domain registration has expired
    Expired,
    /// The registration failed with an error message.
    /// Note: The message is not exposed directly in API responses.
    #[serde(serialize_with = "serialize_failed")]
    Failed(String),
}

fn serialize_failed<S>(_: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(
        "An unexpected error occurred during registration. Please try again later or contact support.",
    )
}

/// Represents the overall status of a domain including registration state.
#[derive(Debug, Clone)]
pub struct DomainStatus {
    /// The fully qualified domain name
    pub domain: FQDN,
    /// The canister ID if the domain is registered
    pub canister_id: Option<Principal>,
    /// The current registration status
    pub status: RegistrationStatus,
}

impl TryFrom<ApiDomainStatus> for DomainStatus {
    type Error = anyhow::Error;

    fn try_from(api_status: ApiDomainStatus) -> Result<Self, Self::Error> {
        let status = match api_status.status {
            ApiRegistrationStatus::Registering => RegistrationStatus::Registering,
            ApiRegistrationStatus::Registered => RegistrationStatus::Registered,
            ApiRegistrationStatus::Expired => RegistrationStatus::Expired,
            ApiRegistrationStatus::Failed(reason) => RegistrationStatus::Failed(reason),
        };

        Ok(Self {
            domain: FQDN::from_str(&api_status.domain)?,
            canister_id: api_status.canister_id,
            status,
        })
    }
}

impl From<ApiRegistrationStatus> for RegistrationStatus {
    fn from(status: ApiRegistrationStatus) -> Self {
        match status {
            ApiRegistrationStatus::Registering => Self::Registering,
            ApiRegistrationStatus::Registered => Self::Registered,
            ApiRegistrationStatus::Expired => Self::Expired,
            ApiRegistrationStatus::Failed(reason) => Self::Failed(reason),
        }
    }
}

impl TryFrom<ApiRegisteredDomain> for RegisteredDomain {
    type Error = anyhow::Error;

    fn try_from(value: ApiRegisteredDomain) -> Result<Self, Self::Error> {
        Ok(Self {
            domain: FQDN::from_str(&value.domain)?,
            canister_id: value.canister_id,
            cert: value.enc_cert,
            priv_key: value.enc_priv_key,
        })
    }
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;

    use crate::principal;

    use super::*;

    /// The exact text `serialize_failed` substitutes for the real error message.
    const REDACTED: &str = "An unexpected error occurred during registration. Please try again later or contact support.";

    fn api_status(domain: &str) -> ApiDomainStatus {
        ApiDomainStatus {
            domain: domain.to_string(),
            canister_id: Some(principal!("aaaaa-aa")),
            status: ApiRegistrationStatus::Registered,
        }
    }

    fn api_registered(domain: &str) -> ApiRegisteredDomain {
        ApiRegisteredDomain {
            domain: domain.to_string(),
            canister_id: principal!("aaaaa-aa"),
            enc_cert: b"CERT".to_vec(),
            enc_priv_key: b"KEY".to_vec(),
        }
    }

    // ---- RegistrationStatus <- ApiRegistrationStatus ----

    #[test]
    fn registration_status_from_api_maps_every_variant() {
        assert_eq!(
            RegistrationStatus::from(ApiRegistrationStatus::Registering),
            RegistrationStatus::Registering
        );
        assert_eq!(
            RegistrationStatus::from(ApiRegistrationStatus::Registered),
            RegistrationStatus::Registered
        );
        assert_eq!(
            RegistrationStatus::from(ApiRegistrationStatus::Expired),
            RegistrationStatus::Expired
        );
        // The internal conversion keeps the original reason; only serialization hides it.
        assert_eq!(
            RegistrationStatus::from(ApiRegistrationStatus::Failed("boom".to_string())),
            RegistrationStatus::Failed("boom".to_string())
        );
    }

    #[test]
    fn registration_status_failed_compares_by_reason() {
        assert_ne!(
            RegistrationStatus::Failed("a".to_string()),
            RegistrationStatus::Failed("b".to_string())
        );
    }

    // ---- RegistrationStatus serde ----

    #[test]
    fn unit_statuses_serialize_as_snake_case_strings() {
        assert_eq!(
            serde_json::to_string(&RegistrationStatus::Registering).unwrap(),
            r#""registering""#
        );
        assert_eq!(
            serde_json::to_string(&RegistrationStatus::Registered).unwrap(),
            r#""registered""#
        );
        assert_eq!(
            serde_json::to_string(&RegistrationStatus::Expired).unwrap(),
            r#""expired""#
        );
    }

    #[test]
    fn unit_statuses_roundtrip_through_json() {
        for status in [
            RegistrationStatus::Registering,
            RegistrationStatus::Registered,
            RegistrationStatus::Expired,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: RegistrationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn failed_status_never_leaks_the_reason_when_serialized() {
        let status = RegistrationStatus::Failed("db exploded on host 10.0.0.1".to_string());
        let json = serde_json::to_string(&status).unwrap();

        assert!(
            !json.contains("db exploded"),
            "internal error leaked: {json}"
        );
        assert!(!json.contains("10.0.0.1"), "internal error leaked: {json}");
        assert_eq!(json, format!(r#"{{"failed":"{REDACTED}"}}"#));
    }

    #[test]
    fn failed_status_redaction_is_independent_of_the_reason() {
        let a = serde_json::to_string(&RegistrationStatus::Failed(String::new())).unwrap();
        let b = serde_json::to_string(&RegistrationStatus::Failed("x".repeat(500))).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn failed_status_roundtrip_loses_the_original_reason() {
        let json = serde_json::to_string(&RegistrationStatus::Failed("boom".to_string())).unwrap();
        let back: RegistrationStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(back, RegistrationStatus::Failed(REDACTED.to_string()));
    }

    #[test]
    fn unknown_status_fails_to_deserialize() {
        assert!(serde_json::from_str::<RegistrationStatus>(r#""Registering""#).is_err());
        assert!(serde_json::from_str::<RegistrationStatus>(r#""bogus""#).is_err());
    }

    // ---- DomainStatus <- ApiDomainStatus ----

    #[test]
    fn domain_status_try_from_normalizes_case_and_trailing_dot() {
        for input in ["example.com", "Example.COM", "example.com.", "EXAMPLE.com."] {
            let status = DomainStatus::try_from(api_status(input)).unwrap();
            assert_eq!(status.domain, fqdn!("example.com"), "input: {input}");
            assert_eq!(status.domain.to_string(), "example.com", "input: {input}");
        }
    }

    #[test]
    fn domain_status_try_from_punycodes_unicode_labels() {
        let status = DomainStatus::try_from(api_status("bücher.example.com")).unwrap();
        assert_eq!(status.domain.to_string(), "xn--bcher-kva.example.com");
    }

    #[test]
    fn domain_status_try_from_accepts_underscore_labels() {
        // ACME challenge / canister-id records rely on `_`-prefixed labels.
        let status = DomainStatus::try_from(api_status("_acme-challenge.example.com")).unwrap();
        assert_eq!(status.domain, fqdn!("_acme-challenge.example.com"));
    }

    #[test]
    fn domain_status_try_from_rejects_malformed_domains() {
        for bad in [
            "example..com",
            ".example.com",
            "exa mple.com",
            "exa!mple.com",
            "example.com..",
            "*.example.com",
        ] {
            assert!(
                DomainStatus::try_from(api_status(bad)).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn domain_status_try_from_accepts_empty_domain_as_root() {
        // Documents the current (lenient) behaviour of `FQDN::from_str`: an empty
        // string is not an error, it parses as the DNS root.
        let status = DomainStatus::try_from(api_status("")).unwrap();
        assert!(status.domain.is_root());
        assert_eq!(status.domain.to_string(), ".");

        let status = DomainStatus::try_from(api_status(".")).unwrap();
        assert!(status.domain.is_root());
    }

    #[test]
    fn domain_status_try_from_does_not_enforce_rfc_length_limits() {
        // The `fqdn` crate is used without the `strict-rfc` features, so neither the
        // 63-byte label limit nor the 255-byte name limit is applied.
        let long_label = format!("{}.example.com", "a".repeat(64));
        let status = DomainStatus::try_from(api_status(&long_label)).unwrap();
        assert_eq!(status.domain.to_string(), long_label);

        let long_name = (0..6).map(|_| "b".repeat(60)).collect::<Vec<_>>().join(".");
        assert!(long_name.len() > 255);
        let status = DomainStatus::try_from(api_status(&long_name)).unwrap();
        assert_eq!(status.domain.to_string(), long_name);
    }

    #[test]
    fn domain_status_try_from_preserves_canister_id_and_status() {
        let api = ApiDomainStatus {
            domain: "example.com".to_string(),
            canister_id: None,
            status: ApiRegistrationStatus::Failed("boom".to_string()),
        };
        let status = DomainStatus::try_from(api).unwrap();

        assert!(status.canister_id.is_none());
        assert_eq!(
            status.status,
            RegistrationStatus::Failed("boom".to_string())
        );

        let api = ApiDomainStatus {
            domain: "example.com".to_string(),
            canister_id: Some(principal!("qoctq-giaaa-aaaaa-aaaea-cai")),
            status: ApiRegistrationStatus::Registering,
        };
        let status = DomainStatus::try_from(api).unwrap();

        assert_eq!(
            status.canister_id,
            Some(principal!("qoctq-giaaa-aaaaa-aaaea-cai"))
        );
        assert_eq!(status.status, RegistrationStatus::Registering);
    }

    // ---- RegisteredDomain <- ApiRegisteredDomain ----

    #[test]
    fn registered_domain_try_from_does_not_swap_cert_and_key() {
        let domain = RegisteredDomain::try_from(api_registered("EXAMPLE.com.")).unwrap();

        assert_eq!(domain.domain, fqdn!("example.com"));
        assert_eq!(domain.canister_id, principal!("aaaaa-aa"));
        assert_eq!(domain.cert, b"CERT");
        assert_eq!(domain.priv_key, b"KEY");
    }

    #[test]
    fn registered_domain_try_from_rejects_malformed_domain() {
        assert!(RegisteredDomain::try_from(api_registered("exa mple.com")).is_err());
        assert!(RegisteredDomain::try_from(api_registered("a..b.com")).is_err());
    }

    #[test]
    fn registered_domain_try_from_keeps_empty_payloads() {
        let mut api = api_registered("example.com");
        api.enc_cert = vec![];
        api.enc_priv_key = vec![];

        let domain = RegisteredDomain::try_from(api).unwrap();
        assert!(domain.cert.is_empty());
        assert!(domain.priv_key.is_empty());
    }

    #[test]
    fn registered_domain_new_assigns_every_field() {
        let domain = RegisteredDomain::new(
            fqdn!("example.com"),
            principal!("aaaaa-aa"),
            vec![1, 2],
            vec![3, 4],
        );

        assert_eq!(domain.domain, fqdn!("example.com"));
        assert_eq!(domain.canister_id, principal!("aaaaa-aa"));
        assert_eq!(domain.cert, vec![1, 2]);
        assert_eq!(domain.priv_key, vec![3, 4]);
    }
}
