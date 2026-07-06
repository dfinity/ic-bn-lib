use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use candid::Principal;
use fqdn::{FQDN, fqdn};
use ic_bn_lib_common::{
    traits::{dns::Resolves, http::Client},
    types::{dns::Options as DnsOptions, http::ClientOptions},
};
use tracing::{Span, debug, info, instrument};

use crate::{
    custom_domains::base::traits::validation::{ValidatesDomains, ValidationError},
    hickory_resolver::proto::rr::RecordType,
    http::{
        ReqwestClient,
        dns::{Resolver, SingleResolver, is_error_negative_lookup},
    },
    reqwest::{Method, Request, Url},
};

/// DNS validator for custom domain registration.
///
/// Validates that a domain is properly configured for custom domain registration
/// by checking DNS records, CNAME delegation, and canister ownership.
pub struct Validator {
    client: Arc<dyn Client>,
    resolver: Arc<dyn Resolves>,
    delegation_domain: FQDN,
    validation_domains: Vec<FQDN>,
}

impl std::fmt::Debug for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Validator")
    }
}

#[async_trait]
impl ValidatesDomains for Validator {
    #[instrument(level = "info", skip_all, fields(domain = %domain, canister_id))]
    async fn validate(&self, domain: &FQDN) -> Result<Principal, ValidationError> {
        info!("Beginning validation");
        self.validate_cname_delegation(domain).await?;
        self.validate_no_txt_challenge(domain).await?;
        let canister_id = self.validate_canister_mapping(domain).await?;
        Span::current().record("canister_id", canister_id.to_string());
        self.validate_canister_owner(canister_id, domain).await?;
        info!("Validation succeeded");
        Ok(canister_id)
    }

    #[instrument(level = "info", skip_all, fields(domain = %domain))]
    async fn validate_deletion(&self, domain: &FQDN) -> Result<(), ValidationError> {
        info!("Beginning deletion validation");
        self.validate_no_canister_id_record(domain).await?;
        info!("Deletion validation succeeded");
        Ok(())
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new(
            fqdn!("icp2.io"),
            vec![fqdn!("icp0.io"), fqdn!("ic0.app")],
            DnsOptions::default(),
        )
        .unwrap()
    }
}

impl Validator {
    /// Create a new Validator
    pub fn new(
        delegation_domain: FQDN,
        validation_domains: Vec<FQDN>,
        mut dns_opts: DnsOptions,
    ) -> Result<Self, ValidationError> {
        if delegation_domain.is_root() {
            return Err(ValidationError::UnexpectedError(anyhow!(
                "Delegation domain cannot be empty"
            )));
        }
        if validation_domains.is_empty() {
            return Err(ValidationError::UnexpectedError(anyhow!(
                "At least one validation domain is required"
            )));
        }

        dns_opts.opts.cache_size = 0;
        let resolver = Resolver::new(dns_opts).context("unable to create Resolver")?;

        let http_opts = ClientOptions::default();
        let http_resolver = SingleResolver::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let client = ReqwestClient::new(http_opts, Some(http_resolver))
            .context("unable to create HTTP client")?;

        Ok(Self {
            client: Arc::new(client),
            resolver: Arc::new(resolver),
            delegation_domain,
            validation_domains,
        })
    }

    /// Validates that the canister declares ownership of the domain.
    ///
    /// Checks the /.well-known/ic-domains asset of the canister to verify
    /// that the domain is listed as a known domain for that canister.
    /// Tries each validation domain in order until one succeeds.
    async fn validate_canister_owner(
        &self,
        canister_id: Principal,
        domain: &FQDN,
    ) -> Result<(), ValidationError> {
        let mut last_error = None;
        let domain_str = domain.to_string();

        for validation_domain in &self.validation_domains {
            // Verify domain name is stored inside the canister, confirming canister ownership
            let url = format!("https://{canister_id}.{validation_domain}/.well-known/ic-domains");
            debug!("checking canister owner, calling '{url}'");

            match self
                .fetch_and_verify_domain_ownership(&url, &domain_str, canister_id)
                .await
            {
                Ok(_) => return Ok(()),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or(ValidationError::MissingKnownDomains {
            id: canister_id.to_string(),
        }))
    }

    /// Helper to handle the request/parsing logic for a single domain
    async fn fetch_and_verify_domain_ownership(
        &self,
        url: &str,
        domain_to_check: &str,
        canister_id: Principal,
    ) -> Result<(), ValidationError> {
        let url_parsed = Url::parse(url).map_err(|e| ValidationError::UnexpectedError(e.into()))?;

        let response = self
            .client
            .execute(Request::new(Method::GET, url_parsed))
            .await
            .map_err(|e| ValidationError::KnownDomainsUnavailable {
                id: canister_id.to_string(),
                error: e.to_string(),
            })?;

        let text = response
            .text()
            .await
            .map_err(|e| ValidationError::UnexpectedError(e.into()))?;

        if text.contains(domain_to_check) {
            Ok(())
        } else {
            Err(ValidationError::MissingKnownDomains {
                id: canister_id.to_string(),
            })
        }
    }

    /// Validates that there are no existing canister ID TXT records for the domain.
    ///
    /// This check ensures the domain can be safely deleted or is not already registered.
    async fn validate_no_canister_id_record(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let hostname = format!("_canister-id.{domain}.");
        debug!("checking there's no canister ID record, resolving '{hostname}'");

        match self.resolver.resolve(RecordType::TXT, &hostname).await {
            Ok(_) => Err(ValidationError::ExistingDnsTxtCanisterId { src: hostname }),
            Err(err) => {
                if is_error_negative_lookup(&err) {
                    Ok(())
                } else {
                    Err(ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve TXT record for {hostname}: {err}"
                    )))
                }
            }
        }
    }

    /// Validates that there are no conflicting ACME challenge TXT records.
    ///
    /// Ensures that any existing ACME challenge records point to the delegation domain
    /// or that no conflicting records exist that would interfere with certificate issuance.
    async fn validate_no_txt_challenge(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let hostname = format!("_acme-challenge.{domain}.");
        debug!("checking there are no conflicting ACME challenge records, resolving '{hostname}'");

        match self.resolver.resolve(RecordType::TXT, &hostname).await {
            Ok(v) => {
                // If there are records - check that all of them belong to the delegation domain
                for rr in v {
                    let name = rr.name.to_lowercase().to_ascii();
                    debug!("got RR: '{name}'");

                    let name = FQDN::from_ascii_str(&name)
                        .context(format!("unable to parse '{name}' as FQDN"))?;

                    if !name.is_subdomain_of(&self.delegation_domain) {
                        return Err(ValidationError::ExistingDnsTxtChallenge { src: hostname });
                    }
                }

                Ok(())
            }

            Err(err) => {
                if is_error_negative_lookup(&err) {
                    Ok(())
                } else {
                    Err(ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve TXT record for {hostname}: {err}",
                    )))
                }
            }
        }
    }

    /// Validates that the domain has proper CNAME delegation set up.
    ///
    /// Checks that the ACME challenge subdomain has a CNAME record pointing
    /// to the corresponding delegation domain for certificate validation.
    async fn validate_cname_delegation(&self, domain: &FQDN) -> Result<(), ValidationError> {
        let cname_src = format!("_acme-challenge.{domain}.");
        let expected_cname_dst = format!("_acme-challenge.{domain}.{}.", self.delegation_domain);
        debug!("checking CNAME delegation '{cname_src}' -> '{expected_cname_dst}'");

        // Resolve CNAME record
        let records = self
            .resolver
            .resolve(RecordType::CNAME, &cname_src)
            .await
            .map_err(|err| {
                if is_error_negative_lookup(&err) {
                    ValidationError::MissingDnsCname {
                        src: cname_src.clone(),
                        dst: expected_cname_dst.clone(),
                    }
                } else {
                    ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve CNAME from {cname_src}: {err}"
                    ))
                }
            })?;

        // Validate expected CNAME record exists
        records
            .iter()
            // Filter out non-CNAME records (e.g. RRSIG from DNSSEC)
            .filter(|&x| x.data.record_type() == RecordType::CNAME)
            .any(|rr| {
                let cname_dst = rr.data.to_string();
                debug!("got CNAME dst: '{cname_dst}'");
                cname_dst == expected_cname_dst
            })
            .then_some(())
            .ok_or(ValidationError::MissingDnsCname {
                src: cname_src,
                dst: expected_cname_dst,
            })
    }

    /// Validates and extracts the canister ID from DNS TXT records.
    ///
    /// Looks for a TXT record at the canister ID prefix subdomain and validates
    /// that exactly one record exists containing a valid canister Principal.
    async fn validate_canister_mapping(&self, domain: &FQDN) -> Result<Principal, ValidationError> {
        let hostname = format!("_canister-id.{domain}");
        debug!("checking canister ID mapping, resolving '{hostname}'");

        // Resolve TXT record
        let records = self
            .resolver
            .resolve(RecordType::TXT, &hostname)
            .await
            .map_err(|err| {
                if is_error_negative_lookup(&err) {
                    ValidationError::MissingDnsTxtCanisterId {
                        src: hostname.clone(),
                    }
                } else {
                    ValidationError::UnexpectedError(anyhow!(
                        "Failed to resolve TXT record at {hostname}: {err}",
                    ))
                }
            })?;

        // Filter out non-TXT records (e.g. RRSIG from DNSSEC)
        let records = records
            .into_iter()
            .filter(|x| x.data.record_type() == RecordType::TXT)
            .collect::<Vec<_>>();

        // Make sure there's exactly one record
        if records.is_empty() {
            return Err(ValidationError::MissingDnsTxtCanisterId { src: hostname });
        }

        if records.len() > 1 {
            let records = records.into_iter().map(|x| x.data.to_string()).collect();
            return Err(ValidationError::MultipleDnsTxtCanisterId {
                src: hostname,
                records,
            });
        }

        let canister_id = records[0].data.to_string();
        debug!("got canister ID: '{canister_id}'");

        // Parse canister ID
        Principal::from_text(&canister_id).map_err(|_| ValidationError::InvalidDnsTxtCanisterId {
            src: hostname,
            id: canister_id,
        })
    }
}
