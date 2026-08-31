use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use candid::Principal;
use fqdn::{FQDN, fqdn};
use hickory_resolver::proto::rr::RecordType;
use reqwest::{Method, Request, Url};
use tracing::{Span, debug, info, instrument};

use crate::{
    custom_domains::base::traits::validation::{ValidatesDomains, ValidationError},
    dns::{
        Options as DnsOptions, is_error_negative_lookup,
        resolvers::Resolves,
        resolvers::{Resolver, SingleResolver},
    },
    http::{ReqwestClient, client::Client, client::ClientOptions},
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
    async fn validate_limited(&self, domain: &FQDN) -> Result<(), ValidationError> {
        info!("Beginning validation");
        self.validate_cname_delegation(domain).await?;
        self.validate_no_txt_challenge(domain).await?;
        info!("Validation succeeded");
        Ok(())
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
                Err(e) => {
                    info!("got validation error: {e:#}");
                    last_error = Some(e)
                }
            }
        }

        Err(
            last_error.unwrap_or_else(|| ValidationError::MissingKnownDomains {
                id: canister_id.to_string(),
            }),
        )
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

        // Check if the file contains our domain on one of the lines
        if text
            .split('\n')
            .any(|x| x.trim().eq_ignore_ascii_case(domain_to_check))
        {
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
    ///
    /// This covers cases when the domain has both TXT and CNAME records, for example:
    ///
    /// ;; ANSWER SECTION:
    /// _acme-challenge.id.ai.         300 IN CNAME acme-challenge.id.ai.icp2.io.
    /// _acme-challenge.id.ai.icp2.io. 300 IN TXT   "foobar2"
    ///
    /// So we check that `_acme-challenge.id.ai.icp2.io` is a subdomain of `icp2.io`
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

#[cfg(test)]
mod test {
    use ::http::Response as HttpResponse;

    use crate::{
        hickory_resolver::{
            net::{NetError, NoRecords},
            proto::{
                op::{Query, ResponseCode},
                rr::{
                    Name, RData, Record,
                    rdata::{A, CNAME, TXT},
                },
            },
        },
        principal,
    };

    use super::*;

    fn mk_validator(client: Arc<dyn Client>, resolver: Arc<dyn Resolves>) -> Validator {
        Validator {
            client,
            resolver,
            delegation_domain: fqdn!("icp2.io"),
            validation_domains: vec![fqdn!("icp0.io")],
        }
    }

    /// HTTP client that must not be called (used for DNS-only tests).
    #[derive(Debug)]
    struct UnusedClient;

    #[async_trait]
    impl Client for UnusedClient {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            unreachable!("HTTP client should not be called in this test")
        }
    }

    /// DNS resolver that must not be called (used for HTTP-only tests).
    struct UnusedResolver;

    #[async_trait]
    impl Resolves for UnusedResolver {
        async fn resolve(&self, _: RecordType, _: &str) -> Result<Vec<Record>, NetError> {
            unreachable!("DNS resolver should not be called in this test")
        }

        fn flush_cache(&self) {}
    }

    /// DNS resolver backed by a closure, so each test can script its own responses.
    ///
    /// A boxed `dyn Fn` is used (rather than a bare generic `F`) because a plain generic
    /// closure parameter does not get inferred as higher-ranked over the `&str` lifetime,
    /// which then fails to unify with the per-call lifetime in `Resolves::resolve`.
    #[allow(clippy::type_complexity)]
    struct MockResolver(
        Box<dyn Fn(RecordType, &str) -> Result<Vec<Record>, NetError> + Send + Sync>,
    );

    impl MockResolver {
        fn new(
            f: impl Fn(RecordType, &str) -> Result<Vec<Record>, NetError> + Send + Sync + 'static,
        ) -> Self {
            Self(Box::new(f))
        }
    }

    #[async_trait]
    impl Resolves for MockResolver {
        async fn resolve(
            &self,
            record_type: RecordType,
            name: &str,
        ) -> Result<Vec<Record>, NetError> {
            (self.0)(record_type, name)
        }

        fn flush_cache(&self) {}
    }

    /// HTTP client backed by a closure, so each test can script its own responses.
    /// See [`MockResolver`] for why this boxes the closure instead of using a bare generic.
    #[allow(clippy::type_complexity)]
    struct MockClient(
        Box<dyn Fn(&reqwest::Request) -> Result<reqwest::Response, reqwest::Error> + Send + Sync>,
    );

    impl MockClient {
        fn new(
            f: impl Fn(&reqwest::Request) -> Result<reqwest::Response, reqwest::Error>
            + Send
            + Sync
            + 'static,
        ) -> Self {
            Self(Box::new(f))
        }
    }

    impl std::fmt::Debug for MockClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MockClient")
        }
    }

    #[async_trait]
    impl Client for MockClient {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            (self.0)(&req)
        }
    }

    fn cname_record(name: &str, target: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
        )
    }

    fn txt_record(name: &str, value: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            300,
            RData::TXT(TXT::new(vec![value.to_string()])),
        )
    }

    fn a_record(name: &str) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(127, 0, 0, 1))),
        )
    }

    /// Builds a resolver error that `is_error_negative_lookup()` recognizes as "no such record".
    fn negative_lookup_error(name: &str, record_type: RecordType) -> NetError {
        NoRecords::new(
            Query::query(Name::from_ascii(name).unwrap(), record_type),
            ResponseCode::NXDomain,
        )
        .into()
    }

    fn text_response(body: &str) -> reqwest::Response {
        HttpResponse::new(body.to_string()).into()
    }

    /// Builds a real `reqwest::Error` (via a non-2xx response) for HTTP-failure tests.
    fn error_response(status: u16) -> reqwest::Error {
        let resp: reqwest::Response = HttpResponse::builder()
            .status(status)
            .body(String::new())
            .unwrap()
            .into();
        resp.error_for_status().unwrap_err()
    }

    // ---- validate_cname_delegation ----

    #[tokio::test]
    async fn cname_delegation_succeeds_when_cname_matches() {
        let resolver = MockResolver::new(|record_type, name| {
            assert_eq!(record_type, RecordType::CNAME);
            assert_eq!(name, "_acme-challenge.example.com.");
            Ok(vec![cname_record(
                "_acme-challenge.example.com.",
                "_acme-challenge.example.com.icp2.io.",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        validator
            .validate_cname_delegation(&fqdn!("example.com"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cname_delegation_ignores_non_cname_records() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![
                a_record("_acme-challenge.example.com."),
                cname_record(
                    "_acme-challenge.example.com.",
                    "_acme-challenge.example.com.icp2.io.",
                ),
            ])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        validator
            .validate_cname_delegation(&fqdn!("example.com"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cname_delegation_fails_on_missing_record() {
        let resolver =
            MockResolver::new(|record_type, name| Err(negative_lookup_error(name, record_type)));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_cname_delegation(&fqdn!("example.com"))
            .await
            .unwrap_err();

        match err {
            ValidationError::MissingDnsCname { src, dst } => {
                assert_eq!(src, "_acme-challenge.example.com.");
                assert_eq!(dst, "_acme-challenge.example.com.icp2.io.");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn cname_delegation_fails_on_wrong_target() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![cname_record(
                "_acme-challenge.example.com.",
                "somewhere-else.com.",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_cname_delegation(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationError::MissingDnsCname { .. }));
    }

    #[tokio::test]
    async fn cname_delegation_propagates_unexpected_resolver_error() {
        let resolver = MockResolver::new(|_, _| Err(NetError::Timeout));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_cname_delegation(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationError::UnexpectedError(_)));
    }

    // ---- validate_no_txt_challenge ----

    #[tokio::test]
    async fn no_txt_challenge_succeeds_on_missing_record() {
        let resolver =
            MockResolver::new(|record_type, name| Err(negative_lookup_error(name, record_type)));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        validator
            .validate_no_txt_challenge(&fqdn!("id.ai"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn no_txt_challenge_succeeds_when_record_is_subdomain_of_delegation() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![txt_record(
                "_acme-challenge.id.ai.icp2.io.",
                "foobar2",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        validator
            .validate_no_txt_challenge(&fqdn!("id.ai"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn no_txt_challenge_fails_when_record_is_not_subdomain_of_delegation() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![txt_record(
                "_acme-challenge.id.ai.evil.io.",
                "foobar2",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_no_txt_challenge(&fqdn!("id.ai"))
            .await
            .unwrap_err();

        match err {
            ValidationError::ExistingDnsTxtChallenge { src } => {
                assert_eq!(src, "_acme-challenge.id.ai.");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_txt_challenge_propagates_unexpected_resolver_error() {
        let resolver = MockResolver::new(|_, _| Err(NetError::Timeout));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_no_txt_challenge(&fqdn!("id.ai"))
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationError::UnexpectedError(_)));
    }

    // ---- validate_canister_mapping ----

    #[tokio::test]
    async fn canister_mapping_succeeds_with_single_valid_record() {
        let resolver = MockResolver::new(|record_type, name| {
            assert_eq!(record_type, RecordType::TXT);
            assert_eq!(name, "_canister-id.example.com");
            Ok(vec![txt_record(
                "_canister-id.example.com.",
                "qoctq-giaaa-aaaaa-aaaea-cai",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let canister_id = validator
            .validate_canister_mapping(&fqdn!("example.com"))
            .await
            .unwrap();

        assert_eq!(canister_id, principal!("qoctq-giaaa-aaaaa-aaaea-cai"));
    }

    #[tokio::test]
    async fn canister_mapping_ignores_non_txt_records() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![
                a_record("_canister-id.example.com."),
                txt_record("_canister-id.example.com.", "qoctq-giaaa-aaaaa-aaaea-cai"),
            ])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        validator
            .validate_canister_mapping(&fqdn!("example.com"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn canister_mapping_fails_on_missing_record() {
        let resolver =
            MockResolver::new(|record_type, name| Err(negative_lookup_error(name, record_type)));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_canister_mapping(&fqdn!("example.com"))
            .await
            .unwrap_err();

        match err {
            ValidationError::MissingDnsTxtCanisterId { src } => {
                assert_eq!(src, "_canister-id.example.com");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn canister_mapping_fails_on_no_records_returned() {
        let resolver = MockResolver::new(|_, _| Ok(vec![]));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_canister_mapping(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            ValidationError::MissingDnsTxtCanisterId { .. }
        ));
    }

    #[tokio::test]
    async fn canister_mapping_fails_on_multiple_records() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![
                txt_record("_canister-id.example.com.", "aaaaa-aa"),
                txt_record("_canister-id.example.com.", "qoctq-giaaa-aaaaa-aaaea-cai"),
            ])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_canister_mapping(&fqdn!("example.com"))
            .await
            .unwrap_err();

        match err {
            ValidationError::MultipleDnsTxtCanisterId { src, records } => {
                assert_eq!(src, "_canister-id.example.com");
                assert_eq!(records.len(), 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn canister_mapping_fails_on_invalid_principal() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![txt_record(
                "_canister-id.example.com.",
                "not-a-principal!!!",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_canister_mapping(&fqdn!("example.com"))
            .await
            .unwrap_err();

        match err {
            ValidationError::InvalidDnsTxtCanisterId { src, id } => {
                assert_eq!(src, "_canister-id.example.com");
                assert_eq!(id, "not-a-principal!!!");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn canister_mapping_propagates_unexpected_resolver_error() {
        let resolver = MockResolver::new(|_, _| Err(NetError::Timeout));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_canister_mapping(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationError::UnexpectedError(_)));
    }

    // ---- validate_no_canister_id_record (exercised via validate_deletion) ----

    #[tokio::test]
    async fn no_canister_id_record_succeeds_on_missing_record() {
        let resolver =
            MockResolver::new(|record_type, name| Err(negative_lookup_error(name, record_type)));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        validator
            .validate_deletion(&fqdn!("example.com"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn no_canister_id_record_fails_when_record_exists() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![txt_record(
                "_canister-id.example.com.",
                "qoctq-giaaa-aaaaa-aaaea-cai",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_deletion(&fqdn!("example.com"))
            .await
            .unwrap_err();

        match err {
            ValidationError::ExistingDnsTxtCanisterId { src } => {
                assert_eq!(src, "_canister-id.example.com.");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_canister_id_record_fails_even_when_result_is_empty() {
        // Any `Ok` result (even an empty one) means the query returned an answer,
        // which is treated as evidence of an existing record.
        let resolver = MockResolver::new(|_, _| Ok(vec![]));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_deletion(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            ValidationError::ExistingDnsTxtCanisterId { .. }
        ));
    }

    #[tokio::test]
    async fn no_canister_id_record_propagates_unexpected_resolver_error() {
        let resolver = MockResolver::new(|_, _| Err(NetError::Timeout));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_deletion(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationError::UnexpectedError(_)));
    }

    // ---- validate_canister_owner / fetch_and_verify_domain_ownership ----

    #[tokio::test]
    async fn canister_owner_succeeds_when_domain_listed() {
        let canister_id = principal!("aaaaa-aa");
        let client = MockClient::new(|req: &reqwest::Request| {
            assert_eq!(
                req.url().as_str(),
                "https://aaaaa-aa.icp0.io/.well-known/ic-domains"
            );
            Ok(text_response("foo.bar\nEXAMPLE.com\nbaz.qux"))
        });
        let validator = mk_validator(Arc::new(client), Arc::new(UnusedResolver));

        validator
            .validate_canister_owner(canister_id, &fqdn!("example.com"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn canister_owner_fails_when_domain_not_listed() {
        let canister_id = principal!("aaaaa-aa");
        let client = MockClient::new(|_: &reqwest::Request| Ok(text_response("foo.bar\nbaz.qux")));
        let validator = mk_validator(Arc::new(client), Arc::new(UnusedResolver));

        let err = validator
            .validate_canister_owner(canister_id, &fqdn!("example.com"))
            .await
            .unwrap_err();

        match err {
            ValidationError::MissingKnownDomains { id } => {
                assert_eq!(id, canister_id.to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn canister_owner_falls_back_to_next_validation_domain() {
        let canister_id = principal!("aaaaa-aa");
        let client = MockClient::new(|req: &reqwest::Request| {
            let body = if req.url().as_str().contains("icp0.io") {
                "foo.bar"
            } else {
                "example.com"
            };
            Ok(text_response(body))
        });

        let validator = Validator {
            client: Arc::new(client),
            resolver: Arc::new(UnusedResolver),
            delegation_domain: fqdn!("icp2.io"),
            validation_domains: vec![fqdn!("icp0.io"), fqdn!("ic0.app")],
        };

        validator
            .validate_canister_owner(canister_id, &fqdn!("example.com"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn canister_owner_fails_when_all_validation_domains_fail() {
        let canister_id = principal!("aaaaa-aa");
        let client = MockClient::new(|_: &reqwest::Request| Ok(text_response("foo.bar")));

        let validator = Validator {
            client: Arc::new(client),
            resolver: Arc::new(UnusedResolver),
            delegation_domain: fqdn!("icp2.io"),
            validation_domains: vec![fqdn!("icp0.io"), fqdn!("ic0.app")],
        };

        let err = validator
            .validate_canister_owner(canister_id, &fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationError::MissingKnownDomains { .. }));
    }

    #[tokio::test]
    async fn canister_owner_fails_when_http_request_errors() {
        let canister_id = principal!("aaaaa-aa");
        let client = MockClient::new(|_: &reqwest::Request| Err(error_response(500)));
        let validator = mk_validator(Arc::new(client), Arc::new(UnusedResolver));

        let err = validator
            .validate_canister_owner(canister_id, &fqdn!("example.com"))
            .await
            .unwrap_err();

        match err {
            ValidationError::KnownDomainsUnavailable { id, .. } => {
                assert_eq!(id, canister_id.to_string());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ---- Validator::new ----

    #[tokio::test]
    async fn new_rejects_root_delegation_domain() {
        let err = Validator::new(
            FQDN::default(),
            vec![fqdn!("icp0.io")],
            DnsOptions::default(),
        )
        .unwrap_err();

        assert!(matches!(err, ValidationError::UnexpectedError(_)));
    }

    #[tokio::test]
    async fn new_rejects_empty_validation_domains() {
        let err = Validator::new(fqdn!("icp2.io"), vec![], DnsOptions::default()).unwrap_err();

        assert!(matches!(err, ValidationError::UnexpectedError(_)));
    }

    #[tokio::test]
    async fn new_succeeds_with_valid_params() {
        Validator::new(
            fqdn!("icp2.io"),
            vec![fqdn!("icp0.io")],
            DnsOptions::default(),
        )
        .unwrap();
    }

    // ---- full validate() / validate_deletion() integration ----

    #[tokio::test]
    async fn validate_succeeds_end_to_end() {
        let canister_id = principal!("qoctq-giaaa-aaaaa-aaaea-cai");

        let resolver = MockResolver::new(move |record_type, name| match (record_type, name) {
            (RecordType::CNAME, "_acme-challenge.example.com.") => Ok(vec![cname_record(
                "_acme-challenge.example.com.",
                "_acme-challenge.example.com.icp2.io.",
            )]),
            (RecordType::TXT, "_acme-challenge.example.com.") => {
                Err(negative_lookup_error(name, record_type))
            }
            (RecordType::TXT, "_canister-id.example.com") => Ok(vec![txt_record(
                "_canister-id.example.com.",
                "qoctq-giaaa-aaaaa-aaaea-cai",
            )]),
            _ => panic!("unexpected resolve call: {record_type:?} {name}"),
        });

        let client = MockClient::new(|req: &reqwest::Request| {
            assert_eq!(
                req.url().as_str(),
                "https://qoctq-giaaa-aaaaa-aaaea-cai.icp0.io/.well-known/ic-domains"
            );
            Ok(text_response("example.com"))
        });

        let validator = mk_validator(Arc::new(client), Arc::new(resolver));

        let result = validator.validate(&fqdn!("example.com")).await.unwrap();
        assert_eq!(result, canister_id);
    }

    #[tokio::test]
    async fn validate_fails_fast_on_missing_cname() {
        let resolver =
            MockResolver::new(|record_type, name| Err(negative_lookup_error(name, record_type)));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator.validate(&fqdn!("example.com")).await.unwrap_err();

        assert!(matches!(err, ValidationError::MissingDnsCname { .. }));
    }

    #[tokio::test]
    async fn validate_deletion_succeeds_when_no_record() {
        let resolver =
            MockResolver::new(|record_type, name| Err(negative_lookup_error(name, record_type)));
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        validator
            .validate_deletion(&fqdn!("example.com"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_deletion_fails_when_record_exists() {
        let resolver = MockResolver::new(|_, _| {
            Ok(vec![txt_record(
                "_canister-id.example.com.",
                "qoctq-giaaa-aaaaa-aaaea-cai",
            )])
        });
        let validator = mk_validator(Arc::new(UnusedClient), Arc::new(resolver));

        let err = validator
            .validate_deletion(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            ValidationError::ExistingDnsTxtCanisterId { .. }
        ));
    }
}
