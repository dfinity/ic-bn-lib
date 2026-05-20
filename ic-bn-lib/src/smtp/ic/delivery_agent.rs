use std::{fmt::Display, str::FromStr, sync::Arc, time::Duration};

use ahash::{AHashMap, RandomState};
use async_trait::async_trait;
use candid::Principal;
use futures::future::try_join_all;
use http::Method;
use ic_agent::Agent;
use ic_bn_lib_common::traits::http::Client;
use moka::sync::Cache;
use tracing::info;
use url::Url;

use crate::{
    custom_domains::LooksUpCustomDomain,
    smtp::{
        DeliversMail, DeliveryError, EmailMessage, RecipientPolicy, RecipientResolveError,
        ResolvesRecipient,
        address::EmailAddress,
        ic::{
            ExecutesIcSmtpRequest, IcSmtpRequestExecutor,
            candid::{Envelope, SmtpRequest, SmtpResponse},
            parse_email,
        },
    },
};

#[derive(thiserror::Error, Debug)]
pub enum IcSmtpDeliveryAgentError {
    #[error("IC Agent error: {0}")]
    Agent(#[from] ic_agent::AgentError),
    #[error("Unable to parse message: {0}")]
    Parser(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug)]
pub struct IcSmtpDeliveryAgent {
    request_executor: Arc<dyn ExecutesIcSmtpRequest>,
    custom_domains: Arc<dyn LooksUpCustomDomain>,
    http_client: Arc<dyn Client>,
    ic_base_domain: String,
    mx_cache: Cache<Principal, Principal, RandomState>,
}

impl Display for IcSmtpDeliveryAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IcSmtpDeliveryAgent")
    }
}

impl IcSmtpDeliveryAgent {
    /// Creates a new `IcSmtpDeliveryAgent` with a generic `Arc<dyn ExecutesIcSmtpRequest>`
    pub fn new(
        request_executor: Arc<dyn ExecutesIcSmtpRequest>,
        custom_domains: Arc<dyn LooksUpCustomDomain>,
        http_client: Arc<dyn Client>,
        ic_base_domain: &str,
        cache_ttl: Duration,
        cache_capacity: u64,
    ) -> Self {
        let mx_cache = Cache::builder()
            .time_to_live(cache_ttl)
            .max_capacity(cache_capacity)
            .build_with_hasher(RandomState::default());

        Self {
            request_executor,
            custom_domains,
            http_client,
            ic_base_domain: ic_base_domain.into(),
            mx_cache,
        }
    }

    /// Creates a new `IcSmtpDeliveryAgent` with an IC Agent
    pub fn new_with_agent(
        agent: Agent,
        custom_domains: Arc<dyn LooksUpCustomDomain>,
        http_client: Arc<dyn Client>,
        ic_base_domain: &str,
        cache_ttl: Duration,
        cache_capacity: u64,
    ) -> Self {
        let request_executor = Arc::new(IcSmtpRequestExecutor::new(agent));

        Self::new(
            request_executor,
            custom_domains,
            http_client,
            ic_base_domain,
            cache_ttl,
            cache_capacity,
        )
    }

    /// Executes an HTTP request to the canister to get the SMTP canister id
    async fn lookup_mx_canister(&self, canister_id: Principal) -> Option<Principal> {
        let url = Url::parse(&format!(
            "https://{canister_id}.{}/.well-known/ic-smtp-canister-id",
            self.ic_base_domain
        ))
        .ok()?;
        let req = reqwest::Request::new(Method::GET, url);

        let resp = match self.http_client.execute(req).await {
            Ok(v) => v,
            Err(e) => {
                info!("{self}: {canister_id}: MX HTTP request failed: {e:#}");
                return None;
            }
        };

        if !resp.status().is_success() {
            info!(
                "{self}: {canister_id}: MX HTTP request bad status code: {}",
                resp.status()
            );
            return None;
        }

        let body = match resp.bytes().await {
            Ok(v) => v,
            Err(e) => {
                info!("{self}: {canister_id}: MX HTTP body streaming failed: {e:#}");
                return None;
            }
        };

        // Perform optimistic UTF-8 conversion
        let body_str = &String::from_utf8_lossy(&body);

        match Principal::from_text(body_str.trim()) {
            Ok(v) => Some(v),
            Err(e) => {
                info!("{self}: {canister_id}: MX HTTP: incorrect principal: ({body_str}) {e:#}");
                None
            }
        }
    }

    /// Resolves SMTP canister id for the given canister_id
    async fn resolve_smtp_canister_id(&self, canister_id: Principal) -> Option<Principal> {
        // Try to find MX canister, check the cache first
        if let Some(v) = self.mx_cache.get(&canister_id) {
            return Some(v);
        }

        // Otherwise do a request with a fall back to casnister_id
        let mx_canister_id = self
            .lookup_mx_canister(canister_id)
            .await
            .unwrap_or(canister_id);

        // Store the MX canister ID in the cache.
        // We do it even if it's the same as base canister_id
        // to avoid repeated HTTP calls even in the case when there's no MX canister.
        self.mx_cache.insert(canister_id, mx_canister_id);

        Some(mx_canister_id)
    }

    /// Resolves destination SMTP canister id for the given address
    async fn resolve_canister_id(&self, address: &EmailAddress) -> Option<Principal> {
        // First check if the target domain has a canister as 1st label.
        // This covers addresses like "foo@qoctq-giaaa-aaaaa-aaaea-cai.icp0.io"
        let lbl = address.domain.labels().next()?;
        let canister_id = Principal::from_str(lbl).ok().or_else(|| {
            // Then check custom domains
            self.custom_domains
                .lookup_custom_domain(&address.domain)
                .map(|x| x.canister_id)
        })?;

        // Finally check if there's an MX canister defined
        self.resolve_smtp_canister_id(canister_id).await
    }

    /// Delivers given SMTP request to the canister
    async fn smtp_request_deliver(
        &self,
        canister_id: Principal,
        smtp_request: SmtpRequest,
    ) -> Result<(), DeliveryError> {
        let resp = self
            .request_executor
            .canister_request(canister_id, smtp_request, false)
            .await
            .map_err(|e| DeliveryError::Temporary(e.to_string()))?;

        if let SmtpResponse::Err(e) = resp {
            if e.code >= 500 && e.code < 599 {
                return Err(DeliveryError::Permanent(e.message));
            }

            return Err(DeliveryError::Temporary(e.message));
        }

        Ok(())
    }
}

#[async_trait]
impl DeliversMail for IcSmtpDeliveryAgent {
    async fn deliver_mail(&self, message: EmailMessage) -> Result<(), DeliveryError> {
        // A single message can be (potentially) destined for several canisters/domains.
        // So we build a map (canister_id) -> (recipients).
        let mut mapping: AHashMap<Principal, Vec<EmailAddress>> = AHashMap::new();

        for rcpt in message.rcpt_to {
            // Figure out which canister we should talk to
            let canister_id = self
                .resolve_canister_id(&rcpt)
                .await
                .ok_or_else(|| DeliveryError::Permanent("Unknown domain".into()))?;

            if let Some(v) = mapping.get_mut(&canister_id) {
                v.push(rcpt);
            } else {
                mapping.insert(canister_id, vec![rcpt]);
            }
        }

        let parsed =
            parse_email(&message.body).map_err(|e| DeliveryError::Permanent(e.to_string()))?;

        // Deliver the message to all relevant canisters in parallel
        let mut futs = Vec::with_capacity(mapping.len());
        for (canister_id, rcpts) in mapping.drain() {
            let smtp_request = SmtpRequest {
                envelope: Some(Envelope {
                    from: message.mail_from.clone().into(),
                    to: rcpts.into_iter().map(|x| x.into()).collect(),
                }),
                message: Some(parsed.clone()),
                gateway_flags: None,
            };

            futs.push(self.smtp_request_deliver(canister_id, smtp_request.clone()));
        }

        try_join_all(futs).await?;
        Ok(())
    }
}

#[async_trait]
impl ResolvesRecipient for IcSmtpDeliveryAgent {
    async fn resolve_recipient(
        &self,
        from: &EmailAddress,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError> {
        // Figure out which canister we should talk to
        let canister_id = self
            .resolve_canister_id(rcpt)
            .await
            .ok_or(RecipientResolveError::UnknownDomain)?;

        let req = SmtpRequest {
            envelope: Some(Envelope {
                from: from.into(),
                to: vec![rcpt.into()],
            }),
            message: None,
            gateway_flags: None,
        };

        let resp = self
            .request_executor
            .canister_request(canister_id, req, true)
            .await
            .map_err(|e| RecipientResolveError::Temporary(e.to_string()))?;

        if let SmtpResponse::Err(e) = resp {
            // Code 550 indicates that the recipient is unknown
            if e.code == 550 {
                return Err(RecipientResolveError::UnknownRecipient);
            }

            if e.code >= 500 && e.code < 599 {
                return Err(RecipientResolveError::Permanent(e.message));
            }

            return Err(RecipientResolveError::Temporary(e.message));
        }

        Ok(RecipientPolicy::Accept)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::{
        email,
        smtp::ic::candid::{Header, Message, SmtpOk, SmtpRequestError},
    };

    use super::*;
    use ahash::HashMap;
    use fqdn::{FQDN, fqdn};
    use ic_bn_lib_common::{principal, types::CustomDomain};
    use indoc::indoc;
    use uuid::Uuid;

    #[derive(Debug)]
    struct TestHttpClient(HashMap<Principal, Principal>, AtomicUsize, AtomicUsize);

    #[async_trait::async_trait]
    impl Client for TestHttpClient {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            assert_eq!(req.url().path(), "/.well-known/ic-smtp-canister-id");
            let canister_id = principal!(fqdn!(req.url().authority()).labels().next().unwrap());

            // Respond with an MX canister id for configured canisters
            if let Some(v) = self.0.get(&canister_id) {
                self.1.fetch_add(1, Ordering::SeqCst);

                return Ok(reqwest::Response::from(
                    http::response::Builder::new()
                        .status(200)
                        .body(reqwest::Body::from(v.to_string()))
                        .unwrap(),
                ));
            }

            self.2.fetch_add(1, Ordering::SeqCst);
            Ok(reqwest::Response::from(
                http::response::Builder::new().status(404).body("").unwrap(),
            ))
        }
    }

    #[derive(Debug, Default)]
    struct TestIcSmtpRequestExecutor(Mutex<Vec<(Principal, SmtpRequest)>>);

    #[async_trait]
    impl ExecutesIcSmtpRequest for TestIcSmtpRequestExecutor {
        async fn canister_request(
            &self,
            canister_id: Principal,
            request: SmtpRequest,
            validate: bool,
        ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
            if !validate {
                (*self.0.lock().unwrap()).push((canister_id, request));
                return Ok(SmtpResponse::Ok(SmtpOk {}));
            }

            if canister_id == principal!("aaaaa-aa") {
                return Ok(SmtpResponse::Err(SmtpRequestError {
                    code: 550,
                    message: "Nobody here".into(),
                }));
            } else if canister_id == principal!("6hsbt-vqaaa-aaaaf-aaafq-cai") {
                return Ok(SmtpResponse::Err(SmtpRequestError {
                    code: 555,
                    message: "Some permanent error".into(),
                }));
            } else if canister_id == principal!("lusdn-iiaaa-aaaam-qivpa-cai") {
                return Err(IcSmtpDeliveryAgentError::Agent(
                    ic_agent::AgentError::InvalidReplicaStatus,
                ));
            }

            Ok(SmtpResponse::Ok(SmtpOk {}))
        }
    }

    #[derive(Debug)]
    struct TestDomainResolver(HashMap<FQDN, CustomDomain>);

    impl LooksUpCustomDomain for TestDomainResolver {
        fn lookup_custom_domain(&self, hostname: &fqdn::Fqdn) -> Option<CustomDomain> {
            self.0.get(hostname).cloned()
        }
    }

    fn create_agent() -> (
        IcSmtpDeliveryAgent,
        Arc<TestHttpClient>,
        Arc<TestIcSmtpRequestExecutor>,
    ) {
        let resolver = TestDomainResolver(HashMap::from_iter([
            (
                fqdn!("foo.bar"),
                CustomDomain {
                    name: fqdn!("foo.bar"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
            ),
            (
                fqdn!("dead.beef"),
                CustomDomain {
                    name: fqdn!("dead.beef"),
                    canister_id: principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                    timestamp: 0,
                },
            ),
        ]));

        let http_client = Arc::new(TestHttpClient(
            HashMap::from_iter([
                (
                    principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                    principal!("aaaaa-aa"),
                ),
                (
                    principal!("gjxif-ryaaa-aaaad-ae4ka-cai"),
                    principal!("6hsbt-vqaaa-aaaaf-aaafq-cai"),
                ),
            ]),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ));

        let request_executor = Arc::new(TestIcSmtpRequestExecutor::default());

        (
            IcSmtpDeliveryAgent::new(
                request_executor.clone(),
                Arc::new(resolver),
                http_client.clone(),
                "icp0.io",
                Duration::from_secs(10),
                10,
            ),
            http_client,
            request_executor,
        )
    }

    #[tokio::test]
    async fn test_resolve_canister_id() {
        let (delivery_agent, http_client, _) = create_agent();

        for (email, canister_id) in [
            // Normal canister address (w/o custom domains)
            (
                "foo@lusdn-iiaaa-aaaam-qivpa-cai.icp0.io",
                Some(principal!("lusdn-iiaaa-aaaam-qivpa-cai")),
            ),
            // Custom domain
            (
                "foo@foo.bar",
                Some(principal!("qoctq-giaaa-aaaaa-aaaea-cai")),
            ),
            // Normal canister with MX canister set up
            (
                "foo@gjxif-ryaaa-aaaad-ae4ka-cai.icp0.io",
                Some(principal!("6hsbt-vqaaa-aaaaf-aaafq-cai")),
            ),
            // Custom domain with MX canister set up
            ("foo@dead.beef", Some(principal!("aaaaa-aa"))),
            // Unknown custom domain
            ("foo@some-random-domain.org", None),
            // Bad canister ID
            ("foo@gjxif-ryaaa-aaaad-ae4ka-ca.icp0.io", None),
        ] {
            // Run each check a few times to make sure caching kicks in
            for _ in 0..10 {
                let id = delivery_agent.resolve_canister_id(&email!(email)).await;
                assert_eq!(id, canister_id);
            }
        }

        // Make sure we got right number of HTTP requests: 2 for existing MXs and 2 for missing.
        assert_eq!(http_client.1.load(Ordering::SeqCst), 2);
        assert_eq!(http_client.2.load(Ordering::SeqCst), 2);
        // The rest should be served from the cache
        delivery_agent.mx_cache.run_pending_tasks();
        assert_eq!(delivery_agent.mx_cache.entry_count(), 4);
    }

    #[tokio::test]
    async fn test_resolve_recipient() {
        let (delivery_agent, _, _) = create_agent();

        assert!(matches!(
            delivery_agent
                .resolve_recipient(&email!("jane@doe.com"), &email!("foo@dead.moroz"))
                .await
                .unwrap_err(),
            RecipientResolveError::UnknownDomain
        ));
        assert!(matches!(
            delivery_agent
                .resolve_recipient(&email!("jane@doe.com"), &email!("foo@dead.beef"))
                .await
                .unwrap_err(),
            RecipientResolveError::UnknownRecipient
        ));
        assert!(matches!(
            delivery_agent
                .resolve_recipient(
                    &email!("jane@doe.com"),
                    &email!("foo@lusdn-iiaaa-aaaam-qivpa-cai.icp0.io")
                )
                .await
                .unwrap_err(),
            RecipientResolveError::Temporary(_)
        ));
        assert!(matches!(
            delivery_agent
                .resolve_recipient(
                    &email!("jane@doe.com"),
                    // maps mx to 6hsbt-vqaaa-aaaaf-aaafq-cai
                    &email!("foo@gjxif-ryaaa-aaaad-ae4ka-cai.icp0.io")
                )
                .await
                .unwrap_err(),
            RecipientResolveError::Permanent(_)
        ));
    }

    #[tokio::test]
    async fn test_delivery() {
        let (delivery_agent, _, executor) = create_agent();

        let message = indoc! {r#"
            From: Some One <someone@example.com>
            To: John Doe <john@doe.com>
            MIME-Version: 1.0
            Content-Type: multipart/mixed;
                    boundary="XXXXboundary text"

            --XXXXboundary text
            Content-Type: text/plain

            this is the body text

            --XXXXboundary text
            Content-Type: text/plain;
            Content-Disposition: attachment;
                    filename="test.txt"

            this is the attachment text

            --XXXXboundary text--
        "#};

        let message = EmailMessage {
            id: Uuid::nil(),
            ehlo_hostname: fqdn!("foo.bar"),
            mail_from: email!("john@doe.com"),
            rcpt_to: vec![
                // these two go to qoctq-giaaa-aaaaa-aaaea-cai as a single mail
                email!("jane.doe@foo.bar"),
                email!("someone.else@foo.bar"),
                // this one to aaaaa-aa
                email!("foo@dead.beef"),
            ],
            body: message.as_bytes().into(),
        };

        delivery_agent.deliver_mail(message.clone()).await.unwrap();

        let body = indoc! {r#"
            --XXXXboundary text
            Content-Type: text/plain

            this is the body text

            --XXXXboundary text
            Content-Type: text/plain;
            Content-Disposition: attachment;
                    filename="test.txt"

            this is the attachment text

            --XXXXboundary text--
        "#};

        let create_request = |rcpts: Vec<EmailAddress>| -> SmtpRequest {
            SmtpRequest {
                envelope: Some(Envelope {
                    from: message.clone().mail_from.into(),
                    to: rcpts.into_iter().map(|x| x.into()).collect(),
                }),
                message: Some(Message {
                    headers: vec![
                        Header {
                            name: "From".into(),
                            value: " Some One <someone@example.com>\n".into(),
                        },
                        Header {
                            name: "To".into(),
                            value: " John Doe <john@doe.com>\n".into(),
                        },
                        Header {
                            name: "MIME-Version".into(),
                            value: " 1.0\n".into(),
                        },
                        Header {
                            name: "Content-Type".into(),
                            value: " multipart/mixed;\n        boundary=\"XXXXboundary text\"\n"
                                .into(),
                        },
                    ],

                    body: body.as_bytes().to_vec(),
                }),
                gateway_flags: None,
            }
        };

        let msgs = executor.0.lock().unwrap().clone();

        // Make sure that each canister gets the same SmtpRequest
        assert_eq!(
            msgs,
            vec![
                (
                    principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    create_request(vec![
                        email!("jane.doe@foo.bar"),
                        email!("someone.else@foo.bar"),
                    ])
                ),
                (
                    principal!("aaaaa-aa"),
                    create_request(vec![email!("foo@dead.beef"),])
                )
            ]
        )
    }
}
