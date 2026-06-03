#![allow(clippy::too_many_arguments)]

use std::{
    fmt::Display,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::{AHashMap, RandomState};
use async_trait::async_trait;
use candid::Principal;
use futures::future::join_all;
use http::Method;
use ic_agent::{Agent, AgentError};
use ic_bn_lib_common::traits::http::Client;
use moka::sync::Cache;
use show_option::ShowOption as _;
use strum::IntoStaticStr;
use tracing::{debug, info};
use url::Url;

use crate::{
    BoolYesNo,
    custom_domains::LooksUpCustomDomain,
    smtp::{
        DeliversMail, DeliveryError, EmailMessage, RecipientPolicy, RecipientResolveError,
        ResolvesRecipient, SessionMeta,
        address::EmailAddress,
        ic::{
            DestCanister, ExecutesIcSmtpRequest, IcSmtpRequestExecutor, Metrics,
            ReceivesIcSmtpNotifications,
            candid::{Envelope, Message, SmtpRequest, SmtpResponse},
            parse_email,
        },
    },
    truncate,
};

#[derive(thiserror::Error, Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
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
    smtp_canister_id_cache: Cache<Principal, Principal, RandomState>,
    metrics: Metrics,
    notification_handler: Option<Arc<dyn ReceivesIcSmtpNotifications>>,
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
        metrics: Metrics,
        notification_handler: Option<Arc<dyn ReceivesIcSmtpNotifications>>,
    ) -> Self {
        let smtp_canister_id_cache = Cache::builder()
            .time_to_live(cache_ttl)
            .max_capacity(cache_capacity)
            .build_with_hasher(RandomState::default());

        Self {
            request_executor,
            custom_domains,
            http_client,
            ic_base_domain: ic_base_domain.into(),
            smtp_canister_id_cache,
            metrics,
            notification_handler,
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
        metrics: Metrics,
        notification_handler: Option<Arc<dyn ReceivesIcSmtpNotifications>>,
    ) -> Self {
        let request_executor = Arc::new(IcSmtpRequestExecutor::new(agent));

        Self::new(
            request_executor,
            custom_domains,
            http_client,
            ic_base_domain,
            cache_ttl,
            cache_capacity,
            metrics,
            notification_handler,
        )
    }

    fn observe_canister_lookup(
        &self,
        success: bool,
        custom_domain: bool,
        smtp_canister: bool,
        cached: bool,
        elapsed: Duration,
    ) {
        self.metrics
            .canister_id_lookups
            .with_label_values(&[
                success.yesno(),
                custom_domain.yesno(),
                smtp_canister.yesno(),
                cached.yesno(),
            ])
            .inc();

        self.metrics
            .canister_id_lookup_latency
            .with_label_values(&[
                success.yesno(),
                custom_domain.yesno(),
                smtp_canister.yesno(),
                cached.yesno(),
            ])
            .observe(elapsed.as_secs_f64());
    }

    /// Executes an HTTP request to the canister to get the SMTP canister id
    async fn lookup_smtp_canister_id(&self, canister_id: Principal) -> Option<Principal> {
        let url = Url::parse(&format!(
            "https://{canister_id}.{}/.well-known/ic-smtp-canister-id",
            self.ic_base_domain
        ))
        .ok()?;
        debug!("{self}: {canister_id}: Requesting SMTP canister ID using URL: {url}");

        let req = reqwest::Request::new(Method::GET, url);
        let resp = match self.http_client.execute(req).await {
            Ok(v) => v,
            Err(e) => {
                info!("{self}: {canister_id}: SMTP canister ID request failed: {e:#}");
                return None;
            }
        };

        if !resp.status().is_success() {
            info!(
                "{self}: {canister_id}: SMTP canister ID request bad status code: {}",
                resp.status()
            );
            return None;
        }

        let body = match resp.bytes().await {
            Ok(v) => v,
            Err(e) => {
                info!("{self}: {canister_id}: SMTP canister ID HTTP body streaming failed: {e:#}");
                return None;
            }
        };

        // Perform optimistic UTF-8 conversion
        let body_str = String::from_utf8_lossy(&body);
        let body_str = body_str.trim();

        match Principal::from_text(body_str) {
            Ok(v) => {
                debug!("{self}: {canister_id}: Got correct SMTP canister ID: {v}");
                Some(v)
            }
            Err(e) => {
                // Sanitize a bit
                let body_str = body_str.replace("\r", " ").replace("\n", " ");
                let body_str = truncate(&body_str, 128);
                info!("{self}: {canister_id}: Incorrect SMTP canister ID: '{body_str}': {e:#}");
                None
            }
        }
    }

    /// Resolves SMTP canister ID for the given canister_id.
    /// Returns also if it was obtained from the cache.
    async fn resolve_smtp_canister_id(&self, canister_id: Principal) -> (Principal, bool) {
        debug!("{self}: {canister_id}: Looking up SMTP canister ID");

        // Try to find SMTP canister ID, check the cache first
        if let Some(v) = self.smtp_canister_id_cache.get(&canister_id) {
            debug!("{self}: {canister_id}: SMTP canister ID found in cache: {v}");
            return (v, true);
        }

        // Otherwise do a lookup with a fallback to canister_id
        let smtp_canister_id = self
            .lookup_smtp_canister_id(canister_id)
            .await
            .unwrap_or(canister_id);

        // Store the SMTP canister ID in the cache.
        // We do it even if it's the same as base canister_id
        // to avoid repeated HTTP calls in the case when there's
        // no dedicated SMTP canister.
        self.smtp_canister_id_cache
            .insert(canister_id, smtp_canister_id);

        debug!("{self}: {canister_id}: SMTP canister ID obtained: {smtp_canister_id}");
        (smtp_canister_id, false)
    }

    /// Resolves destination SMTP canister id for the given address.
    async fn resolve_canister_id(&self, address: &EmailAddress) -> Option<DestCanister> {
        debug!("{self}: {address}: resolving SMTP canister ID");
        let start = Instant::now();

        let mut custom_domain = false;
        // First check if the target domain has a canister as 1st label.
        // This covers addresses like "foo@qoctq-giaaa-aaaaa-aaaea-cai.icp0.io"
        let lbl = address.domain().labels().next()?;
        let Some(canister_id) = Principal::from_str(lbl)
            .ok()
            .inspect(|x| {
                debug!("{self}: {address}: found canister ID in domain: {x}");
            })
            .or_else(|| {
                // Then check custom domains
                self.custom_domains
                    .lookup_custom_domain(address.domain())
                    .inspect(|x| {
                        debug!("{self}: {address}: found custom domain canister ID: {x}");
                        custom_domain = true;
                    })
            })
        else {
            debug!("{self}: {address}: unable to resolve canister ID");
            self.observe_canister_lookup(false, false, false, false, start.elapsed());
            return None;
        };

        // Finally check if there's an SMTP canister ID defined
        let (smtp_canister_id, cached) = self.resolve_smtp_canister_id(canister_id).await;
        self.observe_canister_lookup(
            true,
            custom_domain,
            smtp_canister_id != canister_id,
            cached,
            start.elapsed(),
        );

        Some(DestCanister {
            smtp: smtp_canister_id,
            orig: canister_id,
            custom_domain,
        })
    }

    /// Sends the given SMTP request to the canister
    async fn send_smtp_request(
        &self,
        canister_id: Principal,
        ic_smtp_request: SmtpRequest,
    ) -> Result<(), DeliveryError> {
        let ic_smtp_response = self
            .request_executor
            .canister_request(canister_id, ic_smtp_request, false)
            .await
            .map_err(|e| match e {
                IcSmtpDeliveryAgentError::Agent(AgentError::InvalidMethodError(_)) => {
                    DeliveryError::Permanent(format!(
                        "Canister {canister_id} does not support SMTP protocol"
                    ))
                }
                _ => DeliveryError::Temporary(e.to_string()),
            })?;

        if let SmtpResponse::Err(e) = ic_smtp_response {
            info!(
                "{self}: {canister_id}: mail delivery failed: {} {}",
                e.code, e.message
            );

            if e.code >= 500 && e.code < 600 {
                return Err(DeliveryError::Permanent(e.message));
            }

            return Err(DeliveryError::Temporary(e.message));
        }

        Ok(())
    }

    /// Sends the message to the listed recipients
    async fn smtp_message_send(
        &self,
        rcpts: Vec<EmailAddress>,
        dest: DestCanister,
        meta: Arc<SessionMeta>,
        message: Arc<EmailMessage>,
        ic_message: Message,
    ) -> Result<(), DeliveryError> {
        let ic_smtp_request = SmtpRequest {
            envelope: Some(Envelope {
                from: message.mail_from.clone().into(),
                to: rcpts.into_iter().map(|x| x.into()).collect(),
            }),
            message: Some(ic_message.clone()),
            gateway_flags: None,
            message_id: Some(message.id.to_string()),
        };

        let start = Instant::now();
        let res = self.send_smtp_request(dest.smtp, ic_smtp_request).await;

        let error_lbl: &'static str = if let Err(e) = &res { e.into() } else { "" };
        self.metrics
            .smtp_requests
            .with_label_values(&["no", error_lbl])
            .inc();
        self.metrics
            .smtp_request_latency
            .with_label_values(&["no", error_lbl])
            .observe(start.elapsed().as_secs_f64());

        if let Some(v) = self.notification_handler.clone() {
            let error = res.clone().err();
            let meta = meta.clone();
            let message = message.clone();

            tokio::spawn(async move {
                v.notify_ic_message(meta, message, dest, error).await;
            });
        }

        res
    }
}

#[async_trait]
impl DeliversMail for IcSmtpDeliveryAgent {
    async fn deliver_mail(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
    ) -> Result<(), DeliveryError> {
        info!(
            "{self}: delivering mail, ehlo: {}, from: '{}', to: '{:?}', id '{}'",
            meta.ehlo_hostname.show_or(""),
            message.mail_from,
            message.rcpt_to,
            message.id
        );

        let ic_message = parse_email(&message.body)
            .map_err(|e| DeliveryError::Permanent(format!("message parsing failed: {e:#}")))?;

        // A single message can be (potentially) destined for several canisters/domains.
        // So we build a map (canister_ids) -> (recipients).
        let mut mapping: AHashMap<DestCanister, Vec<EmailAddress>> =
            AHashMap::with_capacity(message.rcpt_to.len());

        // The future in this loop usually resolves instantly due to the nature of the SMTP protocol.
        // Before the mail is delivered it goes through an RCPT TO sequence which populates the cache.
        // So making it concurrent isn't worth it probably currently.
        for rcpt in &message.rcpt_to {
            // Figure out which canister we should talk to
            let dest = self
                .resolve_canister_id(rcpt)
                .await
                .ok_or_else(|| DeliveryError::Permanent("Unknown domain".into()))?;

            if let Some(v) = mapping.get_mut(&dest) {
                v.push(rcpt.clone());
            } else {
                mapping.insert(dest, vec![rcpt.clone()]);
            }
        }

        let meta = Arc::new(meta);

        // Deliver the message to all relevant canisters in parallel
        let mut futs = Vec::with_capacity(mapping.len());
        for (dest, rcpts) in mapping {
            futs.push(self.smtp_message_send(
                rcpts,
                dest,
                meta.clone(),
                message.clone(),
                ic_message.clone(),
            ));
        }

        // Find & return 1st error if there's any
        join_all(futs)
            .await
            .into_iter()
            .find(|x| x.is_err())
            .unwrap_or(Ok(()))
    }
}

#[async_trait]
impl ResolvesRecipient for IcSmtpDeliveryAgent {
    async fn resolve_recipient(
        &self,
        from: &EmailAddress,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError> {
        debug!("{self}: looking up recipient, from: '{from}', to: '{rcpt}'");

        // Figure out which canister we should talk to
        let dest = self
            .resolve_canister_id(rcpt)
            .await
            .ok_or(RecipientResolveError::UnknownDomain)?;

        let ic_smtp_request = SmtpRequest {
            envelope: Some(Envelope {
                from: from.into(),
                to: vec![rcpt.into()],
            }),
            message: None,
            gateway_flags: None,
            message_id: None,
        };

        let start = Instant::now();
        let res = self
            .request_executor
            .canister_request(dest.smtp, ic_smtp_request, true)
            .await
            .map_err(|e| match e {
                IcSmtpDeliveryAgentError::Agent(
                    AgentError::CertifiedReject { reject, .. }
                    | AgentError::UncertifiedReject { reject, .. },
                    // It seems it's the only way to check that canister is missing a method
                ) if reject.error_code.as_ref().is_some_and(|x| x == "IC0536") => {
                    RecipientResolveError::Permanent(format!(
                        "Canister {} does not support SMTP protocol",
                        dest.smtp
                    ))
                }

                _ => RecipientResolveError::Temporary(e.to_string()),
            });

        let error_lbl: &'static str = if let Err(e) = &res { e.into() } else { "" };
        self.metrics
            .smtp_requests
            .with_label_values(&["yes", error_lbl])
            .inc();
        self.metrics
            .smtp_request_latency
            .with_label_values(&["yes", error_lbl])
            .observe(start.elapsed().as_secs_f64());

        if let SmtpResponse::Err(e) = res? {
            info!(
                "{self}: {}: failed to resolve recipient: {} {}",
                dest.smtp, e.code, e.message
            );

            // Code 550 indicates that the recipient is unknown
            if e.code == 550 {
                return Err(RecipientResolveError::UnknownRecipient);
            }

            if e.code >= 500 && e.code < 600 {
                return Err(RecipientResolveError::Permanent(e.message));
            }

            return Err(RecipientResolveError::Temporary(e.message));
        }

        Ok(RecipientPolicy::Accept)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use crate::{
        email,
        smtp::{
            SessionCounters,
            ic::candid::{Header, Message, SmtpOk, SmtpRequestError},
        },
    };

    use super::*;
    use ahash::HashMap;
    use fqdn::{FQDN, fqdn};
    use ic_bn_lib_common::principal;
    use indoc::indoc;
    use prometheus::Registry;
    use tokio::sync::mpsc;
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

            // Respond with an SMTP canister ID for configured canisters
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

    #[derive(Debug)]
    #[allow(clippy::type_complexity)]
    struct TestNotificationHandler(
        mpsc::Sender<(
            Arc<SessionMeta>,
            Arc<EmailMessage>,
            DestCanister,
            Option<DeliveryError>,
        )>,
    );

    #[async_trait]
    impl ReceivesIcSmtpNotifications for TestNotificationHandler {
        async fn notify_ic_message(
            &self,
            meta: Arc<SessionMeta>,
            message: Arc<EmailMessage>,
            dest: DestCanister,
            error: Option<DeliveryError>,
        ) {
            self.0.send((meta, message, dest, error)).await.unwrap();
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
    struct TestDomainResolver(HashMap<FQDN, Principal>);

    impl LooksUpCustomDomain for TestDomainResolver {
        fn lookup_custom_domain(&self, hostname: &fqdn::Fqdn) -> Option<Principal> {
            self.0.get(hostname).cloned()
        }
    }

    #[allow(clippy::type_complexity)]
    fn create_agent() -> (
        IcSmtpDeliveryAgent,
        Arc<TestHttpClient>,
        Arc<TestIcSmtpRequestExecutor>,
        mpsc::Receiver<(
            Arc<SessionMeta>,
            Arc<EmailMessage>,
            DestCanister,
            Option<DeliveryError>,
        )>,
    ) {
        let resolver = TestDomainResolver(HashMap::from_iter([
            (fqdn!("foo.bar"), principal!("qoctq-giaaa-aaaaa-aaaea-cai")),
            (
                fqdn!("dead.beef"),
                principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
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
        let (tx, rx) = mpsc::channel(10);
        let notif_handler = Arc::new(TestNotificationHandler(tx));

        (
            IcSmtpDeliveryAgent::new(
                request_executor.clone(),
                Arc::new(resolver),
                http_client.clone(),
                "icp0.io",
                Duration::from_secs(10),
                10,
                Metrics::new(&Registry::new()),
                Some(notif_handler),
            ),
            http_client,
            request_executor,
            rx,
        )
    }

    #[tokio::test]
    async fn test_resolve_canister_id() {
        let (delivery_agent, http_client, _, _) = create_agent();

        for (email, dest_expect) in [
            // Normal canister address (w/o custom domains)
            (
                "foo@lusdn-iiaaa-aaaam-qivpa-cai.icp0.io",
                Some(DestCanister {
                    smtp: principal!("lusdn-iiaaa-aaaam-qivpa-cai"),
                    orig: principal!("lusdn-iiaaa-aaaam-qivpa-cai"),
                    custom_domain: false,
                }),
            ),
            // Custom domain
            (
                "foo@foo.bar",
                Some(DestCanister {
                    smtp: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    orig: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    custom_domain: true,
                }),
            ),
            // Normal canister with SMTP canister ID set up
            (
                "foo@gjxif-ryaaa-aaaad-ae4ka-cai.icp0.io",
                Some(DestCanister {
                    smtp: principal!("6hsbt-vqaaa-aaaaf-aaafq-cai"),
                    orig: principal!("gjxif-ryaaa-aaaad-ae4ka-cai"),
                    custom_domain: false,
                }),
            ),
            // Custom domain with SMTP canister ID set up
            (
                "foo@dead.beef",
                Some(DestCanister {
                    smtp: principal!("aaaaa-aa"),
                    orig: principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                    custom_domain: true,
                }),
            ),
            // Unknown custom domain
            ("foo@some-random-domain.org", None),
            // Bad canister ID
            ("foo@gjxif-ryaaa-aaaad-ae4ka-ca.icp0.io", None),
        ] {
            // Run each check a few times to make sure caching kicks in
            for _ in 0..10 {
                let dest = delivery_agent.resolve_canister_id(&email!(email)).await;
                assert_eq!(dest, dest_expect);
            }
        }

        // Make sure we got right number of HTTP requests: 2 for existing SMTP canister IDs and 2 for missing.
        assert_eq!(http_client.1.load(Ordering::SeqCst), 2);
        assert_eq!(http_client.2.load(Ordering::SeqCst), 2);
        // The rest should be served from the cache
        delivery_agent.smtp_canister_id_cache.run_pending_tasks();
        assert_eq!(delivery_agent.smtp_canister_id_cache.entry_count(), 4);
    }

    #[tokio::test]
    async fn test_resolve_recipient() {
        let (delivery_agent, _, _, _) = create_agent();

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
                    // maps to 6hsbt-vqaaa-aaaaf-aaafq-cai
                    &email!("foo@gjxif-ryaaa-aaaad-ae4ka-cai.icp0.io")
                )
                .await
                .unwrap_err(),
            RecipientResolveError::Permanent(_)
        ));
    }

    #[tokio::test]
    async fn test_delivery() {
        let (delivery_agent, _, executor, mut notif_rx) = create_agent();

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

        let remote_ip = IpAddr::from_str("1.1.1.1").unwrap();
        let meta = SessionMeta {
            id: Uuid::nil(),
            message_id: Uuid::nil(),
            remote_ip,
            tls_info: None,
            ehlo_hostname: None,
            counters: SessionCounters::new(),
            last_error: None,
            mail_from: None,
            rcpt_to: vec![],
        };
        delivery_agent
            .deliver_mail(meta, Arc::new(message.clone()))
            .await
            .unwrap();

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
                message_id: Some(Uuid::nil().to_string()),
            }
        };

        let msgs = executor.0.lock().unwrap().clone();

        // Make sure that each canister gets the correct SmtpRequest
        assert_eq!(msgs.len(), 2);
        assert!(msgs.contains(&(
            principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
            create_request(vec![
                email!("jane.doe@foo.bar"),
                email!("someone.else@foo.bar"),
            ])
        )));
        assert!(msgs.contains(&(
            principal!("aaaaa-aa"),
            create_request(vec![email!("foo@dead.beef"),])
        )));

        // Check that 2 notifications arrive - one for each canister
        let mut notifs = [
            notif_rx.recv().await.unwrap(),
            notif_rx.recv().await.unwrap(),
        ]
        .into_iter()
        .collect::<Vec<_>>();
        notifs.sort_by_key(|x| x.2.smtp);

        let (meta, msg, dest, error) = notifs[0].clone();
        assert!(error.is_none());
        assert_eq!(dest.smtp, principal!("aaaaa-aa"));
        assert_eq!(meta.remote_ip, remote_ip);
        assert_eq!(msg.mail_from, email!("john@doe.com"));

        let (meta, msg, dest, error) = notifs[1].clone();
        assert!(error.is_none());
        assert_eq!(dest.smtp, principal!("qoctq-giaaa-aaaaa-aaaea-cai"));
        assert_eq!(meta.remote_ip, remote_ip);
        assert_eq!(msg.mail_from, email!("john@doe.com"));
    }
}
