#![allow(clippy::too_many_arguments)]

use std::{
    fmt::Display,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::{AHashMap, RandomState};
use async_trait::async_trait;
use candid::{Encode, Principal};
use futures::{StreamExt, TryStreamExt, future::join_all, stream};
use http::Method;
use ic_agent::Agent;
use moka::sync::Cache;
use show_option::ShowOption as _;
use strum::IntoStaticStr;
use tokio::sync::Semaphore;
use tokio_util::time::FutureExt;
use tracing::{debug, info, warn};
use url::Url;

use crate::{
    BoolYesNo,
    custom_domains::LooksUpCustomDomain,
    http::Client,
    smtp::{
        DeliversMail, DeliveryError, EmailMessage, RecipientPolicy, RecipientResolveError,
        ResolvesRecipient, SessionMeta,
        address::EmailAddress,
        ic::{
            DestCanister, ExecutesIcSmtpRequest, IcSmtpRequestExecutor, Metrics, ParsedEmail,
            ReceivesIcSmtpNotifications,
            candid::{
                Envelope, SmtpCapabilities, SmtpRequest, SmtpRequestError, SmtpResponse,
                SmtpUploadChunk, SmtpUploadChunkResponse, SmtpUploadId, SmtpUploadStatusResponse,
            },
            is_ambiguous, is_missing_method, is_payload_too_large, is_rate_limited,
            parse_email_bytes,
            upload::{
                IcSmtpUploadConfig, UploadPlan, UploadPlanError, build_chunk, build_commit,
                plan_chunks, single_shot_encoded_len,
            },
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
    #[error("Canister does not implement {0}")]
    Unsupported(&'static str),
    #[error("Chunked upload failed: {0}")]
    Upload(String),
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
    caps_cache: Cache<Principal, Arc<SmtpCapabilities>, RandomState>,
    upload_cfg: IcSmtpUploadConfig,
    upload_permits: Arc<Semaphore>,
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

        let upload_cfg = IcSmtpUploadConfig::default();

        Self {
            request_executor,
            custom_domains,
            http_client,
            ic_base_domain: ic_base_domain.into(),
            smtp_canister_id_cache,
            caps_cache: Self::build_caps_cache(&upload_cfg, cache_capacity),
            upload_permits: Arc::new(Semaphore::new(upload_cfg.global_concurrency)),
            upload_cfg,
            metrics,
            notification_handler,
        }
    }

    fn build_caps_cache(
        cfg: &IcSmtpUploadConfig,
        capacity: u64,
    ) -> Cache<Principal, Arc<SmtpCapabilities>, RandomState> {
        Cache::builder()
            .time_to_live(cfg.capabilities_cache_ttl)
            .max_capacity(capacity)
            .build_with_hasher(RandomState::default())
    }

    /// Enables & configures the chunked upload protocol
    #[must_use]
    pub fn with_upload_config(mut self, cfg: IcSmtpUploadConfig) -> Self {
        let capacity = self
            .smtp_canister_id_cache
            .policy()
            .max_capacity()
            .unwrap_or(10_000);

        self.caps_cache = Self::build_caps_cache(&cfg, capacity);
        self.upload_permits = Arc::new(Semaphore::new(cfg.global_concurrency.max(1)));
        self.upload_cfg = cfg;

        self
    }

    /// Fetches capabilities of the given canister, from cache where possible
    async fn capabilities(&self, canister_id: Principal) -> Arc<SmtpCapabilities> {
        if let Some(v) = self.caps_cache.get(&canister_id) {
            self.metrics
                .capability_lookups
                .with_label_values(&["yes", v.supports_chunked().yesno()])
                .inc();

            return v;
        }

        let caps = match self
            .request_executor
            .canister_capabilities(canister_id)
            .await
        {
            Ok(v) => {
                let v = Arc::new(v);
                self.caps_cache.insert(canister_id, v.clone());
                v
            }

            Err(e) if is_missing_method(&e) => {
                debug!("{self}: {canister_id}: no smtp_capabilities, assuming legacy");
                let v = Arc::new(SmtpCapabilities::default());
                self.caps_cache.insert(canister_id, v.clone());
                v
            }

            Err(e) => {
                debug!("{self}: {canister_id}: capability lookup failed: {e:#}");
                Arc::new(SmtpCapabilities::default())
            }
        };

        self.metrics
            .capability_lookups
            .with_label_values(&["no", caps.supports_chunked().yesno()])
            .inc();

        caps
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
            .map_err(|e| map_delivery_error(canister_id, &e))?;

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

    /// Uploads the body as chunks and finalizes it with a commit.
    ///
    /// Chunks are independent and idempotent, so they are submitted
    /// concurrently (even if the canister processes them sequentially in the end)
    async fn upload_and_commit(
        &self,
        canister_id: Principal,
        envelope: &Envelope,
        parsed: &ParsedEmail,
        message_id: &str,
        plan: &UploadPlan,
    ) -> Result<(), DeliveryError> {
        let start = Instant::now();
        let concurrency = self
            .upload_cfg
            .concurrency(plan.chunk_size)
            .min(self.upload_cfg.global_concurrency.max(1));

        debug!(
            "{self}: {canister_id}: uploading {} bytes in {} chunks of {} ({concurrency} in flight)",
            plan.body_size, plan.total_chunks, plan.chunk_size
        );

        // Create & upload chunks
        let res = stream::iter(0..plan.total_chunks)
            .map(|index| async move {
                let _permit = self
                    .upload_permits
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| {
                        ChunkFailure::give_up(DeliveryError::Temporary(
                            "upload semaphore closed".into(),
                        ))
                    })?;

                let chunk = build_chunk(
                    plan,
                    index,
                    &parsed.body,
                    &parsed.headers,
                    envelope,
                    message_id,
                    None,
                );

                self.upload_one_chunk(canister_id, &chunk).await
            })
            .buffer_unordered(concurrency)
            .try_collect::<Vec<_>>()
            .await
            .map(|_| ());

        if let Err(e) = res {
            self.observe_upload(start, Some(&e.error));

            // If the error tells us to abort the upload, do so
            if !e.keep_upload {
                self.spawn_abort(canister_id, message_id);
            }

            return Err(e.error);
        }

        self.metrics.upload_bytes.inc_by(plan.body_size as u64);

        // Commit the uploaded chunks to finalize the message
        let res = self.commit_upload(canister_id, message_id, plan).await;
        self.observe_upload(start, res.as_ref().err());
        res
    }

    /// Uploads a single chunk, retrying transient failures
    async fn upload_one_chunk(
        &self,
        canister_id: Principal,
        chunk: &SmtpUploadChunk,
    ) -> Result<(), ChunkFailure> {
        let mut attempt = 0usize;

        loop {
            let start = Instant::now();
            let res = self
                .request_executor
                .canister_upload_chunk(canister_id, chunk)
                .await;

            let err_lbl: &'static str = match &res {
                Ok(SmtpUploadChunkResponse::Ok(_)) => "",
                Ok(SmtpUploadChunkResponse::Err(_)) => "canister",
                Err(e) => e.into(),
            };
            self.observe_upload_call("chunk", err_lbl, start);

            let e = match res {
                Ok(SmtpUploadChunkResponse::Ok(_)) => return Ok(()),

                // The canister gave a verdict; it will give the same one again.
                Ok(SmtpUploadChunkResponse::Err(e)) => {
                    info!(
                        "{self}: {canister_id}: chunk {} rejected: {} {}",
                        chunk.index, e.code, e.message
                    );
                    return Err(ChunkFailure::give_up(map_canister_error(&e)));
                }

                Err(e) => e,
            };

            // The canister advertised chunking but does not implement it.
            // Drop the stale capabilities from the cache.
            if is_missing_method(&e) {
                warn!(
                    "{self}: {canister_id}: advertised chunked upload but does not \
                     implement smtp_upload_chunk; invalidating capabilities"
                );

                self.caps_cache.invalidate(&canister_id);
                return Err(ChunkFailure::give_up(DeliveryError::Temporary(
                    "canister does not implement chunked upload".into(),
                )));
            }

            if is_payload_too_large(&e) {
                return Err(ChunkFailure::give_up(DeliveryError::Permanent(format!(
                    "chunk {} rejected as too large by canister {canister_id}",
                    chunk.index
                ))));
            }

            let rate_limited = is_rate_limited(&e);
            if attempt >= self.upload_cfg.chunk_retries {
                return Err(if rate_limited {
                    ChunkFailure::resumable(DeliveryError::Temporary(format!(
                        "canister {canister_id} rate limited the upload: {e}"
                    )))
                } else {
                    ChunkFailure::give_up(DeliveryError::Temporary(format!(
                        "chunk {} upload failed: {e}",
                        chunk.index
                    )))
                });
            }

            attempt += 1;
            self.metrics
                .upload_chunk_retries
                .with_label_values(&[<&'static str>::from(&e)])
                .inc();

            // Exponential backoff; a rate-limited replica gets a longer delay
            let base = if rate_limited { 2000 } else { 250 };
            let delay = Duration::from_millis(base * (1 << (attempt - 1)) as u64);

            debug!(
                "{self}: {canister_id}: chunk {} attempt {attempt} failed ({e}), retrying in {delay:?}",
                chunk.index
            );

            tokio::time::sleep(delay).await;
        }
    }

    /// Finalizes an upload
    async fn commit_upload(
        &self,
        canister_id: Principal,
        message_id: &str,
        plan: &UploadPlan,
    ) -> Result<(), DeliveryError> {
        let commit = build_commit(plan, message_id);

        let start = Instant::now();
        let res = self
            .request_executor
            .canister_upload_commit(canister_id, commit)
            .await;

        let err_lbl: &'static str = match &res {
            Ok(SmtpResponse::Ok(_)) => "",
            Ok(SmtpResponse::Err(_)) => "canister",
            Err(e) => e.into(),
        };
        self.observe_upload_call("commit", err_lbl, start);

        match res {
            Ok(SmtpResponse::Ok(_)) => Ok(()),

            Ok(SmtpResponse::Err(e)) => {
                info!(
                    "{self}: {canister_id}: commit rejected: {} {}",
                    e.code, e.message
                );
                Err(map_canister_error(&e))
            }

            // The commit may or may not have succeeded.
            // Retrying can deliver the same mail twice, so ask the canister what actually happened.
            Err(e) if is_ambiguous(&e) => {
                warn!("{self}: {canister_id}: commit outcome unknown ({e:#}), querying status");
                self.resolve_ambiguous_commit(canister_id, message_id).await
            }

            // If the failure is final - abort the upload and report the error
            Err(e) => {
                self.spawn_abort(canister_id, message_id);
                Err(map_delivery_error(canister_id, &e))
            }
        }
    }

    /// Asks the canister whether a commit whose reply we never saw was applied
    async fn resolve_ambiguous_commit(
        &self,
        canister_id: Principal,
        message_id: &str,
    ) -> Result<(), DeliveryError> {
        let start = Instant::now();
        let res = self
            .request_executor
            .canister_upload_status(
                canister_id,
                SmtpUploadId {
                    message_id: message_id.to_string(),
                },
            )
            .await;
        self.observe_upload_call("status", if res.is_ok() { "" } else { "agent" }, start);

        match res {
            Ok(SmtpUploadStatusResponse::Ok(st)) if st.known && st.committed => {
                match st.result {
                    // The delivery did happen; report its result
                    Some(SmtpResponse::Ok(_)) => {
                        info!("{self}: {canister_id}: commit had succeeded");
                        Ok(())
                    }
                    Some(SmtpResponse::Err(e)) => Err(map_canister_error(&e)),
                    // Committed but no outcome for whatever reason - assume it was delivered
                    None => Ok(()),
                }
            }

            // Still open: the commit never ran, so one more attempt is safe
            Ok(SmtpUploadStatusResponse::Ok(st)) if st.known => {
                Err(DeliveryError::Temporary("commit did not complete".into()))
            }

            // Unknown / ambiguous: retry the delivery just in case
            _ => Err(DeliveryError::Temporary(
                "commit outcome could not be determined".into(),
            )),
        }
    }

    /// Best-effort release of an upload we are giving up on
    fn spawn_abort(&self, canister_id: Principal, message_id: &str) {
        let executor = self.request_executor.clone();
        let upload = SmtpUploadId {
            message_id: message_id.to_string(),
        };

        tokio::spawn(async move {
            let _ = executor.canister_upload_abort(canister_id, upload).await;
        });
    }

    fn observe_upload_call(&self, method: &str, error: &str, start: Instant) {
        self.metrics
            .upload_calls
            .with_label_values(&[method, error])
            .inc();
        self.metrics
            .upload_call_latency
            .with_label_values(&[method, error])
            .observe(start.elapsed().as_secs_f64());
    }

    fn observe_upload(&self, start: Instant, error: Option<&DeliveryError>) {
        let lbl: &'static str = error.map_or("", Into::into);
        self.metrics
            .upload_duration
            .with_label_values(&[lbl])
            .observe(start.elapsed().as_secs_f64());
    }

    /// Sends the message to the listed recipients of a single canister.
    async fn smtp_message_send(
        &self,
        dest: Destination,
        envelope: Envelope,
        meta: Arc<SessionMeta>,
        message: Arc<EmailMessage>,
        parsed: Arc<ParsedEmail>,
        route: Route,
    ) -> Result<(), DeliveryError> {
        let message_id = message.id.to_string();
        let start = Instant::now();

        let mode = route.label();

        // Check which method should we use to send the message
        let res = match route {
            Route::Reject(e) => Err(e),

            Route::SingleShot => {
                let ic_smtp_request = SmtpRequest {
                    envelope: Some(envelope),
                    message: Some(parsed.to_message()),
                    gateway_flags: None,
                    message_id: Some(message_id),
                };

                self.send_smtp_request(dest.smtp, ic_smtp_request).await
            }

            Route::Chunked(plan) => {
                self.upload_and_commit(dest.smtp, &envelope, &parsed, &message_id, &plan)
                    .await
            }
        };

        let latency = start.elapsed();
        let error_lbl: &'static str = if let Err(e) = &res { e.into() } else { "" };

        self.metrics
            .deliveries
            .with_label_values(&[mode, error_lbl])
            .inc();
        self.metrics
            .smtp_requests
            .with_label_values(&["no", error_lbl])
            .inc();
        self.metrics
            .smtp_request_latency
            .with_label_values(&["no", error_lbl])
            .observe(latency.as_secs_f64());

        if let Some(v) = self.notification_handler.clone() {
            let error = res.clone().err();
            let meta = meta.clone();
            let message = message.clone();
            // Several `DestCanister`s can share one SMTP canister and therefore
            // one delivery
            let origins = dest.origins.clone();

            tokio::spawn(async move {
                for origin in origins {
                    v.notify_ic_message(
                        meta.clone(),
                        message.clone(),
                        origin,
                        latency,
                        error.clone(),
                    )
                    .await;
                }
            });
        }

        res
    }
}

/// Why a chunk upload stopped, and whether the partial upload is worth keeping
#[derive(Clone, Debug)]
struct ChunkFailure {
    error: DeliveryError,
    /// Leave the partial upload alone rather than aborting it
    keep_upload: bool,
}

impl ChunkFailure {
    /// The attempt is over; release whatever the canister is holding.
    const fn give_up(error: DeliveryError) -> Self {
        Self {
            error,
            keep_upload: false,
        }
    }

    /// Transient back-pressure: skip the abort, let the canister expire it.
    const fn resumable(error: DeliveryError) -> Self {
        Self {
            error,
            keep_upload: true,
        }
    }
}

/// One SMTP canister and everything destined for it.
///
/// Recipients are merged per **SMTP canister**, not per [`DestCanister`]: the
/// same canister can be reached through several `DestCanister`s - two
/// app canisters delegating to one shared SMTP canister via
/// `.well-known/ic-smtp-canister-id`, or one canister addressed both through a
/// custom domain and through `<principal>.icp0.io`.
#[derive(Clone, Debug)]
struct Destination {
    smtp: Principal,
    origins: Vec<DestCanister>,
    rcpts: Vec<EmailAddress>,
}

/// How one destination canister will receive this message
#[derive(Clone, Debug)]
enum Route {
    /// Fits into a single ingress message
    SingleShot,
    /// Too large for one call, and the canister supports chunked upload
    Chunked(Arc<UploadPlan>),
    /// Cannot be delivered - no canister call will be made at all
    Reject(DeliveryError),
}

impl Route {
    const fn label(&self) -> &'static str {
        match self {
            Self::SingleShot => "single_shot",
            Self::Chunked(_) => "chunked",
            Self::Reject(_) => "rejected",
        }
    }
}

/// Maps a transport-level error from a delivery call to an SMTP outcome
fn map_delivery_error(canister_id: Principal, e: &IcSmtpDeliveryAgentError) -> DeliveryError {
    if is_missing_method(e) {
        return DeliveryError::Permanent(format!(
            "Canister {canister_id} does not support SMTP protocol"
        ));
    }

    // The same message will be refused always
    if is_payload_too_large(e) {
        return DeliveryError::Permanent(format!(
            "Message is too large for canister {canister_id} to accept in a single call"
        ));
    }

    DeliveryError::Temporary(e.to_string())
}

/// Maps a canister-reported SMTP error to a delivery outcome
fn map_canister_error(e: &SmtpRequestError) -> DeliveryError {
    if (500..600).contains(&e.code) {
        DeliveryError::Permanent(e.message.clone())
    } else {
        DeliveryError::Temporary(e.message.clone())
    }
}

#[async_trait]
impl DeliversMail for IcSmtpDeliveryAgent {
    async fn deliver_mail(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
    ) -> Result<(), DeliveryError> {
        // Delivery runs inside the SMTP session, before the 250 is written, and
        // no existing timeout can limit it: `max_session_duration` is only
        // checked when the client sends more bytes, and `timeout` is a socket
        // read timeout.
        // So wrap it with timeout.
        self.deliver_mail_inner(meta, message)
            .timeout(self.upload_cfg.delivery_timeout)
            .await
            .unwrap_or_else(|_| {
                Err(DeliveryError::Temporary(format!(
                    "delivery timed out after {:?}",
                    self.upload_cfg.delivery_timeout
                )))
            })
    }
}

impl IcSmtpDeliveryAgent {
    async fn deliver_mail_inner(
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

        // Body is a view into the session buffer, so cloning is cheap.
        let parsed = Arc::new(
            parse_email_bytes(&message.body)
                .map_err(|e| DeliveryError::Permanent(format!("message parsing failed: {e:#}")))?,
        );

        // A single message can be (potentially) destined for several canisters/domains.
        // So we build a map (smtp canister) -> (recipients), keyed by the canister
        // we actually talk to
        let mut mapping: AHashMap<Principal, Destination> =
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

            let entry = mapping.entry(dest.smtp).or_insert_with(|| Destination {
                smtp: dest.smtp,
                origins: vec![],
                rcpts: vec![],
            });

            if !entry.origins.contains(&dest) {
                entry.origins.push(dest);
            }
            entry.rcpts.push(rcpt.clone());
        }

        let message_id = message.id.to_string();

        // Plan how the message will be delivered to each destination canister
        let destinations = self
            .plan_destinations(
                &mapping,
                &parsed,
                &message_id,
                &message.mail_from,
                message.body.len() as u64,
            )
            .await;

        let meta = Arc::new(meta);

        // Deliver the message to all relevant canisters concurrently
        let mut futs = Vec::with_capacity(destinations.len());
        for (dest, envelope, route) in destinations {
            futs.push(self.smtp_message_send(
                dest,
                envelope,
                meta.clone(),
                message.clone(),
                parsed.clone(),
                route,
            ));
        }

        // Find & return 1st error if there are any
        join_all(futs)
            .await
            .into_iter()
            .find(std::result::Result::is_err)
            .unwrap_or(Ok(()))
    }

    /// Decides how each destination canister will receive this message (single-call, chunked etc)
    async fn plan_destinations(
        &self,
        mapping: &AHashMap<Principal, Destination>,
        parsed: &ParsedEmail,
        message_id: &str,
        mail_from: &EmailAddress,
        // Size of the raw message: headers + body
        raw_size: u64,
    ) -> Vec<(Destination, Envelope, Route)> {
        // Envelope, capabilities and single-call size for each destination.
        let mut prepared = Vec::with_capacity(mapping.len());
        for dest in mapping.values() {
            let envelope = Envelope {
                from: mail_from.clone().into(),
                to: dest.rcpts.iter().map(Into::into).collect(),
            };

            // Estimate the encoded size of the envelope
            let envelope_size = Encode!(&envelope).map(|x| x.len()).unwrap_or(0);
            let caps = self.capabilities(dest.smtp).await;

            prepared.push((dest.clone(), envelope, envelope_size, caps));
        }

        let est = |envelope: &Envelope| {
            single_shot_encoded_len(&parsed.headers, envelope, message_id, parsed.body.len())
        };

        // Does anything actually need chunking?
        let needs_chunking = prepared
            .iter()
            .any(|(_, env, _, _)| est(env).is_ok_and(|n| n > self.upload_cfg.max_ingress_size));

        // One plan for everyone
        let plan = if needs_chunking && !parsed.body.is_empty() {
            let widest = prepared
                .iter()
                .max_by_key(|(_, _, len, _)| *len)
                .map(|(_, env, _, _)| env.clone());

            widest.map(|env| {
                plan_chunks(
                    &parsed.headers,
                    &env,
                    message_id,
                    &parsed.body,
                    self.upload_cfg.max_ingress_size,
                    self.upload_cfg.chunk_size,
                )
                .map(Arc::new)
            })
        } else {
            None
        };

        prepared
            .into_iter()
            .map(|(dest, envelope, _, caps)| {
                let route =
                    self.route_for(dest.smtp, &envelope, &caps, plan.as_ref(), raw_size, &est);
                (dest, envelope, route)
            })
            .collect()
    }

    /// Picks the transfer mode for one destination.
    fn route_for(
        &self,
        smtp: Principal,
        envelope: &Envelope,
        caps: &SmtpCapabilities,
        plan: Option<&Result<Arc<UploadPlan>, UploadPlanError>>,
        raw_size: u64,
        est: &impl Fn(&Envelope) -> Result<usize, UploadPlanError>,
    ) -> Route {
        let Ok(encoded) = est(envelope) else {
            return Route::Reject(DeliveryError::Temporary(
                "unable to size the message for delivery".into(),
            ));
        };

        // Fits one ingress message
        if encoded <= self.upload_cfg.max_ingress_size {
            return Route::SingleShot;
        }

        if caps.supports_chunked() {
            // Advertised limits are the canister's own promises, so exceeding
            // them is a definite refusal rather than something to retry.
            if caps.max_message_size.is_some_and(|m| raw_size > m) {
                return Route::Reject(DeliveryError::Permanent(format!(
                    "message is {raw_size} bytes, canister {smtp} accepts at most {}",
                    caps.max_message_size.unwrap_or(0)
                )));
            }

            return match plan {
                Some(Ok(p)) => Route::Chunked(p.clone()),

                // Planning failed (too big header block?)
                Some(Err(e)) => Route::Reject(DeliveryError::Permanent(e.to_string())),

                None => Route::Reject(DeliveryError::Temporary(
                    "message requires chunked upload but no plan was produced".into(),
                )),
            };
        }

        // Too big for one call and no chunking on offer. Bouncing is safe: the
        // check above already let through everything that fits.
        Route::Reject(DeliveryError::Permanent(format!(
            "message is too large ({encoded} bytes encoded, limit is {}) and \
             canister {smtp} does not support chunked upload",
            self.upload_cfg.max_ingress_size
        )))
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

        // Issue the canister request and capabilities query concurrently
        let (res, _) = tokio::join!(
            self.request_executor
                .canister_request(dest.smtp, ic_smtp_request, true),
            self.capabilities(dest.smtp),
        );

        let res = res.map_err(|e| {
            if is_missing_method(&e) {
                RecipientResolveError::Permanent(format!(
                    "Canister {} does not support SMTP protocol",
                    dest.smtp
                ))
            } else {
                RecipientResolveError::Temporary(e.to_string())
            }
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

    /// Largest message this recipient's canister will take
    async fn recipient_max_message_size(&self, rcpt: &EmailAddress) -> Option<usize> {
        let lbl = rcpt.domain().labels().next()?;
        let canister_id = Principal::from_str(lbl)
            .ok()
            .or_else(|| self.custom_domains.lookup_custom_domain(rcpt.domain()))?;

        let smtp_canister_id = self.smtp_canister_id_cache.get(&canister_id)?;
        let caps = self.caps_cache.get(&smtp_canister_id)?;

        // Advertised max size or default otherwise
        caps.max_message_size
            .map_or(Some(self.upload_cfg.max_ingress_size), |v| Some(v as usize))
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

    use crate::smtp::ic::candid::SmtpUploadCommit;
    use crate::{
        email, principal,
        smtp::{
            SessionCounters,
            ic::candid::{Header, Message, SmtpOk, SmtpRequestError},
        },
    };
    use ic_agent::{AgentError, agent_error::HttpErrorPayload};
    use ic_transport_types::{RejectCode, RejectResponse};

    use super::*;
    use ahash::HashMap;
    use fqdn::{FQDN, fqdn};
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
            _latency: Duration,
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
        ];
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

    // =======================================================================
    // Chunked upload
    // =======================================================================

    use crate::smtp::ic::candid::{
        SMTP_UPLOAD_PROTOCOL_VERSION, SmtpUploadChunk, SmtpUploadChunkOk, SmtpUploadStatus,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    #[derive(Debug, Default, Clone)]
    struct Upload {
        envelope: Option<Envelope>,
        headers: Option<Vec<Header>>,
        total_chunks: u32,
        chunk_size: u64,
        body_size: u64,
        chunks: BTreeMap<u32, Vec<u8>>,
    }

    /// A test executor that actually implements the canister side of the
    /// protocol: it verifies each chunk's digest on arrival, enforces the shape
    /// invariants it must act on before the commit, reassembles at commit and
    /// re-derives the digest chain from what it stored. That makes the round-trip tests below real protocol tests rather
    /// than assertions about what the gateway happens to send.
    #[derive(Debug, Default)]
    struct ChunkingExecutor {
        caps: SmtpCapabilities,
        uploads: Mutex<HashMap<(Principal, String), Upload>>,
        /// Messages the canister considers delivered, as (canister, message, envelope).
        delivered: Mutex<Vec<(Principal, Message, Envelope)>>,
        /// Single-call deliveries, for asserting which path was taken.
        single_shot: Mutex<Vec<(Principal, SmtpRequest)>>,
        /// index -> how many more times to fail it transiently.
        fail_chunk: Mutex<HashMap<u32, usize>>,
        /// Chunk calls seen, including the failed attempts.
        chunk_calls: AtomicUsize,
        /// Reject every chunk with IC0536, as a canister that lied would.
        no_chunk_method: bool,
        /// Reject chunks from this index on with HTTP 429, as a rate-limiting
        /// replica would. Earlier chunks are stored, so there is a real partial
        /// upload for the retry to resume from.
        rate_limit_from: Option<u32>,
        /// Largest encoded call this executor has been handed.
        max_encoded: AtomicUsize,
    }

    impl ChunkingExecutor {
        fn with_caps(caps: SmtpCapabilities) -> Self {
            Self {
                caps,
                ..Default::default()
            }
        }

        fn chunking_caps() -> SmtpCapabilities {
            SmtpCapabilities {
                upload_protocol_version: Some(SMTP_UPLOAD_PROTOCOL_VERSION),
                max_message_size: Some(50 * 1024 * 1024),
            }
        }

        fn reject(code: u64, msg: &str) -> SmtpRequestError {
            SmtpRequestError {
                code,
                message: msg.into(),
            }
        }
    }

    #[async_trait]
    impl ExecutesIcSmtpRequest for ChunkingExecutor {
        async fn canister_request(
            &self,
            canister_id: Principal,
            request: SmtpRequest,
            validate: bool,
        ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
            if validate {
                return Ok(SmtpResponse::Ok(SmtpOk {}));
            }

            self.max_encoded
                .fetch_max(Encode!(&request).unwrap().len(), Ordering::SeqCst);
            self.single_shot
                .lock()
                .unwrap()
                .push((canister_id, request));
            Ok(SmtpResponse::Ok(SmtpOk {}))
        }

        async fn canister_capabilities(
            &self,
            _canister_id: Principal,
        ) -> Result<SmtpCapabilities, IcSmtpDeliveryAgentError> {
            Ok(self.caps.clone())
        }

        async fn canister_upload_chunk(
            &self,
            canister_id: Principal,
            chunk: &SmtpUploadChunk,
        ) -> Result<SmtpUploadChunkResponse, IcSmtpDeliveryAgentError> {
            self.chunk_calls.fetch_add(1, Ordering::SeqCst);
            self.max_encoded
                .fetch_max(Encode!(chunk).unwrap().len(), Ordering::SeqCst);

            if self.no_chunk_method {
                return Err(IcSmtpDeliveryAgentError::Agent(
                    AgentError::UncertifiedReject {
                        reject: RejectResponse {
                            reject_code: RejectCode::DestinationInvalid,
                            reject_message: "method does not exist".into(),
                            error_code: Some("IC0536".into()),
                        },
                        operation: None,
                    },
                ));
            }

            if self.rate_limit_from.is_some_and(|from| chunk.index >= from) {
                return Err(IcSmtpDeliveryAgentError::Agent(AgentError::HttpError(
                    HttpErrorPayload {
                        status: 429,
                        content_type: None,
                        content: vec![],
                    },
                )));
            }

            // Injected transient failure
            {
                let mut f = self.fail_chunk.lock().unwrap();
                if let Some(left) = f.get_mut(&chunk.index)
                    && *left > 0
                {
                    *left -= 1;
                    return Err(IcSmtpDeliveryAgentError::Agent(
                        AgentError::InvalidReplicaStatus,
                    ));
                }
            }

            if chunk.version != SMTP_UPLOAD_PROTOCOL_VERSION {
                return Ok(SmtpUploadChunkResponse::Err(Self::reject(
                    550,
                    "unsupported version",
                )));
            }

            // The canister verifies the payload digest BEFORE storing, so a
            // corrupt transfer costs one chunk rather than the whole upload.
            let digest: [u8; 32] = Sha256::digest(&chunk.payload).into();
            if digest.to_vec() != chunk.payload_sha256 {
                return Ok(SmtpUploadChunkResponse::Err(Self::reject(
                    550,
                    "chunk digest mismatch",
                )));
            }

            // Shape. The index has to be bounded BEFORE it is used in the
            // offset arithmetic below, which would otherwise underflow on a
            // malformed chunk - wrapping in release, trapping in a canister
            // built with overflow checks.
            let expected = u64::from(chunk.index)
                .checked_mul(chunk.chunk_size)
                .and_then(|offset| chunk.body_size.checked_sub(offset))
                .map(|left| chunk.chunk_size.min(left));

            if chunk.index >= chunk.total_chunks
                || expected != Some(chunk.payload.len() as u64)
                || chunk.headers.is_some() != (chunk.index == 0)
            {
                return Ok(SmtpUploadChunkResponse::Err(Self::reject(
                    550,
                    "malformed chunk",
                )));
            }

            let mut uploads = self.uploads.lock().unwrap();
            let up = uploads
                .entry((canister_id, chunk.message_id.clone()))
                .or_default();

            if up.total_chunks == 0 {
                up.total_chunks = chunk.total_chunks;
                up.chunk_size = chunk.chunk_size;
                up.body_size = chunk.body_size;
                up.envelope = Some(chunk.envelope.clone());
            } else if up.total_chunks != chunk.total_chunks
                || up.chunk_size != chunk.chunk_size
                || up.body_size != chunk.body_size
                || up.envelope.as_ref() != Some(&chunk.envelope)
            {
                // Two different messages collided on one message_id. 4xx, not
                // 5xx: `map_canister_error` turns 5xx into a permanent failure
                // and a collision is worth retrying.
                return Ok(SmtpUploadChunkResponse::Err(Self::reject(
                    450,
                    "inconsistent chunk",
                )));
            }

            if chunk.index == 0 {
                up.headers.clone_from(&chunk.headers);
            }
            up.chunks.insert(chunk.index, chunk.payload.clone());
            let chunks_received = up.chunks.len() as u32;
            drop(uploads);

            Ok(SmtpUploadChunkResponse::Ok(SmtpUploadChunkOk {
                chunks_received,
            }))
        }

        async fn canister_upload_commit(
            &self,
            canister_id: Principal,
            commit: SmtpUploadCommit,
        ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
            let up = {
                let mut uploads = self.uploads.lock().unwrap();
                match uploads.remove(&(canister_id, commit.message_id.clone())) {
                    Some(v) => v,
                    None => return Ok(SmtpResponse::Err(Self::reject(450, "unknown upload"))),
                }
            };

            if up.chunks.len() as u32 != commit.total_chunks
                || up.total_chunks != commit.total_chunks
            {
                return Ok(SmtpResponse::Err(Self::reject(450, "incomplete upload")));
            }

            // Re-derive the digest chain from the per-chunk digests, exactly as
            // the protocol specifies - O(total) rather than a second pass over
            // the whole body.
            let mut rolling = Sha256::new();
            let mut body = Vec::with_capacity(up.body_size as usize);
            for payload in up.chunks.values() {
                let d: [u8; 32] = Sha256::digest(payload).into();
                rolling.update(d);
                body.extend_from_slice(payload);
            }
            let derived: [u8; 32] = rolling.finalize().into();

            if derived.to_vec() != commit.body_sha256 {
                return Ok(SmtpResponse::Err(Self::reject(550, "body digest mismatch")));
            }
            if body.len() as u64 != up.body_size {
                return Ok(SmtpResponse::Err(Self::reject(550, "body size mismatch")));
            }

            self.delivered.lock().unwrap().push((
                canister_id,
                Message {
                    headers: up.headers.clone().unwrap_or_default(),
                    body,
                },
                up.envelope.clone().unwrap(),
            ));

            Ok(SmtpResponse::Ok(SmtpOk {}))
        }

        async fn canister_upload_status(
            &self,
            canister_id: Principal,
            upload: SmtpUploadId,
        ) -> Result<SmtpUploadStatusResponse, IcSmtpDeliveryAgentError> {
            let known = {
                let uploads = self.uploads.lock().unwrap();
                uploads.contains_key(&(canister_id, upload.message_id))
            };

            Ok(SmtpUploadStatusResponse::Ok(SmtpUploadStatus {
                known,
                ..Default::default()
            }))
        }

        async fn canister_upload_abort(
            &self,
            canister_id: Principal,
            upload: SmtpUploadId,
        ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
            self.uploads
                .lock()
                .unwrap()
                .remove(&(canister_id, upload.message_id));
            Ok(SmtpResponse::Ok(SmtpOk {}))
        }
    }

    /// Small ingress budget so tests can trigger chunking without
    /// multi-megabyte bodies.
    fn test_upload_cfg() -> IcSmtpUploadConfig {
        IcSmtpUploadConfig {
            max_ingress_size: 256 * 1024,
            chunk_size: 64 * 1024,
            max_inflight_bytes: 256 * 1024,
            global_concurrency: 4,
            chunk_retries: 2,
            delivery_timeout: Duration::from_secs(30),
            capabilities_cache_ttl: Duration::from_secs(600),
            max_header_size: 32 * 1024,
        }
    }

    fn create_chunking_agent(
        executor: Arc<ChunkingExecutor>,
        cfg: IcSmtpUploadConfig,
    ) -> IcSmtpDeliveryAgent {
        let resolver = TestDomainResolver(HashMap::from_iter([(
            fqdn!("foo.bar"),
            principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
        )]));

        let http_client = Arc::new(TestHttpClient(
            HashMap::default(),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ));

        IcSmtpDeliveryAgent::new(
            executor,
            Arc::new(resolver),
            http_client,
            "icp0.io",
            Duration::from_secs(10),
            10,
            Metrics::new(&Registry::new()),
            None,
        )
        .with_upload_config(cfg)
    }

    fn big_message(body_len: usize) -> EmailMessage {
        let mut raw =
            b"From: Some One <someone@example.com>\nTo: John Doe <john@doe.com>\nSubject: big\n\n"
                .to_vec();
        raw.extend((0..body_len).map(|i| (i % 251) as u8));

        EmailMessage {
            id: Uuid::nil(),
            mail_from: email!("john@doe.com"),
            rcpt_to: vec![email!("jane.doe@foo.bar")],
            body: raw.into(),
        }
    }

    fn test_meta() -> SessionMeta {
        SessionMeta {
            id: Uuid::nil(),
            message_id: Uuid::nil(),
            remote_ip: IpAddr::from_str("1.1.1.1").unwrap(),
            tls_info: None,
            ehlo_hostname: None,
            counters: SessionCounters::new(),
            last_error: None,
            mail_from: None,
            rcpt_to: vec![],
        }
    }

    /// The two delivery paths must produce an identical `Message`. This is the
    /// invariant nothing in the type system enforces, and the chunked path is
    /// the one that will be less exercised in production.
    #[tokio::test]
    async fn test_chunked_delivery_matches_single_shot_byte_for_byte() {
        let body_len = 300_000;

        // Chunked
        let chunked_exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        let agent = create_chunking_agent(chunked_exec.clone(), test_upload_cfg());
        agent
            .deliver_mail(test_meta(), Arc::new(big_message(body_len)))
            .await
            .unwrap();

        // Single-shot: same message, but a budget big enough to send it whole
        let single_exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        let agent = create_chunking_agent(
            single_exec.clone(),
            IcSmtpUploadConfig {
                max_ingress_size: 8 * 1024 * 1024,
                ..test_upload_cfg()
            },
        );
        agent
            .deliver_mail(test_meta(), Arc::new(big_message(body_len)))
            .await
            .unwrap();

        let delivered = chunked_exec.delivered.lock().unwrap().clone();
        assert_eq!(delivered.len(), 1, "chunked path must deliver exactly once");
        let (_, chunked_msg, chunked_env) = delivered[0].clone();

        let single_req = {
            let single = single_exec.single_shot.lock().unwrap();
            assert_eq!(single.len(), 1, "small message must take the single call");
            single[0].1.clone()
        };

        assert_eq!(chunked_msg, single_req.message.unwrap());
        assert_eq!(chunked_env, single_req.envelope.unwrap());
        assert_eq!(chunked_msg.body.len(), body_len);

        // ...and the chunked path really did chunk
        assert!(chunked_exec.chunk_calls.load(Ordering::SeqCst) > 1);
        assert!(chunked_exec.single_shot.lock().unwrap().is_empty());
    }

    /// No call the gateway builds may exceed the configured ingress limit.
    #[tokio::test]
    async fn test_no_call_exceeds_the_ingress_budget() {
        let cfg = test_upload_cfg();
        let exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        let agent = create_chunking_agent(exec.clone(), cfg.clone());

        agent
            .deliver_mail(test_meta(), Arc::new(big_message(1_000_000)))
            .await
            .unwrap();

        let max = exec.max_encoded.load(Ordering::SeqCst);
        assert!(max > 0);
        assert!(
            max <= cfg.max_ingress_size,
            "largest encoded call {max} exceeded the {} byte budget",
            cfg.max_ingress_size
        );
    }

    /// A transient chunk failure is retried, and the retry is a no-op for the
    /// canister because chunks are idempotent.
    #[tokio::test]
    async fn test_transient_chunk_failure_is_retried() {
        let exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        exec.fail_chunk.lock().unwrap().insert(2, 2);

        let agent = create_chunking_agent(exec.clone(), test_upload_cfg());
        agent
            .deliver_mail(test_meta(), Arc::new(big_message(300_000)))
            .await
            .unwrap();

        assert_eq!(exec.delivered.lock().unwrap().len(), 1);
        // 5 chunks + the 2 injected failures
        assert_eq!(exec.chunk_calls.load(Ordering::SeqCst), 7);
    }

    /// Exhausting the retries must be temporary, so the sender tries again
    /// later rather than the mail being bounced.
    #[tokio::test]
    async fn test_chunk_failure_beyond_retries_is_temporary() {
        let exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        exec.fail_chunk.lock().unwrap().insert(1, 99);

        let agent = create_chunking_agent(exec.clone(), test_upload_cfg());
        let err = agent
            .deliver_mail(test_meta(), Arc::new(big_message(300_000)))
            .await
            .unwrap_err();

        assert!(matches!(err, DeliveryError::Temporary(_)), "{err:?}");
        assert!(exec.delivered.lock().unwrap().is_empty());
    }

    /// A canister that advertises chunking but does not implement it must not
    /// bounce the mail, and the stale capabilities must be dropped so the
    /// sender's retry gets a clean answer.
    #[tokio::test]
    async fn test_lying_canister_invalidates_capabilities() {
        let exec = Arc::new(ChunkingExecutor {
            caps: ChunkingExecutor::chunking_caps(),
            no_chunk_method: true,
            ..Default::default()
        });

        let agent = create_chunking_agent(exec.clone(), test_upload_cfg());
        let err = agent
            .deliver_mail(test_meta(), Arc::new(big_message(300_000)))
            .await
            .unwrap_err();

        assert!(matches!(err, DeliveryError::Temporary(_)), "{err:?}");

        agent.caps_cache.run_pending_tasks();
        assert_eq!(
            agent.caps_cache.entry_count(),
            0,
            "stale capabilities must be invalidated"
        );
    }

    /// A legacy canister - the default trait bodies - keeps the single-call
    /// path for everything that fits, and an oversize message costs it zero
    /// canister calls rather than a partial delivery.
    #[tokio::test]
    async fn test_legacy_canister_never_sees_a_chunk() {
        let exec = Arc::new(ChunkingExecutor::default()); // no capabilities
        let agent = create_chunking_agent(exec.clone(), test_upload_cfg());

        // Small: single call, exactly as before
        agent
            .deliver_mail(test_meta(), Arc::new(big_message(1000)))
            .await
            .unwrap();
        assert_eq!(exec.single_shot.lock().unwrap().len(), 1);
        assert_eq!(exec.chunk_calls.load(Ordering::SeqCst), 0);

        // Far past the hard ingress limit: refused outright, and the canister is
        // never called at all.
        let err = agent
            .deliver_mail(test_meta(), Arc::new(big_message(2_000_000)))
            .await
            .unwrap_err();

        assert!(matches!(err, DeliveryError::Permanent(_)), "{err:?}");
        assert!(err.to_string().contains("does not support chunked upload"));
        assert_eq!(exec.single_shot.lock().unwrap().len(), 1, "no extra calls");
        assert_eq!(exec.chunk_calls.load(Ordering::SeqCst), 0);
    }

    /// A legacy canister keeps the single call for everything that fits the
    /// ingress budget, right up to the boundary. The routing threshold is the
    /// budget itself - no reserve is subtracted - so nothing that delivers
    /// today may start being chunked or refused.
    #[tokio::test]
    async fn test_legacy_canister_gets_the_single_call_up_to_the_limit() {
        let exec = Arc::new(ChunkingExecutor::default()); // legacy
        let cfg = test_upload_cfg();
        let agent = create_chunking_agent(exec.clone(), cfg.clone());

        // Just under the 256 KiB budget once headers and framing are counted
        let body_len = 250 * 1024;
        agent
            .deliver_mail(test_meta(), Arc::new(big_message(body_len)))
            .await
            .unwrap();

        let encoded = exec.max_encoded.load(Ordering::SeqCst);
        assert!(
            encoded <= cfg.max_ingress_size,
            "{encoded} exceeded the {} byte budget",
            cfg.max_ingress_size
        );
        assert_eq!(exec.single_shot.lock().unwrap().len(), 1);
        assert_eq!(exec.chunk_calls.load(Ordering::SeqCst), 0);
    }

    /// A canister that advertises a ceiling below the message size is a
    /// definite refusal, and must cost zero upload calls.
    #[tokio::test]
    async fn test_advertised_ceiling_is_enforced_before_uploading() {
        let exec = Arc::new(ChunkingExecutor::with_caps(SmtpCapabilities {
            max_message_size: Some(100_000),
            ..ChunkingExecutor::chunking_caps()
        }));

        let agent = create_chunking_agent(exec.clone(), test_upload_cfg());
        let err = agent
            .deliver_mail(test_meta(), Arc::new(big_message(300_000)))
            .await
            .unwrap_err();

        assert!(matches!(err, DeliveryError::Permanent(_)), "{err:?}");
        assert_eq!(exec.chunk_calls.load(Ordering::SeqCst), 0);
        assert!(exec.delivered.lock().unwrap().is_empty());
    }

    /// The RCPT TO hook must answer from cache only, and must reflect whether
    /// the destination can actually take a large message.
    #[tokio::test]
    async fn test_recipient_max_message_size_reads_the_caches() {
        let exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        let agent = create_chunking_agent(exec, test_upload_cfg());
        let rcpt = email!("jane.doe@foo.bar");

        // Nothing resolved yet, so nothing is enforced
        assert_eq!(agent.recipient_max_message_size(&rcpt).await, None);

        agent
            .resolve_recipient(&email!("john@doe.com"), &rcpt)
            .await
            .unwrap();

        assert_eq!(
            agent.recipient_max_message_size(&rcpt).await,
            Some(50 * 1024 * 1024)
        );
    }

    /// A rate-limited replica must not be sent an abort on top: the canister
    /// expires the upload on its own. Any other failure releases it explicitly.
    #[tokio::test]
    async fn test_rate_limited_upload_is_left_for_a_retry() {
        // No retries, so the test does not sit through the backoff
        let cfg = IcSmtpUploadConfig {
            chunk_retries: 0,
            ..test_upload_cfg()
        };

        // Rate limited: the partial upload survives
        let exec = Arc::new(ChunkingExecutor {
            caps: ChunkingExecutor::chunking_caps(),
            rate_limit_from: Some(2),
            ..Default::default()
        });
        let agent = create_chunking_agent(exec.clone(), cfg.clone());

        let err = agent
            .deliver_mail(test_meta(), Arc::new(big_message(300_000)))
            .await
            .unwrap_err();
        assert!(matches!(err, DeliveryError::Temporary(_)), "{err:?}");

        // Chunks before the rate limit did land, so there is something to keep
        assert!(exec.chunk_calls.load(Ordering::SeqCst) >= 3);

        // Give any spawned abort a chance to run before asserting it did not
        tokio::time::sleep(Duration::from_millis(100)).await;
        let kept_chunks = {
            let uploads = exec.uploads.lock().unwrap();
            uploads
                .values()
                .next()
                .expect("a rate-limited upload must be left in place to resume")
                .chunks
                .len()
        };
        assert!(
            kept_chunks > 0,
            "the chunks that did land must be preserved"
        );

        // A non-transient failure releases the space instead
        let exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        exec.fail_chunk.lock().unwrap().insert(1, 99);
        let agent = create_chunking_agent(exec.clone(), cfg);

        let err = agent
            .deliver_mail(test_meta(), Arc::new(big_message(300_000)))
            .await
            .unwrap_err();
        assert!(matches!(err, DeliveryError::Temporary(_)), "{err:?}");

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            exec.uploads.lock().unwrap().is_empty(),
            "an abandoned upload must be released"
        );
    }

    /// Two recipients that resolve to different `DestCanister`s but the same
    /// SMTP canister must be delivered as ONE upload carrying both.
    ///
    /// Before they were merged this produced two concurrent uploads under the
    /// same `(caller, message_id)` with different envelopes - which a canister
    /// checking cross-chunk consistency rejects, and whose abort then removed
    /// the other upload as well.
    #[tokio::test]
    async fn test_recipients_sharing_an_smtp_canister_are_merged() {
        let shared = principal!("6hsbt-vqaaa-aaaaf-aaafq-cai");
        let via_custom_domain = principal!("qoctq-giaaa-aaaaa-aaaea-cai");
        let addressed_directly = principal!("gjxif-ryaaa-aaaad-ae4ka-cai");

        // `foo.bar` is a custom domain for one canister, the other is addressed
        // as `<principal>.icp0.io`. Both delegate their SMTP to `shared`.
        let resolver =
            TestDomainResolver(HashMap::from_iter([(fqdn!("foo.bar"), via_custom_domain)]));

        let http_client = Arc::new(TestHttpClient(
            HashMap::from_iter([(via_custom_domain, shared), (addressed_directly, shared)]),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        ));

        let exec = Arc::new(ChunkingExecutor::with_caps(
            ChunkingExecutor::chunking_caps(),
        ));
        let agent = IcSmtpDeliveryAgent::new(
            exec.clone(),
            Arc::new(resolver),
            http_client,
            "icp0.io",
            Duration::from_secs(10),
            10,
            Metrics::new(&Registry::new()),
            None,
        )
        .with_upload_config(test_upload_cfg());

        let rcpt_a = email!("a@foo.bar");
        let rcpt_b = email!("b@gjxif-ryaaa-aaaad-ae4ka-cai.icp0.io");

        // Guard the premise: these must be two DISTINCT `DestCanister`s that
        // nonetheless share an SMTP canister, otherwise the test would pass
        // trivially without exercising the merge at all.
        let dest_a = agent.resolve_canister_id(&rcpt_a).await.unwrap();
        let dest_b = agent.resolve_canister_id(&rcpt_b).await.unwrap();
        assert_ne!(dest_a, dest_b, "the two destinations must differ");
        assert_eq!(dest_a.smtp, shared);
        assert_eq!(dest_b.smtp, shared);

        let message = EmailMessage {
            rcpt_to: vec![rcpt_a, rcpt_b],
            ..big_message(300_000)
        };

        agent
            .deliver_mail(test_meta(), Arc::new(message))
            .await
            .unwrap();

        let delivered = exec.delivered.lock().unwrap().clone();
        assert_eq!(
            delivered.len(),
            1,
            "one SMTP canister must receive exactly one message"
        );

        let (canister, _, envelope) = delivered[0].clone();
        assert_eq!(canister, shared);

        // ...carrying both recipients
        let mut users = envelope
            .to
            .iter()
            .map(|a| a.user.clone())
            .collect::<Vec<_>>();
        users.sort();
        assert_eq!(users, vec!["a".to_string(), "b".to_string()]);

        // ...and the body was uploaded once, not once per `DestCanister`
        assert_eq!(exec.chunk_calls.load(Ordering::SeqCst), 5);
    }

    fn tiny_envelope() -> Envelope {
        Envelope {
            from: email!("john@doe.com").into(),
            to: vec![email!("jane@foo.bar").into()],
        }
    }

    /// The commit's digest is now the ONLY check with truth value about the
    /// body, so prove it actually fires. Every other test drives it with a
    /// correct gateway, where it never can.
    #[tokio::test]
    async fn test_commit_verifies_the_derived_digest() {
        use crate::smtp::ic::candid::SHA256_LEN;

        let exec = ChunkingExecutor::with_caps(ChunkingExecutor::chunking_caps());
        let canister = principal!("aaaaa-aa");
        let env = tiny_envelope();
        let hdrs = vec![Header {
            name: "Subject".into(),
            value: " hi\n".into(),
        }];
        let body = bytes::Bytes::from(vec![7u8; 4096]);

        let plan = plan_chunks(&hdrs, &env, "mid", &body, 256 * 1024, 1024).unwrap();
        assert!(plan.total_chunks > 1);

        for i in 0..plan.total_chunks {
            let chunk = build_chunk(&plan, i, &body, &hdrs, &env, "mid", None);
            assert!(matches!(
                exec.canister_upload_chunk(canister, &chunk).await.unwrap(),
                SmtpUploadChunkResponse::Ok(_)
            ));
        }

        // Every chunk was stored and verified, but the commit asserts a digest
        // that does not match what the canister derived.
        let mut commit = build_commit(&plan, "mid");
        commit.body_sha256 = vec![0u8; SHA256_LEN];

        let resp = exec.canister_upload_commit(canister, commit).await.unwrap();
        assert!(
            matches!(&resp, SmtpResponse::Err(e) if e.code == 550),
            "{resp:?}"
        );
        assert!(exec.delivered.lock().unwrap().is_empty());
    }

    /// An out-of-range index must be rejected, not used in the offset
    /// arithmetic - which would underflow `u64` and trap a real canister.
    #[tokio::test]
    async fn test_malformed_chunk_index_does_not_underflow() {
        let exec = ChunkingExecutor::with_caps(ChunkingExecutor::chunking_caps());

        let chunk = SmtpUploadChunk {
            version: crate::smtp::ic::candid::SMTP_UPLOAD_PROTOCOL_VERSION,
            message_id: "mid".into(),
            envelope: tiny_envelope(),
            // index * chunk_size is far past body_size
            index: u32::MAX,
            total_chunks: 4,
            chunk_size: 1024,
            body_size: 100,
            payload_sha256: Sha256::digest([]).to_vec(),
            payload: vec![],
            headers: None,
            gateway_flags: None,
        };

        let resp = exec
            .canister_upload_chunk(principal!("aaaaa-aa"), &chunk)
            .await
            .unwrap();

        assert!(
            matches!(&resp, SmtpUploadChunkResponse::Err(e) if e.code == 550),
            "{resp:?}"
        );
        assert!(exec.uploads.lock().unwrap().is_empty());
    }

    /// A chunk that disagrees with the upload it is joining is retryable, not a
    /// bounce: `map_canister_error` turns 5xx into a permanent failure.
    #[tokio::test]
    async fn test_inconsistent_chunk_is_temporary() {
        let exec = ChunkingExecutor::with_caps(ChunkingExecutor::chunking_caps());
        let canister = principal!("aaaaa-aa");
        let hdrs = vec![Header {
            name: "Subject".into(),
            value: " hi\n".into(),
        }];
        let body = bytes::Bytes::from(vec![7u8; 4096]);
        let plan = plan_chunks(&hdrs, &tiny_envelope(), "mid", &body, 256 * 1024, 1024).unwrap();

        let first = build_chunk(&plan, 0, &body, &hdrs, &tiny_envelope(), "mid", None);
        exec.canister_upload_chunk(canister, &first).await.unwrap();

        // Same message_id, different envelope: a collision between two messages
        let other_env = Envelope {
            from: email!("john@doe.com").into(),
            to: vec![email!("someone.else@foo.bar").into()],
        };
        let clashing = build_chunk(&plan, 1, &body, &hdrs, &other_env, "mid", None);

        let resp = exec
            .canister_upload_chunk(canister, &clashing)
            .await
            .unwrap();

        let SmtpUploadChunkResponse::Err(e) = resp else {
            panic!("expected the clashing chunk to be rejected");
        };
        assert_eq!(e.code, 450, "a collision must be retryable, not a bounce");
        assert!(matches!(
            map_canister_error(&e),
            DeliveryError::Temporary(_)
        ));
    }
}
