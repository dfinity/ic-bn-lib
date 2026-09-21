//! # Canister Client
//!
//! This module provides a client for interacting with the custom domains canister.
//! It handles all communication, serialization, encryption, and error handling.

use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use derive_new::new;
use fqdn::FQDN;
use ic_custom_domains_canister_api::{
    CertificatesPage, DomainStatus as DomainStatusApi, FetchTaskError, GetDomainStatusError,
    GetLastChangeTimeError, HasNextTaskError, InputTask as InputTaskApi, ListCertificatesPageError,
    ListCertificatesPageInput, ScheduledTask as ScheduledTaskApi, SubmitTaskError,
    TaskResult as TaskResultApi, TryAddTaskError,
};
use tokio::{
    select,
    time::{interval, sleep},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument, warn};

use crate::{
    DurationDisplay,
    custom_domains::{
        CustomDomain, ProvidesCustomDomains,
        base::{
            traits::{
                cipher::CiphersCertificates,
                repository::{Repository, RepositoryError},
                time::UtcTimestamp,
            },
            types::{
                domain::{DomainStatus, RegisteredDomain},
                task::{InputTask, ScheduledTask, TaskOutcome, TaskOutput, TaskResult},
            },
        },
        flags::DomainFlags,
    },
    ic_agent::Agent,
    tasks::Run,
    tls::{Pem, ProvidesCertificates},
};

#[derive(new)]
pub struct CanisterClient {
    agent: Agent,
    canister_id: Principal,
    certificate_cipher: Arc<dyn CiphersCertificates>,
    poll_interval: Duration,
    refresh_interval: Duration,
    priority: u8,
    custom_domain_flags: Option<DomainFlags>,
    #[new(default)]
    last_change_time: AtomicU64,
    #[new(default)]
    certificates: ArcSwap<Vec<Pem>>,
    #[new(default)]
    custom_domains: ArcSwap<Vec<CustomDomain>>,
}

impl std::fmt::Debug for CanisterClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CanisterClient({})", self.canister_id)
    }
}

impl CanisterClient {
    /// Fetch and cache registrations if changes happened
    async fn update_cache_conditional(&self) -> Result<(), anyhow::Error> {
        let last_change = self.get_last_change_time().await?;
        let cached_timestamp = self.last_change_time.load(Ordering::SeqCst);

        if last_change == cached_timestamp {
            return Ok(());
        }

        self.update_cache(Some(last_change), true).await
    }

    /// Fetch and cache registrations
    async fn update_cache(
        &self,
        last_change: Option<u64>,
        use_update: bool,
    ) -> Result<(), anyhow::Error> {
        // TODO update canister to send last change together with domains?
        let last_change = if let Some(v) = last_change {
            v
        } else {
            self.get_last_change_time().await?
        };

        let (certificates, custom_domains) = self
            .fetch_data(use_update)
            .await
            .context("unable to fetch registrations data")?;

        // Update cache
        self.certificates.store(Arc::new(certificates));
        self.custom_domains.store(Arc::new(custom_domains));
        self.last_change_time.store(last_change, Ordering::SeqCst);

        info!("Cache updated: {} certs", self.certificates.load().len());
        Ok(())
    }

    /// Fetch & convert registrations
    async fn fetch_data(
        &self,
        use_update: bool,
    ) -> Result<(Vec<Pem>, Vec<CustomDomain>), anyhow::Error> {
        let domains = self.all_registrations(use_update).await?;

        let mut certificates = Vec::with_capacity(domains.len());
        let mut custom_domains = Vec::with_capacity(domains.len());

        for d in domains {
            certificates.push(Pem([d.cert, d.priv_key].concat()));
            custom_domains.push(CustomDomain {
                name: d.domain,
                canister_id: d.canister_id,
                timestamp: 0,
                priority: self.priority,
                flags: self.custom_domain_flags,
            });
        }

        Ok((certificates, custom_domains))
    }

    /// Encrypts sensitive data before sending it to canister
    fn encrypt_field(&self, field_name: &str, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher.encrypt(data).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to encrypt {field_name}: {err}"))
        })
    }

    /// Decrypts sensitive data received from canister
    fn decrypt_field(&self, data: &[u8]) -> Result<Vec<u8>, RepositoryError> {
        self.certificate_cipher
            .decrypt(data)
            .map_err(|err| RepositoryError::InternalError(anyhow!("Failed to decrypt data: {err}")))
    }

    /// Makes a query call to the canister, decodes the response, and handles canister API errors
    async fn query<T, R, E>(&self, method: &str, args: &T) -> Result<R, RepositoryError>
    where
        T: CandidType + Sync,
        R: for<'de> Deserialize<'de> + CandidType,
        E: for<'de> Deserialize<'de> + CandidType + std::fmt::Debug,
        RepositoryError: TryFrom<E>,
    {
        let arg = Encode!(args).map_err(|err| {
            RepositoryError::InternalError(anyhow!(
                "Failed to encode arguments for {method}: {err}"
            ))
        })?;

        let result = self
            .agent
            .query(&self.canister_id, method)
            .with_arg(arg)
            .call()
            .await
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Canister query {method} failed: {err}"))
            })?;

        let response = Decode!(&result, Result<R, E>).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to decode {method} response: {err}"))
        })?;

        response.map_err(|err| {
            let err_debug = format!("{err:?}");
            RepositoryError::try_from(err).unwrap_or_else(|_| {
                RepositoryError::InternalError(anyhow!(
                    "Failed to convert canister error: {err_debug}"
                ))
            })
        })
    }

    /// Makes an update call to the canister, decodes the response, and handles canister API errors
    async fn update<T, R, E>(&self, method: &str, args: &T) -> Result<R, RepositoryError>
    where
        T: CandidType + Sync,
        R: for<'de> Deserialize<'de> + CandidType + std::fmt::Debug,
        E: for<'de> Deserialize<'de> + CandidType + std::fmt::Debug,
        RepositoryError: TryFrom<E>,
    {
        let arg = Encode!(args).map_err(|err| {
            RepositoryError::InternalError(anyhow!(
                "Failed to encode arguments for {method}: {err}"
            ))
        })?;

        let result = self
            .agent
            .update(&self.canister_id, method)
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(|err| {
                RepositoryError::InternalError(anyhow!("Canister update {method} failed: {err}"))
            })?;

        let response = Decode!(&result, Result<R, E>).map_err(|err| {
            RepositoryError::InternalError(anyhow!("Failed to decode {method} response: {err}"))
        })?;

        response.map_err(|err| {
            let err_debug = format!("{err:?}");
            RepositoryError::try_from(err).unwrap_or_else(|_| {
                RepositoryError::InternalError(anyhow!(
                    "Failed to convert canister error: {err_debug}"
                ))
            })
        })
    }
}

#[async_trait]
impl Repository for CanisterClient {
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError> {
        let response = self
            .query::<String, Option<DomainStatusApi>, GetDomainStatusError>(
                "get_domain_status",
                &domain.to_string(),
            )
            .await?;

        match response {
            None => Ok(None),
            Some(api_status) => {
                let status = DomainStatus::try_from(api_status).map_err(|err| {
                    RepositoryError::InternalError(anyhow!(
                        "Failed to convert domain status: {err}"
                    ))
                })?;
                Ok(Some(status))
            }
        }
    }

    async fn has_next_task(&self) -> Result<bool, RepositoryError> {
        let response = self
            .query::<(), bool, HasNextTaskError>("has_next_task", &())
            .await?;

        Ok(response)
    }

    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError> {
        let has_next_task = self
            .query::<(), bool, HasNextTaskError>("has_next_task", &())
            .await?;

        if !has_next_task {
            return Ok(None);
        }

        let response = self
            .update::<(), Option<ScheduledTaskApi>, FetchTaskError>("fetch_next_task", &())
            .await?;

        match response {
            None => Ok(None),
            Some(api_task) => {
                // Decrypt certificate if present
                let certificate = api_task
                    .enc_cert
                    .map(|encrypted_cert| self.decrypt_field(encrypted_cert.as_slice()))
                    .transpose()?;

                let domain = FQDN::from_str(&api_task.domain).map_err(|err| {
                    RepositoryError::InternalError(anyhow!("Invalid domain from canister: {err}"))
                })?;

                let task = ScheduledTask::new(
                    api_task.kind.into(),
                    domain,
                    api_task.id,
                    certificate,
                    api_task.wildcard.unwrap_or(false),
                    api_task.canister_id,
                );
                Ok(Some(task))
            }
        }
    }

    async fn submit_task_result(&self, mut task_result: TaskResult) -> Result<(), RepositoryError> {
        // We encrypt certificate and private_key and pass the result further to the canister.
        if let TaskOutcome::Success(TaskOutput::Issue(issued_certificate)) =
            &mut task_result.outcome
        {
            issued_certificate.cert =
                self.encrypt_field("certificate", &issued_certificate.cert)?;

            issued_certificate.priv_key =
                self.encrypt_field("private key", &issued_certificate.priv_key)?;
        }

        self.update::<TaskResultApi, (), SubmitTaskError>(
            "submit_task_result",
            &TaskResultApi::from(task_result),
        )
        .await
    }

    async fn try_add_task(&self, input_task: InputTask) -> Result<(), RepositoryError> {
        let response = self
            .update::<InputTaskApi, (), TryAddTaskError>(
                "try_add_task",
                &InputTaskApi::from(input_task),
            )
            .await;

        response?;

        Ok(())
    }

    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError> {
        let response = self
            .query::<(), UtcTimestamp, GetLastChangeTimeError>("get_last_change_time", &())
            .await?;

        Ok(response)
    }

    async fn all_registrations(
        &self,
        use_update: bool,
    ) -> Result<Vec<RegisteredDomain>, RepositoryError> {
        let mut registered_domains = vec![];
        let mut start_key = None;

        loop {
            let response = if use_update {
                self.update::<ListCertificatesPageInput, CertificatesPage, ListCertificatesPageError>(
                    "list_certificates_page",
                    &ListCertificatesPageInput {
                        start_key,
                        limit: None,
                    },
                )
                .await?
            } else {
                self.query::<ListCertificatesPageInput, CertificatesPage, ListCertificatesPageError>(
                        "list_certificates_page",
                        &ListCertificatesPageInput {
                            start_key,
                            limit: None,
                        },
                    )
                    .await?
            };

            let registrations = response
                .items
                .into_iter()
                .map(|mut reg| {
                    reg.enc_cert = self.decrypt_field(&reg.enc_cert)?;
                    reg.enc_priv_key = self.decrypt_field(&reg.enc_priv_key)?;

                    RegisteredDomain::try_from(reg).map_err(|err| {
                        RepositoryError::InternalError(anyhow!(
                            "Failed to convert RegisteredDomain: {err}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            registered_domains.extend(registrations);
            start_key = response.next_key;

            if start_key.is_none() {
                break;
            }
        }

        Ok(registered_domains)
    }
}

#[async_trait]
impl ProvidesCertificates for CanisterClient {
    async fn get_certificates(&self) -> Result<Vec<Pem>, crate::tls::Error> {
        Ok(self.certificates.load().as_ref().clone())
    }
}

#[async_trait]
impl ProvidesCustomDomains for CanisterClient {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, anyhow::Error> {
        Ok(self.custom_domains.load().as_ref().clone())
    }
}

#[async_trait]
impl Run for CanisterClient {
    #[instrument(skip_all, name = "canister_client")]
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        // Wait a bit until the rest is initialized
        // TODO get rid of
        sleep(Duration::from_secs(15)).await;

        let mut interval_poll = interval(self.poll_interval);
        interval_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut interval_refresh = interval(self.refresh_interval);
        interval_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        warn!(
            "Started polling every {}, full refresh every {}",
            self.poll_interval.display(),
            self.refresh_interval.display()
        );

        loop {
            select! {
                biased;

                () = token.cancelled() => {
                    warn!("{self:?}: stopping");
                    return Ok(())
                },

                _ = interval_refresh.tick() => {
                    if let Err(e) = self.update_cache(None, false).await {
                        warn!("Unable to refresh data: {e:#}");
                    }
                }

                _ = interval_poll.tick() => {
                    if let Err(e) = self.update_cache_conditional().await {
                        warn!("Unable to poll for changes: {e:#}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::{HashMap, VecDeque},
        net::SocketAddr,
        sync::Mutex,
    };

    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{StatusCode, Uri, header::CONTENT_TYPE},
        response::{IntoResponse, Response},
    };
    use axum_server::tls_rustls::RustlsConfig;
    use fqdn::fqdn;
    use ic_custom_domains_canister_api::{
        RegisteredDomain as RegisteredDomainApi, RegistrationStatus as RegistrationStatusApi,
        TaskKind as TaskKindApi, TaskOutcome as TaskOutcomeApi, TaskOutput as TaskOutputApi,
    };
    use ic_transport_types::{
        Envelope, EnvelopeContent, QueryResponse, RejectCode, RejectResponse, ReplyResponse,
    };

    use super::*;
    use crate::{
        custom_domains::{
            base::{
                traits::cipher::CipherError,
                types::{
                    domain::RegistrationStatus,
                    task::{IssueCertificateOutput, TaskFailReason, TaskKind},
                },
            },
            flags::FLAG_TEST,
        },
        principal,
        tests::{TEST_CERT_1, TEST_KEY_1},
    };

    const CANISTER_ID: &str = "qoctq-giaaa-aaaaa-aaaea-cai";
    /// Prefix that [`PrefixCipher`] adds on encryption and strips on decryption.
    const ENC: &[u8] = b"ENC:";
    /// A syntactically invalid domain name (the space is not allowed in a label).
    const BAD_DOMAIN: &str = "exa mple.com";

    // ---------------------------------------------------------------------------------------
    // Cipher test doubles
    // ---------------------------------------------------------------------------------------

    /// Reversible, observable stand-in for the real cipher: encryption prepends a marker and
    /// decryption removes it, so tests can tell whether data went through the cipher at all
    /// and in which direction.
    #[derive(Debug)]
    struct PrefixCipher;

    impl CiphersCertificates for PrefixCipher {
        fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherError> {
            Ok([ENC, data].concat())
        }

        fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CipherError> {
            encrypted_data
                .strip_prefix(ENC)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| CipherError::DecryptionFailed("missing marker".into()))
        }
    }

    /// Cipher that always fails, to exercise the error-mapping paths.
    #[derive(Debug)]
    struct FailingCipher;

    impl CiphersCertificates for FailingCipher {
        fn encrypt(&self, _: &[u8]) -> Result<Vec<u8>, CipherError> {
            Err(CipherError::EncryptionFailed("no key".into()))
        }

        fn decrypt(&self, _: &[u8]) -> Result<Vec<u8>, CipherError> {
            Err(CipherError::DecryptionFailed("no key".into()))
        }
    }

    // ---------------------------------------------------------------------------------------
    // Mock replica
    // ---------------------------------------------------------------------------------------

    /// What the mock replica answers for the next call of a given method.
    enum Reply {
        /// A successful reply carrying a Candid-encoded `Result<R, E>`
        Candid(Vec<u8>),
        /// A replica-level rejection of the call
        Reject(String),
        /// HTTP 200 with a body that is not valid CBOR
        NotCbor,
        /// An HTTP-level failure
        Status(StatusCode),
    }

    /// A single request that reached the mock replica.
    #[derive(Clone)]
    struct RecordedCall {
        /// Canister ID as taken from the request path (verifies URL construction)
        canister: String,
        method: String,
        /// Raw Candid-encoded argument blob
        arg: Vec<u8>,
        /// `true` for the update (`/call`) endpoint, `false` for `/query`
        update: bool,
    }

    #[derive(Default)]
    struct MockState {
        replies: HashMap<String, VecDeque<Reply>>,
        calls: Vec<RecordedCall>,
    }

    /// Owned snapshot of the calls the mock recorded. [`Mock::state`] returns one of these
    /// rather than the `MutexGuard` itself, so assertions never keep the lock alive across a
    /// later `.await` (clippy::await_holding_lock / clippy::significant_drop_tightening).
    struct Calls {
        calls: Vec<RecordedCall>,
    }

    impl Calls {
        /// Names of the called canister methods, in call order.
        fn methods(&self) -> Vec<&str> {
            self.calls.iter().map(|x| x.method.as_str()).collect()
        }

        /// Candid-decodes the argument of the n-th recorded call.
        fn arg<T: CandidType + for<'de> Deserialize<'de>>(&self, idx: usize) -> T {
            Decode!(&self.calls[idx].arg, T).expect("argument does not decode")
        }
    }

    type Shared = Arc<Mutex<MockState>>;

    struct Mock {
        state: Shared,
        url: String,
    }

    impl Mock {
        /// Spawns an HTTPS mock replica on a random loopback port.
        async fn start() -> Self {
            // rustls 0.23+ needs a process-wide provider; idempotent.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            let state: Shared = Arc::new(Mutex::new(MockState::default()));
            let router = Router::new().fallback(handler).with_state(state.clone());

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr: SocketAddr = listener.local_addr().unwrap();

            let config = RustlsConfig::from_pem(
                TEST_CERT_1.as_bytes().to_vec(),
                TEST_KEY_1.as_bytes().to_vec(),
            )
            .await
            .unwrap();

            tokio::spawn(async move {
                axum_server::from_tcp_rustls(listener, config)
                    .unwrap()
                    .serve(router.into_make_service())
                    .await
                    .unwrap();
            });

            Self {
                state,
                url: format!("https://{addr}/"),
            }
        }

        fn push(&self, method: &str, reply: Reply) {
            self.state
                .lock()
                .unwrap()
                .replies
                .entry(method.to_string())
                .or_default()
                .push_back(reply);
        }

        /// Programs the Candid-encoded `Result` that `method` will return next.
        fn reply<R: CandidType, E: CandidType>(&self, method: &str, res: Result<R, E>) {
            self.push(method, Reply::Candid(Encode!(&res).unwrap()));
        }

        fn state(&self) -> Calls {
            Calls {
                calls: self.state.lock().unwrap().calls.clone(),
            }
        }

        fn methods(&self) -> Vec<String> {
            self.state()
                .methods()
                .into_iter()
                .map(ToString::to_string)
                .collect()
        }

        fn client(&self, cipher: Arc<dyn CiphersCertificates>) -> CanisterClient {
            client_at(&self.url, cipher)
        }
    }

    fn cbor(response: &QueryResponse) -> Response {
        (
            [(CONTENT_TYPE, "application/cbor")],
            serde_cbor::to_vec(response).unwrap(),
        )
            .into_response()
    }

    /// Single handler for every replica endpoint: the path shape (`.../canister/<id>/query`
    /// vs `.../call`) is derived from the URI so the mock doesn't hardcode the API version.
    async fn handler(State(state): State<Shared>, uri: Uri, body: Bytes) -> Response {
        let path = uri.path();
        let update = path.ends_with("/call");
        let canister = path.rsplit('/').nth(1).unwrap_or_default().to_string();

        let Ok(envelope) = serde_cbor::from_slice::<Envelope>(&body) else {
            return (StatusCode::BAD_REQUEST, "not a CBOR envelope").into_response();
        };

        let (method, arg) = match &*envelope.content {
            EnvelopeContent::Query {
                method_name, arg, ..
            }
            | EnvelopeContent::Call {
                method_name, arg, ..
            } => (method_name.clone(), arg.clone()),
            EnvelopeContent::ReadState { .. } => {
                return (StatusCode::BAD_REQUEST, "read_state is not mocked").into_response();
            }
        };

        let reply = {
            let mut state = state.lock().unwrap();
            state.calls.push(RecordedCall {
                canister,
                method: method.clone(),
                arg,
                update,
            });
            state.replies.get_mut(&method).and_then(VecDeque::pop_front)
        };

        match reply {
            Some(Reply::Candid(arg)) => cbor(&QueryResponse::Replied {
                reply: ReplyResponse { arg },
                signatures: vec![],
            }),
            Some(Reply::Reject(msg)) => cbor(&QueryResponse::Rejected {
                reject: RejectResponse {
                    reject_code: RejectCode::CanisterReject,
                    reject_message: msg,
                    error_code: None,
                },
                signatures: vec![],
            }),
            Some(Reply::NotCbor) => (StatusCode::OK, "definitely not cbor").into_response(),
            Some(Reply::Status(code)) => (code, "mock failure").into_response(),
            // Nothing programmed: fail fast at the HTTP layer so the client errors out
            // instead of hanging (this is also how update calls are made to fail).
            None => (
                StatusCode::BAD_REQUEST,
                format!("no reply programmed for {method}"),
            )
                .into_response(),
        }
    }

    /// `reqwest` client that trusts the self-signed test certificate.
    fn insecure_client() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            // Avoid reusing connections that the mock may have torn down.
            .pool_max_idle_per_host(0)
            .build()
            .unwrap()
    }

    fn client_at(url: &str, cipher: Arc<dyn CiphersCertificates>) -> CanisterClient {
        let agent = Agent::builder()
            .with_url(url)
            .with_http_client(insecure_client())
            // Our mock cannot produce node signatures.
            .with_verify_query_signatures(false)
            .build()
            .unwrap();

        CanisterClient::new(
            agent,
            principal!(CANISTER_ID),
            cipher,
            Duration::from_secs(60),
            Duration::from_secs(600),
            7,
            Some(DomainFlags::new([FLAG_TEST])),
        )
    }

    fn api_status(domain: &str, status: RegistrationStatusApi) -> DomainStatusApi {
        DomainStatusApi {
            domain: domain.to_string(),
            canister_id: Some(principal!("aaaaa-aa")),
            status,
        }
    }

    fn api_domain(domain: &str, suffix: &str) -> RegisteredDomainApi {
        RegisteredDomainApi {
            domain: domain.to_string(),
            canister_id: principal!("aaaaa-aa"),
            enc_cert: [ENC, b"CERT-", suffix.as_bytes()].concat(),
            enc_priv_key: [ENC, b"KEY-", suffix.as_bytes()].concat(),
        }
    }

    // ---------------------------------------------------------------------------------------
    // Debug
    // ---------------------------------------------------------------------------------------

    #[test]
    fn debug_shows_only_the_canister_id() {
        let client = client_at("https://127.0.0.1:1/", Arc::new(PrefixCipher));
        assert_eq!(
            format!("{client:?}"),
            format!("CanisterClient({CANISTER_ID})")
        );
    }

    // ---------------------------------------------------------------------------------------
    // get_domain_status
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn get_domain_status_sends_the_domain_and_converts_the_reply() {
        let mock = Mock::start().await;
        mock.reply::<_, GetDomainStatusError>(
            "get_domain_status",
            Ok(Some(api_status(
                "my.example.com",
                RegistrationStatusApi::Failed("boom".into()),
            ))),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let status = client
            .get_domain_status(&fqdn!("my.example.com"))
            .await
            .unwrap()
            .expect("expected a status");

        assert_eq!(status.domain, fqdn!("my.example.com"));
        assert_eq!(status.canister_id, Some(principal!("aaaaa-aa")));
        // The internal type keeps the real failure reason; only serialization redacts it.
        assert_eq!(status.status, RegistrationStatus::Failed("boom".into()));

        let state = mock.state();
        assert_eq!(state.methods(), ["get_domain_status"]);
        assert_eq!(state.calls[0].canister, CANISTER_ID);
        assert!(!state.calls[0].update, "must be a query, not an update");
        assert_eq!(state.arg::<String>(0), "my.example.com");
    }

    #[tokio::test]
    async fn get_domain_status_returns_none_for_unknown_domain() {
        let mock = Mock::start().await;
        mock.reply::<Option<DomainStatusApi>, GetDomainStatusError>("get_domain_status", Ok(None));

        let client = mock.client(Arc::new(PrefixCipher));
        assert!(
            client
                .get_domain_status(&fqdn!("example.com"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn get_domain_status_rejects_a_malformed_domain_from_the_canister() {
        let mock = Mock::start().await;
        mock.reply::<_, GetDomainStatusError>(
            "get_domain_status",
            Ok(Some(api_status(BAD_DOMAIN, RegistrationStatusApi::Expired))),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client
            .get_domain_status(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(
            matches!(err, RepositoryError::InternalError(_)),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("Failed to convert domain status"),
            "unexpected error: {err}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Canister / transport error mapping
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn canister_error_is_mapped_to_a_typed_repository_error() {
        let mock = Mock::start().await;
        mock.reply::<Option<DomainStatusApi>, _>(
            "get_domain_status",
            Err(GetDomainStatusError::Unauthorized),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client
            .get_domain_status(&fqdn!("example.com"))
            .await
            .unwrap_err();

        assert!(
            matches!(err, RepositoryError::Unauthorized),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn canister_internal_error_keeps_its_message() {
        let mock = Mock::start().await;
        mock.reply::<u64, _>(
            "get_last_change_time",
            Err(GetLastChangeTimeError::InternalError("db is down".into())),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client.get_last_change_time().await.unwrap_err();

        assert!(
            matches!(err, RepositoryError::InternalError(_)),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("db is down"),
            "lost message: {err}"
        );
    }

    #[tokio::test]
    async fn undecodable_reply_is_an_internal_error() {
        let mock = Mock::start().await;
        // A bare text instead of the expected `Result<bool, HasNextTaskError>`.
        mock.push(
            "has_next_task",
            Reply::Candid(Encode!(&"surprise").unwrap()),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client.has_next_task().await.unwrap_err();

        assert!(
            err.to_string()
                .contains("Failed to decode has_next_task response"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn replica_rejection_is_an_internal_error() {
        let mock = Mock::start().await;
        mock.push(
            "get_last_change_time",
            Reply::Reject("canister trapped".into()),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client.get_last_change_time().await.unwrap_err();

        assert!(
            matches!(err, RepositoryError::InternalError(_)),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string()
                .contains("Canister query get_last_change_time failed"),
            "unexpected error: {err}"
        );
        // The wrapper must not swallow the cause: the canister's reject message survives.
        assert!(
            err.to_string().contains("canister trapped"),
            "lost the rejection message: {err}"
        );
    }

    #[tokio::test]
    async fn http_failure_is_an_internal_error() {
        let mock = Mock::start().await;
        mock.push(
            "has_next_task",
            Reply::Status(StatusCode::INTERNAL_SERVER_ERROR),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client.has_next_task().await.unwrap_err();

        assert!(
            err.to_string()
                .contains("Canister query has_next_task failed"),
            "unexpected error: {err}"
        );
        // The wrapper must not swallow the cause: the HTTP status survives.
        assert!(
            err.to_string().contains("500"),
            "lost the HTTP status: {err}"
        );
    }

    #[tokio::test]
    async fn non_cbor_response_is_an_internal_error() {
        let mock = Mock::start().await;
        mock.push("has_next_task", Reply::NotCbor);

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client.has_next_task().await.unwrap_err();

        assert!(
            err.to_string()
                .contains("Canister query has_next_task failed"),
            "unexpected error: {err}"
        );
        // The wrapper must not swallow the cause: this failure is distinguishable from the
        // HTTP-level one above because the underlying decoding error is carried along.
        assert!(
            err.to_string().to_lowercase().contains("cbor"),
            "lost the decoding cause: {err}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // has_next_task / get_last_change_time
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn has_next_task_returns_the_canister_value() {
        let mock = Mock::start().await;
        mock.reply::<bool, HasNextTaskError>("has_next_task", Ok(true));
        mock.reply::<bool, HasNextTaskError>("has_next_task", Ok(false));

        let client = mock.client(Arc::new(PrefixCipher));
        assert!(client.has_next_task().await.unwrap());
        assert!(!client.has_next_task().await.unwrap());

        let state = mock.state();
        assert_eq!(state.methods(), ["has_next_task", "has_next_task"]);
        // The method takes no arguments, so a Candid-encoded unit is sent.
        state.arg::<()>(0);
    }

    #[tokio::test]
    async fn get_last_change_time_returns_the_timestamp() {
        let mock = Mock::start().await;
        mock.reply::<u64, GetLastChangeTimeError>("get_last_change_time", Ok(12_345));

        let client = mock.client(Arc::new(PrefixCipher));
        assert_eq!(client.get_last_change_time().await.unwrap(), 12_345);
    }

    // ---------------------------------------------------------------------------------------
    // all_registrations
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn all_registrations_walks_all_pages_and_decrypts() {
        let mock = Mock::start().await;
        mock.reply::<_, ListCertificatesPageError>(
            "list_certificates_page",
            Ok(CertificatesPage::new(
                vec![api_domain("a.example.com", "A")],
                Some("b.example.com".into()),
            )),
        );
        mock.reply::<_, ListCertificatesPageError>(
            "list_certificates_page",
            Ok(CertificatesPage::new(
                vec![api_domain("b.example.com", "B")],
                None,
            )),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let domains = client.all_registrations(false).await.unwrap();

        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].domain, fqdn!("a.example.com"));
        assert_eq!(domains[0].canister_id, principal!("aaaaa-aa"));
        assert_eq!(domains[0].cert, b"CERT-A");
        assert_eq!(domains[0].priv_key, b"KEY-A");
        assert_eq!(domains[1].domain, fqdn!("b.example.com"));
        assert_eq!(domains[1].cert, b"CERT-B");
        assert_eq!(domains[1].priv_key, b"KEY-B");

        let state = mock.state();
        assert_eq!(
            state.methods(),
            ["list_certificates_page", "list_certificates_page"]
        );
        assert!(!state.calls[0].update, "use_update=false must query");

        // First page starts at the beginning, the second continues from `next_key`.
        let first = state.arg::<ListCertificatesPageInput>(0);
        assert_eq!(first.start_key, None);
        assert_eq!(first.limit, None);
        let second = state.arg::<ListCertificatesPageInput>(1);
        assert_eq!(second.start_key, Some("b.example.com".into()));
        assert_eq!(second.limit, None);
    }

    #[tokio::test]
    async fn all_registrations_with_use_update_hits_the_update_endpoint() {
        let mock = Mock::start().await;

        let client = mock.client(Arc::new(PrefixCipher));
        // Update calls cannot be served by the mock, so this fails - but only after the
        // request has been recorded, which is what we assert on.
        let err = client.all_registrations(true).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Canister update list_certificates_page failed"),
            "unexpected error: {err}"
        );
        // The wrapper must not swallow the cause of a failed update either.
        assert!(
            err.to_string().contains("400"),
            "lost the HTTP status: {err}"
        );

        let state = mock.state();
        assert_eq!(state.methods(), ["list_certificates_page"]);
        assert!(state.calls[0].update, "use_update=true must be an update");
        assert_eq!(state.calls[0].canister, CANISTER_ID);
        assert_eq!(state.arg::<ListCertificatesPageInput>(0).start_key, None);
    }

    #[tokio::test]
    async fn all_registrations_propagates_decryption_failures() {
        let mock = Mock::start().await;
        mock.reply::<_, ListCertificatesPageError>(
            "list_certificates_page",
            Ok(CertificatesPage::new(
                vec![api_domain("a.example.com", "A")],
                None,
            )),
        );

        let client = mock.client(Arc::new(FailingCipher));
        let err = client.all_registrations(false).await.unwrap_err();

        assert!(
            err.to_string().contains("Failed to decrypt data"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn all_registrations_rejects_a_malformed_domain() {
        let mock = Mock::start().await;
        mock.reply::<_, ListCertificatesPageError>(
            "list_certificates_page",
            Ok(CertificatesPage::new(
                vec![api_domain(BAD_DOMAIN, "A")],
                None,
            )),
        );

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client.all_registrations(false).await.unwrap_err();

        assert!(
            err.to_string()
                .contains("Failed to convert RegisteredDomain"),
            "unexpected error: {err}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // fetch_next_task
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn fetch_next_task_skips_the_update_when_nothing_is_pending() {
        let mock = Mock::start().await;
        mock.reply::<bool, HasNextTaskError>("has_next_task", Ok(false));

        let client = mock.client(Arc::new(PrefixCipher));
        assert!(client.fetch_next_task().await.unwrap().is_none());

        // No update call must be made when there is no task.
        assert_eq!(mock.methods(), ["has_next_task"]);
    }

    #[tokio::test]
    async fn fetch_next_task_issues_an_update_when_a_task_is_pending() {
        let mock = Mock::start().await;
        mock.reply::<bool, HasNextTaskError>("has_next_task", Ok(true));

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client.fetch_next_task().await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Canister update fetch_next_task failed"),
            "unexpected error: {err}"
        );

        let state = mock.state();
        assert_eq!(state.methods(), ["has_next_task", "fetch_next_task"]);
        assert!(!state.calls[0].update);
        assert!(state.calls[1].update, "fetch_next_task must be an update");
    }

    // ---------------------------------------------------------------------------------------
    // submit_task_result
    // ---------------------------------------------------------------------------------------

    fn issue_result() -> TaskResult {
        TaskResult::success(
            fqdn!("example.com"),
            TaskOutput::Issue(IssueCertificateOutput::new(
                principal!("aaaaa-aa"),
                b"CERT".to_vec(),
                b"KEY".to_vec(),
                1,
                2,
            )),
            99,
            TaskKind::Renew,
        )
        .with_duration(Duration::from_secs(42))
    }

    #[tokio::test]
    async fn submit_task_result_encrypts_certificate_and_key() {
        let mock = Mock::start().await;

        let client = mock.client(Arc::new(PrefixCipher));
        // The update itself cannot succeed against the mock; we assert on what was sent.
        let err = client.submit_task_result(issue_result()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("Canister update submit_task_result failed"),
            "unexpected error: {err}"
        );

        let state = mock.state();
        assert_eq!(state.methods(), ["submit_task_result"]);
        assert!(state.calls[0].update);

        let sent = state.arg::<TaskResultApi>(0);
        assert_eq!(sent.domain, "example.com");
        assert_eq!(sent.task_id, 99);
        assert_eq!(sent.task_kind, TaskKindApi::Renew);
        assert_eq!(sent.duration_secs, 42);

        let TaskOutcomeApi::Success(TaskOutputApi::Issue(issued)) = sent.outcome else {
            panic!("expected a successful issuance outcome");
        };
        assert_eq!(issued.enc_cert, b"ENC:CERT");
        assert_eq!(issued.enc_priv_key, b"ENC:KEY");
        assert_eq!(issued.canister_id, principal!("aaaaa-aa"));
        assert_eq!(issued.not_before, 1);
        assert_eq!(issued.not_after, 2);
    }

    #[tokio::test]
    async fn submit_task_result_reports_which_field_failed_to_encrypt() {
        let mock = Mock::start().await;

        let client = mock.client(Arc::new(FailingCipher));
        let err = client.submit_task_result(issue_result()).await.unwrap_err();

        assert!(
            matches!(err, RepositoryError::InternalError(_)),
            "unexpected error: {err}"
        );
        // The certificate is encrypted first, so it is the field that is reported.
        assert!(
            err.to_string().contains("Failed to encrypt certificate"),
            "unexpected error: {err}"
        );
        // Nothing must be sent to the canister if encryption failed.
        assert!(mock.methods().is_empty());
    }

    #[tokio::test]
    async fn submit_task_result_does_not_encrypt_non_issue_outcomes() {
        let mock = Mock::start().await;

        // A failing cipher must not matter: there is nothing to encrypt in a failure result.
        let client = mock.client(Arc::new(FailingCipher));
        let err = client
            .submit_task_result(
                TaskResult::failure(
                    fqdn!("example.com"),
                    TaskFailReason::RateLimited,
                    7,
                    TaskKind::Delete,
                )
                .with_duration(Duration::from_secs(3)),
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("Canister update submit_task_result failed"),
            "unexpected error: {err}"
        );

        let state = mock.state();
        let sent = state.arg::<TaskResultApi>(0);
        assert_eq!(sent.task_kind, TaskKindApi::Delete);
        assert_eq!(sent.task_id, 7);
        assert_eq!(sent.duration_secs, 3);
        assert!(
            matches!(sent.outcome, TaskOutcomeApi::Failure(_)),
            "unexpected outcome: {:?}",
            sent.outcome
        );
    }

    // ---------------------------------------------------------------------------------------
    // try_add_task
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn try_add_task_sends_the_converted_task() {
        let mock = Mock::start().await;

        let client = mock.client(Arc::new(PrefixCipher));
        let err = client
            .try_add_task(InputTask::new(
                TaskKind::Issue,
                fqdn!("example.com"),
                true,
                Some(principal!("aaaaa-aa")),
            ))
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("Canister update try_add_task failed"),
            "unexpected error: {err}"
        );

        let state = mock.state();
        assert_eq!(state.methods(), ["try_add_task"]);
        assert!(state.calls[0].update);

        let sent = state.arg::<InputTaskApi>(0);
        assert_eq!(sent.kind, TaskKindApi::Issue);
        assert_eq!(sent.domain, "example.com");
        assert_eq!(sent.wildcard, Some(true));
        assert_eq!(sent.canister_id, Some(principal!("aaaaa-aa")));
    }

    // ---------------------------------------------------------------------------------------
    // Caching
    // ---------------------------------------------------------------------------------------

    /// Programs a `get_last_change_time` + single-page `list_certificates_page` pair.
    fn program_refresh(mock: &Mock, timestamp: u64) {
        mock.reply::<u64, GetLastChangeTimeError>("get_last_change_time", Ok(timestamp));
        mock.reply::<_, ListCertificatesPageError>(
            "list_certificates_page",
            Ok(CertificatesPage::new(
                vec![api_domain("a.example.com", "A")],
                None,
            )),
        );
    }

    #[tokio::test]
    async fn update_cache_fills_both_caches() {
        let mock = Mock::start().await;
        program_refresh(&mock, 555);

        let client = mock.client(Arc::new(PrefixCipher));
        assert!(client.get_certificates().await.unwrap().is_empty());
        assert!(client.get_custom_domains().await.unwrap().is_empty());

        client.update_cache(None, false).await.unwrap();

        // The certificate cache holds the decrypted cert followed by the private key.
        assert_eq!(
            client.get_certificates().await.unwrap(),
            vec![Pem(b"CERT-AKEY-A".to_vec())]
        );
        assert_eq!(
            client.get_custom_domains().await.unwrap(),
            vec![CustomDomain {
                name: fqdn!("a.example.com"),
                canister_id: principal!("aaaaa-aa"),
                timestamp: 0,
                priority: 7,
                flags: Some(DomainFlags::new([FLAG_TEST])),
            }]
        );
        assert_eq!(client.last_change_time.load(Ordering::SeqCst), 555);
        assert_eq!(
            mock.methods(),
            ["get_last_change_time", "list_certificates_page"]
        );
    }

    #[tokio::test]
    async fn update_cache_uses_the_supplied_timestamp_without_querying() {
        let mock = Mock::start().await;
        program_refresh(&mock, 555);

        let client = mock.client(Arc::new(PrefixCipher));
        client.update_cache(Some(77), false).await.unwrap();

        assert_eq!(client.last_change_time.load(Ordering::SeqCst), 77);
        assert_eq!(mock.methods(), ["list_certificates_page"]);
    }

    #[tokio::test]
    async fn failed_refresh_leaves_the_cache_intact() {
        let mock = Mock::start().await;
        program_refresh(&mock, 555);

        let client = mock.client(Arc::new(PrefixCipher));
        client.update_cache(None, false).await.unwrap();

        // Only the timestamp is programmed this time, so fetching the pages fails.
        mock.reply::<u64, GetLastChangeTimeError>("get_last_change_time", Ok(999));
        let err = client.update_cache(None, false).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("unable to fetch registrations data"),
            "unexpected error: {err:#}"
        );

        assert_eq!(
            client.get_certificates().await.unwrap(),
            vec![Pem(b"CERT-AKEY-A".to_vec())]
        );
        assert_eq!(client.last_change_time.load(Ordering::SeqCst), 555);
    }

    #[tokio::test]
    async fn conditional_update_skips_the_fetch_when_nothing_changed() {
        let mock = Mock::start().await;
        mock.reply::<u64, GetLastChangeTimeError>("get_last_change_time", Ok(42));

        let client = mock.client(Arc::new(PrefixCipher));
        client.last_change_time.store(42, Ordering::SeqCst);

        client.update_cache_conditional().await.unwrap();

        assert_eq!(mock.methods(), ["get_last_change_time"]);
    }

    #[tokio::test]
    async fn conditional_update_refetches_when_the_timestamp_moved() {
        let mock = Mock::start().await;
        mock.reply::<u64, GetLastChangeTimeError>("get_last_change_time", Ok(43));

        let client = mock.client(Arc::new(PrefixCipher));
        client.last_change_time.store(42, Ordering::SeqCst);

        // A changed timestamp triggers a full refresh, which uses update calls.
        let err = client.update_cache_conditional().await.unwrap_err();
        assert!(
            format!("{err:#}").contains("unable to fetch registrations data"),
            "unexpected error: {err:#}"
        );

        let state = mock.state();
        assert_eq!(
            state.methods(),
            ["get_last_change_time", "list_certificates_page"]
        );
        assert!(
            state.calls[1].update,
            "a conditional refresh must use update calls"
        );
        // The cached timestamp must only advance after a successful refresh.
        assert_eq!(client.last_change_time.load(Ordering::SeqCst), 42);
    }
}
