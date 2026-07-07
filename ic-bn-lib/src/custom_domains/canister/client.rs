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
use ic_bn_lib_common::{
    traits::{Run, custom_domains::ProvidesCustomDomains, tls::ProvidesCertificates},
    types::{CustomDomain, DomainFlags, tls::Pem},
};
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

use crate::custom_domains::base::{
    traits::{
        cipher::CiphersCertificates,
        repository::{Repository, RepositoryError},
        time::UtcTimestamp,
    },
    types::{
        domain::{DomainStatus, RegisteredDomain},
        task::{InputTask, ScheduledTask, TaskOutcome, TaskOutput, TaskResult},
    },
};
use crate::ic_agent::Agent;

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
    async fn get_certificates(&self) -> Result<Vec<Pem>, anyhow::Error> {
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
            "Started polling every {}s, full refresh every {}s",
            self.poll_interval.as_secs_f64(),
            self.refresh_interval.as_secs_f64()
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
