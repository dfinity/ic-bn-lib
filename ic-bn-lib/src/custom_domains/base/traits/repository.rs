use std::str::FromStr;

use crate::custom_domains::canister::api::{
    FetchTaskError as ApiFetchTaskError, GetDomainStatusError as ApiGetDomainStatusError,
    GetLastChangeTimeError as ApiGetLastChangeTimeError, HasNextTaskError as ApiHasNextTaskError,
    ListCertificatesPageError as ApiListCertificatesPageError,
    SubmitTaskError as ApiSubmitTaskError, TryAddTaskError as ApiTryAddTaskError,
};
use async_trait::async_trait;
use fqdn::FQDN;
use strum::IntoStaticStr;
use thiserror::Error;

use super::super::{
    traits::time::UtcTimestamp,
    types::{
        domain::{DomainStatus, RegisteredDomain},
        task::{InputTask, ScheduledTask, TaskResult},
    },
};
use anyhow::anyhow;

pub type TaskId = UtcTimestamp;

#[derive(Debug, Error, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RepositoryError {
    #[error("Unauthorized operation")]
    Unauthorized,
    #[error("Another task is in progress for domain: {0}")]
    AnotherTaskInProgress(FQDN),
    #[error("Certificate already issued for domain: {0}")]
    CertificateAlreadyIssued(FQDN),
    #[error("Domain not found: {0}")]
    DomainNotFound(FQDN),
    #[error("Failed to submit result of a non-existing task with ID: {0}")]
    NonExistingTaskSubmitted(TaskId),
    #[error("Update task requires an existing certificate for domain: {0}")]
    MissingCertificateForUpdate(FQDN),
    #[error(transparent)]
    InternalError(#[from] anyhow::Error),
}

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait Repository: Send + Sync {
    /// Retrieves domain status.
    async fn get_domain_status(
        &self,
        domain: &FQDN,
    ) -> Result<Option<DomainStatus>, RepositoryError>;
    /// Checks if there is at least one pending task for execution.
    async fn has_next_task(&self) -> Result<bool, RepositoryError>;
    /// Fetch next pending task for execution.
    async fn fetch_next_task(&self) -> Result<Option<ScheduledTask>, RepositoryError>;
    /// Submits task execution result.
    async fn submit_task_result(&self, task_result: TaskResult) -> Result<(), RepositoryError>;
    /// Tries to submit a new task of certain kind for a domain.
    async fn try_add_task(&self, task: InputTask) -> Result<(), RepositoryError>;
    /// Retrieves the timestamp of the last change accross all registration records.
    async fn get_last_change_time(&self) -> Result<UtcTimestamp, RepositoryError>;
    /// Fetches all registered domains with valid certificates.
    async fn all_registrations(
        &self,
        use_update: bool,
    ) -> Result<Vec<RegisteredDomain>, RepositoryError>;
}

impl TryFrom<ApiSubmitTaskError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiSubmitTaskError) -> Result<Self, Self::Error> {
        match err {
            ApiSubmitTaskError::Unauthorized => Ok(Self::Unauthorized),
            ApiSubmitTaskError::DomainNotFound(domain) => {
                Ok(Self::DomainNotFound(FQDN::from_str(&domain)?))
            }
            ApiSubmitTaskError::NonExistingTaskSubmitted(task_id) => {
                Ok(Self::NonExistingTaskSubmitted(task_id))
            }
            ApiSubmitTaskError::InternalError(err) => Ok(Self::InternalError(anyhow!(err))),
        }
    }
}

impl TryFrom<ApiTryAddTaskError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiTryAddTaskError) -> Result<Self, Self::Error> {
        match err {
            ApiTryAddTaskError::Unauthorized => Ok(Self::Unauthorized),
            ApiTryAddTaskError::DomainNotFound(domain) => {
                Ok(Self::DomainNotFound(FQDN::from_str(&domain)?))
            }
            ApiTryAddTaskError::AnotherTaskInProgress(domain) => {
                Ok(Self::AnotherTaskInProgress(FQDN::from_str(&domain)?))
            }
            ApiTryAddTaskError::CertificateAlreadyIssued(domain) => {
                Ok(Self::CertificateAlreadyIssued(FQDN::from_str(&domain)?))
            }
            ApiTryAddTaskError::MissingCertificateForUpdate(domain) => {
                Ok(Self::MissingCertificateForUpdate(FQDN::from_str(&domain)?))
            }
            ApiTryAddTaskError::InternalError(err) => Ok(Self::InternalError(anyhow!(err))),
        }
    }
}

impl TryFrom<ApiGetDomainStatusError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiGetDomainStatusError) -> Result<Self, Self::Error> {
        match err {
            ApiGetDomainStatusError::Unauthorized => Ok(Self::Unauthorized),
            ApiGetDomainStatusError::InternalError(err) => Ok(Self::InternalError(anyhow!(err))),
        }
    }
}

impl TryFrom<ApiFetchTaskError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiFetchTaskError) -> Result<Self, Self::Error> {
        match err {
            ApiFetchTaskError::Unauthorized => Ok(Self::Unauthorized),
            ApiFetchTaskError::InternalError(err) => Ok(Self::InternalError(anyhow!(err))),
        }
    }
}

impl TryFrom<ApiGetLastChangeTimeError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiGetLastChangeTimeError) -> Result<Self, Self::Error> {
        match err {
            ApiGetLastChangeTimeError::Unauthorized => Ok(Self::Unauthorized),
            ApiGetLastChangeTimeError::InternalError(err) => Ok(Self::InternalError(anyhow!(err))),
        }
    }
}

impl TryFrom<ApiListCertificatesPageError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiListCertificatesPageError) -> Result<Self, Self::Error> {
        match err {
            ApiListCertificatesPageError::Unauthorized => Ok(Self::Unauthorized),
            ApiListCertificatesPageError::InternalError(err) => {
                Ok(Self::InternalError(anyhow!(err)))
            }
        }
    }
}

impl TryFrom<ApiHasNextTaskError> for RepositoryError {
    type Error = anyhow::Error;

    fn try_from(err: ApiHasNextTaskError) -> Result<Self, Self::Error> {
        match err {
            ApiHasNextTaskError::Unauthorized => Ok(Self::Unauthorized),
            ApiHasNextTaskError::InternalError(err) => Ok(Self::InternalError(anyhow!(err))),
        }
    }
}
