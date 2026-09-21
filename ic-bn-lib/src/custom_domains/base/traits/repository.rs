use std::str::FromStr;

use anyhow::anyhow;
use async_trait::async_trait;
use fqdn::FQDN;
use ic_custom_domains_canister_api::{
    FetchTaskError as ApiFetchTaskError, GetDomainStatusError as ApiGetDomainStatusError,
    GetLastChangeTimeError as ApiGetLastChangeTimeError, HasNextTaskError as ApiHasNextTaskError,
    ListCertificatesPageError as ApiListCertificatesPageError,
    SubmitTaskError as ApiSubmitTaskError, TryAddTaskError as ApiTryAddTaskError,
};
use strum::IntoStaticStr;
use thiserror::Error;

use crate::custom_domains::base::{
    traits::time::UtcTimestamp,
    types::{
        domain::{DomainStatus, RegisteredDomain},
        task::{InputTask, ScheduledTask, TaskResult},
    },
};

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

#[cfg(test)]
mod test {
    use fqdn::fqdn;

    use super::*;

    /// Strum-derived discriminant name
    fn kind(err: &RepositoryError) -> &'static str {
        err.into()
    }

    #[test]
    fn test_repository_error_display() {
        assert_eq!(
            RepositoryError::Unauthorized.to_string(),
            "Unauthorized operation"
        );
        assert_eq!(
            RepositoryError::AnotherTaskInProgress(fqdn!("foo.bar")).to_string(),
            "Another task is in progress for domain: foo.bar"
        );
        assert_eq!(
            RepositoryError::CertificateAlreadyIssued(fqdn!("foo.bar")).to_string(),
            "Certificate already issued for domain: foo.bar"
        );
        assert_eq!(
            RepositoryError::DomainNotFound(fqdn!("foo.bar")).to_string(),
            "Domain not found: foo.bar"
        );
        assert_eq!(
            RepositoryError::NonExistingTaskSubmitted(1_234_567_890).to_string(),
            "Failed to submit result of a non-existing task with ID: 1234567890"
        );
        assert_eq!(
            RepositoryError::MissingCertificateForUpdate(fqdn!("foo.bar")).to_string(),
            "Update task requires an existing certificate for domain: foo.bar"
        );

        // InternalError is transparent - it shows the inner error only
        assert_eq!(
            RepositoryError::from(anyhow!("inner error")).to_string(),
            "inner error"
        );
    }

    #[test]
    fn test_repository_error_kind() {
        assert_eq!(kind(&RepositoryError::Unauthorized), "unauthorized");
        assert_eq!(
            kind(&RepositoryError::AnotherTaskInProgress(fqdn!("foo.bar"))),
            "another_task_in_progress"
        );
        assert_eq!(
            kind(&RepositoryError::CertificateAlreadyIssued(fqdn!("foo.bar"))),
            "certificate_already_issued"
        );
        assert_eq!(
            kind(&RepositoryError::DomainNotFound(fqdn!("foo.bar"))),
            "domain_not_found"
        );
        assert_eq!(
            kind(&RepositoryError::NonExistingTaskSubmitted(1)),
            "non_existing_task_submitted"
        );
        assert_eq!(
            kind(&RepositoryError::MissingCertificateForUpdate(fqdn!(
                "foo.bar"
            ))),
            "missing_certificate_for_update"
        );
        assert_eq!(
            kind(&RepositoryError::InternalError(anyhow!("foo"))),
            "internal_error"
        );
    }

    #[test]
    fn test_try_from_submit_task_error() {
        let e = RepositoryError::try_from(ApiSubmitTaskError::Unauthorized).unwrap();
        assert_eq!(kind(&e), "unauthorized");

        // The domain is parsed into an FQDN (and lowercased on the way)
        let e = RepositoryError::try_from(ApiSubmitTaskError::DomainNotFound("Foo.BAR".into()))
            .unwrap();
        match &e {
            RepositoryError::DomainNotFound(v) => assert_eq!(*v, fqdn!("foo.bar")),
            _ => panic!("wrong variant: {e:?}"),
        }

        let e =
            RepositoryError::try_from(ApiSubmitTaskError::NonExistingTaskSubmitted(777)).unwrap();
        match &e {
            RepositoryError::NonExistingTaskSubmitted(v) => assert_eq!(*v, 777),
            _ => panic!("wrong variant: {e:?}"),
        }

        let e = RepositoryError::try_from(ApiSubmitTaskError::InternalError("bad stuff".into()))
            .unwrap();
        assert_eq!(kind(&e), "internal_error");
        assert_eq!(e.to_string(), "bad stuff");
    }

    #[test]
    fn test_try_from_try_add_task_error() {
        let e = RepositoryError::try_from(ApiTryAddTaskError::Unauthorized).unwrap();
        assert_eq!(kind(&e), "unauthorized");

        for (api, expected) in [
            (
                ApiTryAddTaskError::DomainNotFound("foo.bar".into()),
                "domain_not_found",
            ),
            (
                ApiTryAddTaskError::AnotherTaskInProgress("foo.bar".into()),
                "another_task_in_progress",
            ),
            (
                ApiTryAddTaskError::CertificateAlreadyIssued("foo.bar".into()),
                "certificate_already_issued",
            ),
            (
                ApiTryAddTaskError::MissingCertificateForUpdate("foo.bar".into()),
                "missing_certificate_for_update",
            ),
        ] {
            let e = RepositoryError::try_from(api).unwrap();
            assert_eq!(kind(&e), expected);
            assert!(e.to_string().ends_with("foo.bar"), "{e}");
        }

        let e = RepositoryError::try_from(ApiTryAddTaskError::InternalError("bad stuff".into()))
            .unwrap();
        assert_eq!(kind(&e), "internal_error");
        assert_eq!(e.to_string(), "bad stuff");
    }

    /// The domain-carrying conversions must fail if the canister sends
    /// something that can't be parsed as a domain name.
    #[test]
    fn test_try_from_bad_domain() {
        let err = RepositoryError::try_from(ApiSubmitTaskError::DomainNotFound("foo..bar".into()))
            .unwrap_err();
        assert!(err.to_string().contains("empty label"), "{err}");

        assert!(
            RepositoryError::try_from(ApiTryAddTaskError::DomainNotFound("foo..bar".into()))
                .is_err()
        );

        // An empty domain is an exception: it parses as the root domain
        assert!(
            RepositoryError::try_from(ApiTryAddTaskError::AnotherTaskInProgress("".into()))
                .is_ok_and(|x| matches!(x, RepositoryError::AnotherTaskInProgress(_)))
        );
        assert!(
            RepositoryError::try_from(ApiTryAddTaskError::CertificateAlreadyIssued(
                "foo.bar!".into()
            ))
            .is_err()
        );
        assert!(
            RepositoryError::try_from(ApiTryAddTaskError::MissingCertificateForUpdate(
                ".foo.bar".into()
            ))
            .is_err()
        );
    }

    #[test]
    fn test_try_from_simple_errors() {
        let e = RepositoryError::try_from(ApiGetDomainStatusError::Unauthorized).unwrap();
        assert_eq!(kind(&e), "unauthorized");
        let e = RepositoryError::try_from(ApiGetDomainStatusError::InternalError("foo".into()))
            .unwrap();
        assert_eq!((kind(&e), e.to_string()), ("internal_error", "foo".into()));

        let e = RepositoryError::try_from(ApiFetchTaskError::Unauthorized).unwrap();
        assert_eq!(kind(&e), "unauthorized");
        let e = RepositoryError::try_from(ApiFetchTaskError::InternalError("foo".into())).unwrap();
        assert_eq!((kind(&e), e.to_string()), ("internal_error", "foo".into()));

        let e = RepositoryError::try_from(ApiGetLastChangeTimeError::Unauthorized).unwrap();
        assert_eq!(kind(&e), "unauthorized");
        let e = RepositoryError::try_from(ApiGetLastChangeTimeError::InternalError("foo".into()))
            .unwrap();
        assert_eq!((kind(&e), e.to_string()), ("internal_error", "foo".into()));

        let e = RepositoryError::try_from(ApiListCertificatesPageError::Unauthorized).unwrap();
        assert_eq!(kind(&e), "unauthorized");
        let e =
            RepositoryError::try_from(ApiListCertificatesPageError::InternalError("foo".into()))
                .unwrap();
        assert_eq!((kind(&e), e.to_string()), ("internal_error", "foo".into()));

        let e = RepositoryError::try_from(ApiHasNextTaskError::Unauthorized).unwrap();
        assert_eq!(kind(&e), "unauthorized");
        let e =
            RepositoryError::try_from(ApiHasNextTaskError::InternalError("foo".into())).unwrap();
        assert_eq!((kind(&e), e.to_string()), ("internal_error", "foo".into()));
    }
}
