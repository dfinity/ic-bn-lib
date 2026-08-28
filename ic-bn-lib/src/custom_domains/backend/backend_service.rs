use std::{str::FromStr, sync::Arc};

use candid::Principal;
use derive_new::new;
use fqdn::FQDN;

use super::models::{ApiError, ValidationStatus};
use crate::custom_domains::base::{
    traits::{repository::Repository, validation::ValidatesDomains},
    types::{
        domain::DomainStatus,
        task::{InputTask, TaskKind},
    },
};

/// Backend service that orchestrates domain validation, task submission, and registration status retrieval.
///
/// This service acts as the logical layer between user and the repository (data storage).
#[derive(Clone, new)]
pub struct BackendService {
    /// Repository for storing domain data (e.g. certificates) and tasks
    repository: Arc<dyn Repository>,
    /// Domain validator for DNS and canister ownership checks
    validator: Arc<dyn ValidatesDomains>,
    /// Token that allows to bypass certain validation steps & specify the canister ID directly
    pub bypass_token: Option<String>,
}

impl BackendService {
    /// Validates domain configuration and submits a task for further processing.
    ///
    /// `wildcard` requests that the issued certificate also covers `*.domain`. It is
    /// only meaningful for `Issue`; other task kinds should pass `false`.
    pub async fn submit_task(
        &self,
        domain: &str,
        task: TaskKind,
        wildcard: bool,
        canister_id: Option<Principal>,
    ) -> Result<Principal, ApiError> {
        let fqdn = parse_domain(domain)?;

        // If the canister ID is provided - use limited validation, otherwise full one
        // that derives the canister ID from the DNS TXT record
        let resolved_canister_id = if let Some(canister_id) = canister_id {
            self.validator.validate_limited(&fqdn).await?;
            canister_id
        } else {
            self.validator.validate(&fqdn).await?
        };

        // Carry forward only the caller-supplied (bypass) canister ID, not the resolved
        // one. The worker uses this field to decide whether to trust it or derive it from DNS
        let task = InputTask::new(task, fqdn, wildcard, canister_id);

        self.repository.try_add_task(task).await?;
        Ok(resolved_canister_id)
    }

    /// Validates domain can be deleted and submits a delete task
    pub async fn submit_delete_task(&self, domain: &str) -> Result<(), ApiError> {
        let fqdn = parse_domain(domain)?;
        self.validator.validate_deletion(&fqdn).await?;
        let task = InputTask::new(TaskKind::Delete, fqdn, false, None);

        self.repository.try_add_task(task).await?;
        Ok(())
    }

    /// Retrieves the current status of a domain registration
    pub async fn get_domain_status(&self, domain: &str) -> Result<DomainStatus, ApiError> {
        let fqdn = parse_domain(domain)?;

        match self.repository.get_domain_status(&fqdn).await {
            Ok(Some(entry)) => Ok(entry),
            Ok(None) => Err(ApiError::NotFound(format!("Domain {domain} not found"))),
            Err(_) => Err(ApiError::InternalServerError("".to_string())),
        }
    }

    /// Validates that the domain is eligible for registration without submitting a task
    pub async fn validate(&self, domain: &str) -> Result<(Principal, ValidationStatus), ApiError> {
        let fqdn = parse_domain(domain)?;

        match self.validator.validate(&fqdn).await {
            Ok(canister_id) => Ok((canister_id, ValidationStatus::Valid)),
            Err(err) => Err(ApiError::UnprocessableEntity(err.to_string())),
        }
    }
}

/// Parses a domain string into a validated FQDN
fn parse_domain(domain: &str) -> Result<FQDN, ApiError> {
    if domain.is_empty() {
        return Err(ApiError::BadRequest("Domain cannot be empty".to_string()));
    } else if domain.len() > 255 {
        return Err(ApiError::BadRequest("Domain is too long".to_string()));
    }

    FQDN::from_str(domain)
        .map_err(|e| ApiError::BadRequest(format!("Invalid domain format: {e:#}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        custom_domains::base::traits::{
            repository::{MockRepository, RepositoryError},
            validation::{MockValidatesDomains, ValidationError},
        },
        principal,
    };

    fn service(
        repository: MockRepository,
        validator: MockValidatesDomains,
        bypass_token: Option<String>,
    ) -> BackendService {
        BackendService::new(Arc::new(repository), Arc::new(validator), bypass_token)
    }

    #[tokio::test]
    async fn submit_task_with_canister_id_uses_limited_validation_and_preserves_it() {
        // Arrange
        let canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");

        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate_limited()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));
        // `validate()` is intentionally left unmocked: it must not be called on the bypass path.

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(move |task| task.canister_id == Some(canister_id))
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let svc = service(repository, validator, None);

        // Act
        let result = svc
            .submit_task("example.org", TaskKind::Issue, false, Some(canister_id))
            .await
            .unwrap();

        // Assert
        assert_eq!(result, canister_id);
    }

    #[tokio::test]
    async fn submit_task_without_canister_id_uses_full_validation_and_leaves_task_canister_id_none()
    {
        // Arrange
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");

        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));
        // `validate_limited()` is intentionally left unmocked: it must not be called without a
        // caller-supplied canister ID.

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            // Regression guard: the task must carry `None`, not the derived canister_id,
            // otherwise the worker would trust it and skip re-verifying ownership from DNS
            // at execution time (see the comment on `submit_task`).
            .withf(|task| task.canister_id.is_none())
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let svc = service(repository, validator, None);

        // Act
        let result = svc
            .submit_task("example.org", TaskKind::Update, false, None)
            .await
            .unwrap();

        // Assert
        assert_eq!(result, derived_canister_id);
    }

    #[tokio::test]
    async fn submit_task_propagates_limited_validation_failure_without_adding_task() {
        // Arrange
        let canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");

        let mut validator = MockValidatesDomains::new();
        validator.expect_validate_limited().times(1).returning(|_| {
            Box::pin(async {
                Err(ValidationError::ExistingDnsTxtChallenge {
                    src: "_acme-challenge.example.org.".to_string(),
                })
            })
        });

        let repository = MockRepository::new(); // try_add_task must not be called

        let svc = service(repository, validator, None);

        // Act
        let err = svc
            .submit_task("example.org", TaskKind::Issue, false, Some(canister_id))
            .await
            .unwrap_err();

        // Assert
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn submit_task_propagates_full_validation_failure_without_adding_task() {
        // Arrange
        let mut validator = MockValidatesDomains::new();
        validator.expect_validate().times(1).returning(|_| {
            Box::pin(async {
                Err(ValidationError::MissingDnsCname {
                    src: "_acme-challenge.example.org.".to_string(),
                    dst: "_acme-challenge.example.org.icp2.io.".to_string(),
                })
            })
        });

        let repository = MockRepository::new(); // try_add_task must not be called

        let svc = service(repository, validator, None);

        // Act
        let err = svc
            .submit_task("example.org", TaskKind::Issue, false, None)
            .await
            .unwrap_err();

        // Assert
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn submit_task_propagates_repository_error() {
        // Arrange
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .returning(|_| Box::pin(async { Ok(principal!("rrkah-fqaaa-aaaaa-aaaaq-cai")) }));

        let mut repository = MockRepository::new();
        repository.expect_try_add_task().returning(|_| {
            Box::pin(async {
                Err(RepositoryError::AnotherTaskInProgress(
                    FQDN::from_str("example.org").unwrap(),
                ))
            })
        });

        let svc = service(repository, validator, None);

        // Act
        let err = svc
            .submit_task("example.org", TaskKind::Issue, false, None)
            .await
            .unwrap_err();

        // Assert
        assert!(matches!(err, ApiError::Conflict(_)));
    }

    #[tokio::test]
    async fn submit_task_rejects_invalid_domain_before_validating() {
        // Arrange: no expectations set on either mock, so any call panics
        let validator = MockValidatesDomains::new();
        let repository = MockRepository::new();

        let svc = service(repository, validator, None);

        // Act
        let err = svc
            .submit_task("invalid..domain", TaskKind::Issue, false, None)
            .await
            .unwrap_err();

        // Assert
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn submit_delete_task_success_carries_no_canister_id() {
        // Arrange
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate_deletion()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|task| task.kind == TaskKind::Delete && task.canister_id.is_none())
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let svc = service(repository, validator, None);

        // Act & Assert
        svc.submit_delete_task("example.org").await.unwrap();
    }

    #[tokio::test]
    async fn submit_delete_task_propagates_validation_failure() {
        // Arrange
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate_deletion()
            .times(1)
            .returning(|_| {
                Box::pin(async {
                    Err(ValidationError::ExistingDnsTxtCanisterId {
                        src: "_canister-id.example.org.".to_string(),
                    })
                })
            });

        let repository = MockRepository::new(); // try_add_task must not be called

        let svc = service(repository, validator, None);

        // Act
        let err = svc.submit_delete_task("example.org").await.unwrap_err();

        // Assert
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
