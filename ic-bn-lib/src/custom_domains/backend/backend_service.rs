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
        let canister_id = if let Some(canister_id) = canister_id {
            self.validator.validate_limited(&fqdn).await?;
            canister_id
        } else {
            self.validator.validate(&fqdn).await?
        };

        let task = InputTask::new(task, fqdn, wildcard);

        match self.repository.try_add_task(task).await {
            Ok(()) => Ok(canister_id),
            Err(err) => Err(err.into()),
        }
    }

    /// Validates domain can be deleted and submits a delete task
    pub async fn submit_delete_task(&self, domain: &str) -> Result<(), ApiError> {
        let fqdn = parse_domain(domain)?;
        self.validator.validate_deletion(&fqdn).await?;
        let task = InputTask::new(TaskKind::Delete, fqdn, false);

        match self.repository.try_add_task(task).await {
            Ok(()) => Ok(()),
            Err(err) => Err(err.into()),
        }
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
