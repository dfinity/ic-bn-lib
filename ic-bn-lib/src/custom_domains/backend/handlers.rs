use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use tracing::warn;

use super::{
    backend_service::BackendService,
    models::{
        ApiError, CreateOrUpdateResponse, DeleteResponse, ErrorResponse, GetStatusResponse,
        ValidateResponse, error_response, success_response,
    },
};
use crate::custom_domains::base::types::task::TaskKind;

/// Query parameters for the domain registration endpoint.
#[derive(Debug, Default, Deserialize)]
pub struct CreateQuery {
    /// When `true`, the issued certificate also covers `*.domain`.
    #[serde(default)]
    pub wildcard: bool,
}

fn log_error(err: &ApiError, domain: &str, operation: &str) {
    warn!(
        domain = %domain,
        operation = %operation,
        error = %err,
    );
}

/// Register a new domain.
///
/// Triggers an async certificate issuance task for the specified domain.
#[cfg_attr(
    feature = "custom-domains-openapi",
    utoipa::path(
        post,
        path = "/v1/{id}",
        params(
            ("id" = String, Path, description = "Domain name to register"),
            ("wildcard" = Option<bool>, Query, description = "Also issue a *.domain wildcard SAN")
        ),
        responses(
            (status = 202, description = "Domain registration request accepted", body = super::models::ApiResponse<CreateOrUpdateResponse>),
            (status = 400, description = "Invalid request data", body = super::models::ApiResponse<ErrorResponse>),
            (status = 409, description = "Conflict - certificate already exists or task in progress", body = super::models::ApiResponse<ErrorResponse>)
        ),
        tag = "domains"
    )
)]
pub async fn create_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
    Query(query): Query<CreateQuery>,
) -> axum::response::Response {
    match backend_service
        .submit_task(&domain, TaskKind::Issue, query.wildcard)
        .await
    {
        Ok(canister_id) => success_response(
            StatusCode::ACCEPTED,
            CreateOrUpdateResponse {
                domain: domain.clone(),
                canister_id,
            },
            Some(
                "Domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => {
            log_error(&err, &domain, "create_registration");
            error_response(
                err,
                ErrorResponse::new(domain),
                Some("Domain registration request failed".to_string()),
            )
        }
    }
}

/// Update a domain's canister mapping.
///
/// Changes which canister the registered domain points to via an async task.
#[cfg_attr(
    feature = "custom-domains-openapi",
    utoipa::path(
        patch,
        path = "/v1/{id}",
        params(
            ("id" = String, Path, description = "Domain name to update")
        ),
        responses(
            (status = 202, description = "Update request accepted", body = super::models::ApiResponse<CreateOrUpdateResponse>),
            (status = 400, description = "Invalid request data", body = super::models::ApiResponse<ErrorResponse>),
            (status = 404, description = "Domain not found", body = super::models::ApiResponse<ErrorResponse>),
            (status = 409, description = "Conflict - another task already in progress", body = super::models::ApiResponse<ErrorResponse>)
        ),
        tag = "domains"
    )
)]
pub async fn update_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service
        .submit_task(&domain, TaskKind::Update, false)
        .await
    {
        Ok(canister_id) => success_response(
            StatusCode::ACCEPTED,
            CreateOrUpdateResponse {
                domain: domain.clone(),
                canister_id,
            },
            Some(
                "Update domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => {
            log_error(&err, &domain, "update_registration");
            error_response(
                err,
                ErrorResponse::new(domain),
                Some("Update domain registration request failed".to_string()),
            )
        }
    }
}

/// Get domain registration status.
#[cfg_attr(
    feature = "custom-domains-openapi",
    utoipa::path(
        get,
        path = "/v1/{id}",
        params(
            ("id" = String, Path, description = "Domain name to get registration status for")
        ),
        responses(
            (status = 200, description = "Domain status retrieved successfully", body = super::models::ApiResponse<GetStatusResponse>),
            (status = 404, description = "Domain not found", body = super::models::ApiResponse<ErrorResponse>),
            (status = 500, description = "Internal server error", body = super::models::ApiResponse<ErrorResponse>)
        ),
        tag = "domains"
    )
)]
pub async fn get_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service.get_domain_status(&domain).await {
        Ok(domains_status) => success_response(
            StatusCode::OK,
            GetStatusResponse {
                domain: domain.clone(),
                canister_id: domains_status.canister_id,
                registration_status: domains_status.status,
            },
            Some("Registration status of the domain".to_string()),
        ),
        Err(err) => {
            log_error(&err, &domain, "registration_status");
            error_response(
                err,
                ErrorResponse::new(domain),
                Some("Registration status request failed".to_string()),
            )
        }
    }
}

/// Validate domain eligibility for registration.
///
/// Verifies DNS configuration and canister ownership for the specified domain.
#[cfg_attr(
    feature = "custom-domains-openapi",
    utoipa::path(
        get,
        path = "/v1/{id}/validate",
        params(
            ("id" = String, Path, description = "Domain name to validate")
        ),
        responses(
            (status = 200, description = "Domain validation successful", body = super::models::ApiResponse<ValidateResponse>),
            (status = 422, description = "Domain validation failed", body = super::models::ApiResponse<ErrorResponse>)
        ),
        tag = "domains"
    )
)]
pub async fn validate_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service.validate(&domain).await {
        Ok((canister_id, validation_status)) => success_response(
            StatusCode::OK,
            ValidateResponse {
                domain: domain.clone(),
                canister_id,
                validation_status,
            },
            Some("Domain is eligible for registration: DNS records are valid and canister ownership is verified".to_string()),
        ),
        Err(err) => {
            log_error(&err, &domain, "validate_domain");
            error_response(
                err,
            ErrorResponse::new(domain),
                Some("Failed to validate DNS records or verify canister ownership".to_string()),
            )
        }
    }
}

/// Delete an existing domain registration.
///
/// Revokes the certificate and removes the domain registration asynchronously.
#[cfg_attr(
    feature = "custom-domains-openapi",
    utoipa::path(
        delete,
        path = "/v1/{id}",
        params(
            ("id" = String, Path, description = "Domain name to delete")
        ),
        responses(
            (status = 202, description = "Delete request accepted", body = super::models::ApiResponse<DeleteResponse>),
            (status = 404, description = "Domain not found", body = super::models::ApiResponse<ErrorResponse>),
            (status = 409, description = "Conflict - cannot delete domain", body = super::models::ApiResponse<ErrorResponse>)
        ),
        tag = "domains"
    )
)]
pub async fn delete_handler(
    State(backend_service): State<BackendService>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    match backend_service.submit_delete_task(&domain).await {
        Ok(()) => success_response(
            StatusCode::ACCEPTED,
            DeleteResponse {
                domain: domain.clone(),
            },
            Some(
                "Delete domain registration request accepted and may take a few minutes to process"
                    .to_string(),
            ),
        ),
        Err(err) => {
            log_error(&err, &domain, "delete_registration");
            error_response(
                err,
                ErrorResponse::new(domain),
                Some("Delete domain registration request failed".to_string()),
            )
        }
    }
}
