use axum::{Json, http::StatusCode, response::IntoResponse};
use candid::Principal;
use derive_new::new;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

use crate::custom_domains::base::{
    traits::{repository::RepositoryError, validation::ValidationError},
    types::domain::RegistrationStatus,
};

/// Generic API response structure for all endpoints.
#[derive(Serialize, ToSchema)]
pub struct ApiResponse<T> {
    /// Status of the response ("success" or "error")
    status: String,
    /// Optional human-readable message
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Optional response data payload
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    /// Optional error details
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<String>,
}

/// API error types with associated details.
#[derive(Serialize, Deserialize, Debug, Clone, Error)]
pub enum ApiError {
    /// Invalid request data (400)
    #[error("bad_request: {0}")]
    BadRequest(String),
    /// Resource not found (404)
    #[error("not_found: {0}")]
    NotFound(String),
    /// Resource conflict (409)
    #[error("conflict: {0}")]
    Conflict(String),
    /// Request validation failed (422)
    #[error("unprocessable_entity: {0}")]
    UnprocessableEntity(String),
    /// Server error (500)
    #[error(
        "internal_server_error: An unexpected error occurred. Please try again later or contact support."
    )]
    InternalServerError(String),
}

/// Response data payload for domain creation/update.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[derive(ToSchema)]
pub struct CreateOrUpdateResponse {
    /// The domain name
    pub domain: String,
    /// Associated canister ID
    #[schema(value_type = String, example = "rrkah-fqaaa-aaaaa-aaaaq-cai")]
    pub canister_id: Principal,
}

/// Error response data payload.
#[derive(Serialize, Deserialize, Debug, Clone, new)]
#[serde(rename_all = "snake_case")]
#[derive(ToSchema)]
pub struct ErrorResponse {
    /// The domain name
    pub domain: String,
}

/// Delete response data payload.
#[derive(Serialize, Deserialize, Debug, Clone, new)]
#[serde(rename_all = "snake_case")]
#[derive(ToSchema)]
pub struct DeleteResponse {
    /// The domain name
    pub domain: String,
}

/// Get domains status response data payload.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[derive(ToSchema)]
pub struct GetStatusResponse {
    /// The domain name
    pub domain: String,
    /// Associated canister ID
    #[schema(value_type = Option<String>, example = "rrkah-fqaaa-aaaaa-aaaaq-cai", nullable = true)]
    pub canister_id: Option<Principal>,
    /// Domain registration status
    pub registration_status: RegistrationStatus,
}

/// Response data payload for domain-related endpoints.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[derive(ToSchema)]
pub struct ValidateResponse {
    /// The domain name
    pub domain: String,
    /// Associated canister ID
    #[schema(value_type = String, example = "rrkah-fqaaa-aaaaa-aaaaq-cai")]
    pub canister_id: Principal,
    /// Domain validation status
    pub validation_status: ValidationStatus,
}

impl From<RepositoryError> for ApiError {
    fn from(err: RepositoryError) -> Self {
        match err {
            RepositoryError::CertificateAlreadyIssued(domain) => Self::Conflict(format!(
                "Certificate for {domain} already exists; reissuance is not permitted."
            )),
            RepositoryError::AnotherTaskInProgress(domain) => Self::Conflict(format!(
                "Another task for {domain} is already in progress. Please retry after it completes."
            )),
            RepositoryError::DomainNotFound(domain) => {
                Self::NotFound(format!("Domain {domain} not found."))
            }
            RepositoryError::MissingCertificateForUpdate(domain) => Self::BadRequest(format!(
                "Cannot update domain-to-canister mapping: no valid certificate found for domain {domain}."
            )),
            _ => Self::InternalServerError("".to_string()),
        }
    }
}

// All validation errors should be converted to BadRequest
impl From<ValidationError> for ApiError {
    fn from(value: ValidationError) -> Self {
        Self::BadRequest(value.to_string())
    }
}

/// Creates a success response with the given data and message.
pub fn success_response<T: Serialize>(
    code: StatusCode,
    data: T,
    message: Option<String>,
) -> axum::response::Response {
    let json: Json<ApiResponse<T>> = Json(ApiResponse {
        status: "success".to_string(),
        message,
        data: Some(data),
        errors: None,
    });

    (code, json).into_response()
}

/// Creates an error response with the given error, data, and message.
pub fn error_response<T: Serialize>(
    error: ApiError,
    data: T,
    message: Option<String>,
) -> axum::response::Response {
    let code = match error {
        ApiError::BadRequest { .. } => StatusCode::BAD_REQUEST,
        ApiError::NotFound { .. } => StatusCode::NOT_FOUND,
        ApiError::Conflict { .. } => StatusCode::CONFLICT,
        ApiError::UnprocessableEntity { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        ApiError::InternalServerError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let json: Json<ApiResponse<T>> = Json(ApiResponse {
        status: "error".to_string(),
        message,
        data: Some(data),
        errors: Some(error.to_string()),
    });

    (code, json).into_response()
}

/// Domain validation status for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(ToSchema)]
pub enum ValidationStatus {
    /// Domain validation passed
    Valid,
    /// Domain validation failed with error details
    Invalid(String),
}
