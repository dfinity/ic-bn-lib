#![allow(clippy::option_if_let_else)]

use axum::{Json, http::StatusCode, response::IntoResponse};
use candid::Principal;
use derive_new::new;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "custom-domains-openapi")]
use utoipa::ToSchema;

use crate::custom_domains::base::{
    traits::{repository::RepositoryError, validation::ValidationError},
    types::domain::RegistrationStatus,
};

/// Generic API response structure for all endpoints.
#[derive(Serialize)]
#[cfg_attr(feature = "custom-domains-openapi", derive(ToSchema))]
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
#[cfg_attr(feature = "custom-domains-openapi", derive(ToSchema))]
pub struct CreateOrUpdateResponse {
    /// The domain name
    pub domain: String,
    /// Associated canister ID
    #[cfg_attr(
        feature = "custom-domains-openapi",
        schema(value_type = String, example = "rrkah-fqaaa-aaaaa-aaaaq-cai")
    )]
    pub canister_id: Principal,
}

/// Error response data payload.
#[derive(Serialize, Deserialize, Debug, Clone, new)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "custom-domains-openapi", derive(ToSchema))]
pub struct ErrorResponse {
    /// The domain name
    pub domain: String,
}

/// Delete response data payload.
#[derive(Serialize, Deserialize, Debug, Clone, new)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "custom-domains-openapi", derive(ToSchema))]
pub struct DeleteResponse {
    /// The domain name
    pub domain: String,
}

/// Get domains status response data payload.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "custom-domains-openapi", derive(ToSchema))]
pub struct GetStatusResponse {
    /// The domain name
    pub domain: String,
    /// Associated canister ID
    #[cfg_attr(
        feature = "custom-domains-openapi",
        schema(value_type = Option<String>, example = "rrkah-fqaaa-aaaaa-aaaaq-cai", nullable = true)
    )]
    pub canister_id: Option<Principal>,
    /// Domain registration status
    pub registration_status: RegistrationStatus,
}

/// Response data payload for domain-related endpoints.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "custom-domains-openapi", derive(ToSchema))]
pub struct ValidateResponse {
    /// The domain name
    pub domain: String,
    /// Associated canister ID
    #[cfg_attr(
        feature = "custom-domains-openapi",
        schema(value_type = String, example = "rrkah-fqaaa-aaaaa-aaaaq-cai")
    )]
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
#[cfg_attr(feature = "custom-domains-openapi", derive(ToSchema))]
pub enum ValidationStatus {
    /// Domain validation passed
    Valid,
    /// Domain validation failed with error details
    Invalid(String),
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use axum::{body::to_bytes, http::header::CONTENT_TYPE};
    use fqdn::FQDN;
    use serde_json::{Value, json};

    use super::*;
    use crate::principal;

    const CANISTER_ID: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";
    const BODY_LIMIT: usize = 8 * 1024;
    /// The exact text `ApiError::InternalServerError` is allowed to expose.
    const MASKED_INTERNAL: &str = "internal_server_error: An unexpected error occurred. Please try again later or contact support.";

    fn fqdn(s: &str) -> FQDN {
        FQDN::from_str(s).unwrap()
    }

    async fn into_json(resp: axum::response::Response) -> (StatusCode, Value) {
        let status = resp.status();
        let body = to_bytes(resp.into_body(), BODY_LIMIT).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn keys(v: &Value) -> Vec<&str> {
        let mut k = v
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        k.sort_unstable();
        k
    }

    #[tokio::test]
    async fn success_response_omits_message_and_errors_when_none() {
        // `message: None` and the always-`None` `errors` must not appear at all
        // (not as `null`) because of `skip_serializing_if`.
        let resp = success_response(StatusCode::OK, json!({"a": 1}), None);
        let (status, body) = into_json(resp).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(keys(&body), vec!["data", "status"]);
        assert_eq!(body["status"], "success");
        assert_eq!(body["data"], json!({"a": 1}));
    }

    #[tokio::test]
    async fn success_response_uses_given_code_and_message_and_json_content_type() {
        let resp = success_response(
            StatusCode::ACCEPTED,
            DeleteResponse::new("example.org".to_string()),
            Some("accepted".to_string()),
        );

        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(keys(&body), vec!["data", "message", "status"]);
        assert_eq!(body["status"], "success");
        assert_eq!(body["message"], "accepted");
        assert_eq!(body["data"]["domain"], "example.org");
    }

    #[tokio::test]
    async fn error_response_maps_every_variant_to_its_status_code() {
        let cases = [
            (
                ApiError::BadRequest("bad".to_string()),
                StatusCode::BAD_REQUEST,
            ),
            (
                ApiError::NotFound("gone".to_string()),
                StatusCode::NOT_FOUND,
            ),
            (ApiError::Conflict("dupe".to_string()), StatusCode::CONFLICT),
            (
                ApiError::UnprocessableEntity("nope".to_string()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                ApiError::InternalServerError("boom".to_string()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (err, expected_code) in cases {
            let expected_errors = err.to_string();
            let resp = error_response(
                err,
                ErrorResponse::new("example.org".to_string()),
                Some("failed".to_string()),
            );
            let (status, body) = into_json(resp).await;

            assert_eq!(status, expected_code);
            assert_eq!(keys(&body), vec!["data", "errors", "message", "status"]);
            assert_eq!(body["status"], "error");
            assert_eq!(body["message"], "failed");
            assert_eq!(body["data"]["domain"], "example.org");
            assert_eq!(body["errors"], expected_errors);
        }
    }

    #[tokio::test]
    async fn error_response_omits_message_when_none() {
        let resp = error_response(
            ApiError::NotFound("gone".to_string()),
            ErrorResponse::new("example.org".to_string()),
            None,
        );
        let (status, body) = into_json(resp).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(keys(&body), vec!["data", "errors", "status"]);
        assert_eq!(body["errors"], "not_found: gone");
    }

    #[test]
    fn api_error_display_is_prefixed_with_snake_case_kind() {
        assert_eq!(
            ApiError::BadRequest("Domain is too long".to_string()).to_string(),
            "bad_request: Domain is too long"
        );
        assert_eq!(
            ApiError::NotFound("Domain x not found.".to_string()).to_string(),
            "not_found: Domain x not found."
        );
        assert_eq!(
            ApiError::Conflict("busy".to_string()).to_string(),
            "conflict: busy"
        );
        assert_eq!(
            ApiError::UnprocessableEntity("invalid".to_string()).to_string(),
            "unprocessable_entity: invalid"
        );
    }

    #[test]
    fn api_error_display_masks_internal_server_error_details() {
        // The inner string must never reach the client.
        let err = ApiError::InternalServerError(
            "postgres://user:hunter2@db/internal exploded".to_string(),
        );
        let rendered = err.to_string();

        assert_eq!(rendered, MASKED_INTERNAL);
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("postgres"));
    }

    #[test]
    fn api_error_json_shape_is_externally_tagged_and_round_trips() {
        let err = ApiError::UnprocessableEntity("dns is wrong".to_string());
        assert_eq!(
            serde_json::to_value(&err).unwrap(),
            json!({"UnprocessableEntity": "dns is wrong"})
        );

        let back: ApiError = serde_json::from_value(json!({"NotFound": "nope"})).unwrap();
        assert!(matches!(back, ApiError::NotFound(ref x) if x == "nope"));
        assert_eq!(back.to_string(), "not_found: nope");

        assert!(serde_json::from_str::<ApiError>(r#"{"Teapot":"x"}"#).is_err());
    }

    #[test]
    fn repository_error_converts_to_expected_api_error() {
        let err = ApiError::from(RepositoryError::CertificateAlreadyIssued(fqdn(
            "example.org",
        )));
        assert!(matches!(err, ApiError::Conflict(_)));
        assert_eq!(
            err.to_string(),
            "conflict: Certificate for example.org already exists; reissuance is not permitted."
        );

        let err = ApiError::from(RepositoryError::AnotherTaskInProgress(fqdn("example.org")));
        assert!(matches!(err, ApiError::Conflict(_)));
        assert_eq!(
            err.to_string(),
            "conflict: Another task for example.org is already in progress. Please retry after it completes."
        );

        let err = ApiError::from(RepositoryError::DomainNotFound(fqdn("example.org")));
        assert!(matches!(err, ApiError::NotFound(_)));
        assert_eq!(err.to_string(), "not_found: Domain example.org not found.");

        let err = ApiError::from(RepositoryError::MissingCertificateForUpdate(fqdn(
            "example.org",
        )));
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert_eq!(
            err.to_string(),
            "bad_request: Cannot update domain-to-canister mapping: no valid certificate found for domain example.org."
        );
    }

    #[test]
    fn repository_error_catch_all_becomes_masked_internal_error() {
        // Variants without an explicit mapping must fall through to a 500 that
        // carries no details from the original error.
        let unmapped = [
            RepositoryError::Unauthorized,
            RepositoryError::NonExistingTaskSubmitted(1_234_567_890),
            RepositoryError::InternalError(anyhow::anyhow!("secret db failure")),
        ];

        for repo_err in unmapped {
            let original = repo_err.to_string();
            let err = ApiError::from(repo_err);

            assert!(matches!(err, ApiError::InternalServerError(ref x) if x.is_empty()));
            assert_eq!(err.to_string(), MASKED_INTERNAL);
            assert!(!err.to_string().contains(&original));
        }
    }

    #[test]
    fn validation_error_always_converts_to_bad_request_with_full_text() {
        let err = ApiError::from(ValidationError::MultipleDnsTxtCanisterId {
            src: "_canister-id.example.org.".to_string(),
            records: vec!["a".to_string(), "b".to_string()],
        });
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert_eq!(
            err.to_string(),
            r#"bad_request: multiple DNS TXT records for canister id at _canister-id.example.org.: ["a", "b"]"#
        );

        // Even an unexpected/internal validation failure is surfaced as 400.
        let err = ApiError::from(ValidationError::UnexpectedError(anyhow::anyhow!("uh oh")));
        assert!(matches!(err, ApiError::BadRequest(_)));
        assert_eq!(err.to_string(), "bad_request: uh oh");
    }

    #[test]
    fn validation_status_serializes_snake_case_and_round_trips() {
        assert_eq!(
            serde_json::to_value(ValidationStatus::Valid).unwrap(),
            json!("valid")
        );
        assert_eq!(
            serde_json::to_value(ValidationStatus::Invalid("no cname".to_string())).unwrap(),
            json!({"invalid": "no cname"})
        );

        let back: ValidationStatus = serde_json::from_value(json!("valid")).unwrap();
        assert!(matches!(back, ValidationStatus::Valid));

        let back: ValidationStatus =
            serde_json::from_value(json!({"invalid": "no cname"})).unwrap();
        assert!(matches!(back, ValidationStatus::Invalid(ref x) if x == "no cname"));

        // Unknown variants and the non-renamed spellings must be rejected.
        assert!(serde_json::from_value::<ValidationStatus>(json!("Valid")).is_err());
        assert!(serde_json::from_value::<ValidationStatus>(json!("bogus")).is_err());
        assert!(serde_json::from_value::<ValidationStatus>(json!({"invalid": 1})).is_err());
    }

    #[test]
    fn create_or_update_response_round_trips_via_textual_principal() {
        let resp = CreateOrUpdateResponse {
            domain: "example.org".to_string(),
            canister_id: principal!(CANISTER_ID),
        };

        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            value,
            json!({"domain": "example.org", "canister_id": CANISTER_ID})
        );

        let back: CreateOrUpdateResponse = serde_json::from_value(value).unwrap();
        assert_eq!(back.domain, "example.org");
        assert_eq!(back.canister_id, principal!(CANISTER_ID));
    }

    #[test]
    fn create_or_update_response_rejects_malformed_payloads() {
        // Missing field
        let err = serde_json::from_str::<CreateOrUpdateResponse>(r#"{"domain":"example.org"}"#)
            .unwrap_err();
        assert!(
            err.to_string().contains("canister_id"),
            "unexpected error: {err}"
        );

        // Unparseable principal
        let err = serde_json::from_str::<CreateOrUpdateResponse>(
            r#"{"domain":"example.org","canister_id":"not-a-principal"}"#,
        )
        .unwrap_err();
        assert!(err.is_data(), "unexpected error: {err}");

        // Wrong JSON type for the domain
        assert!(
            serde_json::from_str::<CreateOrUpdateResponse>(
                r#"{"domain":42,"canister_id":"rrkah-fqaaa-aaaaa-aaaaq-cai"}"#
            )
            .is_err()
        );

        // A principal encoded as raw bytes is not accepted by the JSON (human-readable) format
        assert!(
            serde_json::from_str::<CreateOrUpdateResponse>(
                r#"{"domain":"example.org","canister_id":[0,0,0,0,0,0,0,0,1,1]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn get_status_response_nulls_missing_canister_id_and_masks_failure_reason() {
        let resp = GetStatusResponse {
            domain: "example.org".to_string(),
            canister_id: None,
            registration_status: RegistrationStatus::Failed("ACME order 4711 rejected".to_string()),
        };

        let raw = serde_json::to_string(&resp).unwrap();
        assert!(
            !raw.contains("4711"),
            "internal failure reason leaked: {raw}"
        );

        let value: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            keys(&value),
            vec!["canister_id", "domain", "registration_status"]
        );
        assert!(value["canister_id"].is_null());
        assert_eq!(
            value["registration_status"]["failed"],
            "An unexpected error occurred during registration. Please try again later or contact support."
        );

        // The masking makes the round-trip deliberately lossy.
        let back: GetStatusResponse = serde_json::from_value(value).unwrap();
        assert_eq!(
            back.registration_status,
            RegistrationStatus::Failed(
                "An unexpected error occurred during registration. Please try again later or contact support."
                    .to_string()
            )
        );
    }

    #[test]
    fn get_status_response_round_trips_non_failed_statuses() {
        for (status, wire) in [
            (RegistrationStatus::Registering, "registering"),
            (RegistrationStatus::Registered, "registered"),
            (RegistrationStatus::Expired, "expired"),
        ] {
            let resp = GetStatusResponse {
                domain: "тест.unicode.org".to_string(),
                canister_id: Some(principal!(CANISTER_ID)),
                registration_status: status.clone(),
            };

            let value = serde_json::to_value(&resp).unwrap();
            assert_eq!(value["registration_status"], json!(wire));
            assert_eq!(value["canister_id"], json!(CANISTER_ID));

            let back: GetStatusResponse = serde_json::from_value(value).unwrap();
            assert_eq!(back.domain, "тест.unicode.org");
            assert_eq!(back.canister_id, Some(principal!(CANISTER_ID)));
            assert_eq!(back.registration_status, status);
        }
    }

    #[test]
    fn delete_and_error_responses_expose_only_the_domain() {
        let value = serde_json::to_value(DeleteResponse::new("example.org".to_string())).unwrap();
        assert_eq!(value, json!({"domain": "example.org"}));

        let value = serde_json::to_value(ErrorResponse::new("example.org".to_string())).unwrap();
        assert_eq!(value, json!({"domain": "example.org"}));

        let back: DeleteResponse = serde_json::from_value(json!({"domain": "a.org"})).unwrap();
        assert_eq!(back.domain, "a.org");
        assert!(serde_json::from_str::<ErrorResponse>("{}").is_err());
    }

    #[test]
    fn validate_response_nests_validation_status() {
        let resp = ValidateResponse {
            domain: "example.org".to_string(),
            canister_id: principal!(CANISTER_ID),
            validation_status: ValidationStatus::Invalid("missing CNAME".to_string()),
        };

        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            value,
            json!({
                "domain": "example.org",
                "canister_id": CANISTER_ID,
                "validation_status": {"invalid": "missing CNAME"},
            })
        );

        let back: ValidateResponse = serde_json::from_value(value).unwrap();
        assert!(
            matches!(back.validation_status, ValidationStatus::Invalid(ref x) if x == "missing CNAME")
        );
    }

    #[tokio::test]
    async fn api_error_serialization_keeps_internal_details_that_display_hides() {
        // `Serialize` is derived and therefore does NOT mask the inner string - only
        // `Display` does. `error_response` renders via `Display`, so the HTTP body
        // must stay clean even though the enum itself round-trips losslessly.
        let secret = "postgres://user:hunter2@db exploded";
        let err = ApiError::InternalServerError(secret.to_string());

        assert_eq!(
            serde_json::to_value(&err).unwrap(),
            json!({"InternalServerError": secret})
        );

        let back: ApiError =
            serde_json::from_value(json!({"InternalServerError": secret})).unwrap();
        assert!(matches!(back, ApiError::InternalServerError(ref x) if x == secret));
        assert_eq!(back.to_string(), MASKED_INTERNAL);

        let resp = error_response(err, ErrorResponse::new("example.org".to_string()), None);
        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["errors"], MASKED_INTERNAL);
        assert!(!body.to_string().contains("hunter2"), "leaked: {body}");
    }

    #[test]
    fn get_status_response_defaults_a_missing_canister_id_to_none() {
        // `canister_id` has no `#[serde(default)]`, but an absent `Option` field is
        // still `None`; an explicit `null` must behave identically.
        let back: GetStatusResponse =
            serde_json::from_str(r#"{"domain":"example.org","registration_status":"registered"}"#)
                .unwrap();
        assert_eq!(back.domain, "example.org");
        assert_eq!(back.canister_id, None);
        assert_eq!(back.registration_status, RegistrationStatus::Registered);

        let back: GetStatusResponse = serde_json::from_str(
            r#"{"domain":"example.org","canister_id":null,"registration_status":"registered"}"#,
        )
        .unwrap();
        assert_eq!(back.canister_id, None);
    }

    #[test]
    fn get_status_response_rejects_malformed_payloads() {
        // The status is mandatory.
        let err =
            serde_json::from_str::<GetStatusResponse>(r#"{"domain":"example.org"}"#).unwrap_err();
        assert!(
            err.to_string().contains("registration_status"),
            "unexpected error: {err}"
        );

        // Unknown variants, the non-renamed spelling, a wrongly typed `Failed`
        // payload, and the bare-string form of the newtype variant.
        for bad in [
            r#""pending""#,
            r#""Registered""#,
            r#""failed""#,
            r#"{"failed":1}"#,
            r#"{"Failed":"x"}"#,
        ] {
            assert!(
                serde_json::from_str::<GetStatusResponse>(&format!(
                    r#"{{"domain":"example.org","registration_status":{bad}}}"#
                ))
                .is_err(),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn validate_response_requires_every_field() {
        for bad in [
            r#"{"canister_id":"rrkah-fqaaa-aaaaa-aaaaq-cai","validation_status":"valid"}"#,
            r#"{"domain":"example.org","validation_status":"valid"}"#,
            r#"{"domain":"example.org","canister_id":"rrkah-fqaaa-aaaaa-aaaaq-cai"}"#,
            r#"{}"#,
        ] {
            assert!(
                serde_json::from_str::<ValidateResponse>(bad).is_err(),
                "expected {bad} to be rejected"
            );
        }
    }
}
