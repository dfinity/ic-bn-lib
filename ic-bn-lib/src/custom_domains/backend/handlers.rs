use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use candid::Principal;
use serde::Deserialize;
use tracing::warn;

use super::{
    backend_service::BackendService,
    models::{
        ApiError, CreateOrUpdateResponse, DeleteResponse, ErrorResponse, GetStatusResponse,
        ValidateResponse, error_response, success_response,
    },
};
use crate::{constant_time_eq, custom_domains::base::types::task::TaskKind};

/// Query parameters for the domain registration endpoint.
#[derive(Debug, Default, Deserialize)]
pub struct CreateQuery {
    /// When `true`, the issued certificate also covers `*.domain`.
    #[serde(default)]
    pub wildcard: bool,
    /// Canister ID to associate the domain with.
    /// Taken into account only if the bypass token is provided in the request.
    pub canister_id: Option<Principal>,
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
            ("wildcard" = Option<bool>, Query, description = "Also issue a *.domain wildcard SAN"),
            ("canister_id" = Option<String>, Query, description = "Canister ID to associate the domain with.")
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
    authorization: Option<TypedHeader<Authorization<Bearer>>>,
) -> axum::response::Response {
    // Consider the canister_id provided in the query only if the bypass token
    // is provided and matches the one configured in the backend service (if any).
    let canister_id = authorization
        .as_ref()
        .map(|x| x.token())
        .zip(backend_service.bypass_token.as_ref())
        .zip(query.canister_id)
        .and_then(|((token, bypass_token), canister_id)| {
            if constant_time_eq(token.as_bytes(), bypass_token.as_bytes()) {
                return Some(canister_id);
            }

            None
        });

    match backend_service
        .submit_task(&domain, TaskKind::Issue, query.wildcard, canister_id)
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
            ("id" = String, Path, description = "Domain name to update"),
            ("canister_id" = Option<String>, Query, description = "Canister ID to associate the domain with.")
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
    Query(query): Query<CreateQuery>,
    authorization: Option<TypedHeader<Authorization<Bearer>>>,
) -> axum::response::Response {
    // Consider the canister_id provided in the query only if the bypass token
    // is provided and matches the one configured in the backend service (if any).
    let canister_id = authorization
        .as_ref()
        .map(|x| x.token())
        .zip(backend_service.bypass_token.as_ref())
        .zip(query.canister_id)
        .and_then(|((token, bypass_token), canister_id)| {
            if constant_time_eq(token.as_bytes(), bypass_token.as_bytes()) {
                return Some(canister_id);
            }

            None
        });

    match backend_service
        .submit_task(&domain, TaskKind::Update, false, canister_id)
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

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use axum::{
        body::to_bytes,
        http::Uri,
        response::{IntoResponse, Response},
    };
    use fqdn::FQDN;
    use serde_json::Value;

    use super::*;
    use crate::{
        custom_domains::base::{
            traits::{
                repository::{MockRepository, RepositoryError},
                validation::{MockValidatesDomains, ValidationError},
            },
            types::domain::{DomainStatus, RegistrationStatus},
        },
        principal,
    };

    const BODY_LIMIT: usize = 8 * 1024;
    const CANISTER_ID: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";
    const OTHER_CANISTER_ID: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
    /// Deliberately the same length as `WRONG_TOKEN` so that a naive length check
    /// cannot distinguish them.
    const BYPASS_TOKEN: &str = "0123456789abcdef";
    const WRONG_TOKEN: &str = "0123456789abcdeg";

    fn service(
        repository: MockRepository,
        validator: MockValidatesDomains,
        bypass_token: Option<&str>,
    ) -> State<BackendService> {
        State(BackendService::new(
            Arc::new(repository),
            Arc::new(validator),
            bypass_token.map(str::to_string),
        ))
    }

    fn bearer(token: &str) -> Option<TypedHeader<Authorization<Bearer>>> {
        Some(TypedHeader(Authorization::bearer(token).unwrap()))
    }

    fn query(wildcard: bool, canister_id: Option<&str>) -> Query<CreateQuery> {
        Query(CreateQuery {
            wildcard,
            canister_id: canister_id.map(|x| Principal::from_text(x).unwrap()),
        })
    }

    async fn into_json(resp: Response) -> (StatusCode, Value) {
        let status = resp.status();
        let body = to_bytes(resp.into_body(), BODY_LIMIT).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn parse_query(uri: &str) -> Result<CreateQuery, StatusCode> {
        Query::<CreateQuery>::try_from_uri(&Uri::from_str(uri).unwrap())
            .map(|x| x.0)
            .map_err(|e| e.into_response().status())
    }

    // --- CreateQuery extractor ------------------------------------------------

    #[test]
    fn create_query_defaults_to_no_wildcard_and_no_canister_id() {
        let q = parse_query("/v1/example.org").unwrap();
        assert!(!q.wildcard);
        assert_eq!(q.canister_id, None);

        // An empty query string must behave the same way.
        let q = parse_query("/v1/example.org?").unwrap();
        assert!(!q.wildcard);
        assert_eq!(q.canister_id, None);

        let d = CreateQuery::default();
        assert!(!d.wildcard);
        assert_eq!(d.canister_id, None);
    }

    #[test]
    fn create_query_parses_wildcard_and_canister_id() {
        let q = parse_query(&format!(
            "/v1/example.org?wildcard=true&canister_id={CANISTER_ID}"
        ))
        .unwrap();
        assert!(q.wildcard);
        assert_eq!(q.canister_id, Some(principal!(CANISTER_ID)));

        let q = parse_query("/v1/example.org?wildcard=false").unwrap();
        assert!(!q.wildcard);

        // Unknown parameters are ignored rather than rejected.
        let q = parse_query("/v1/example.org?wildcard=true&unknown=42").unwrap();
        assert!(q.wildcard);
    }

    #[test]
    fn create_query_rejects_malformed_values_with_400() {
        // Only "true"/"false" are valid booleans - "1"/"yes" must not silently
        // become `false`, they must be rejected.
        for bad in ["wildcard=1", "wildcard=yes", "wildcard="] {
            assert_eq!(
                parse_query(&format!("/v1/example.org?{bad}")).unwrap_err(),
                StatusCode::BAD_REQUEST,
                "expected {bad} to be rejected"
            );
        }

        assert_eq!(
            parse_query("/v1/example.org?canister_id=not-a-principal").unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }

    // --- create_handler -------------------------------------------------------

    #[tokio::test]
    async fn create_handler_accepts_and_returns_derived_canister_id() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .times(1)
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| {
                t.kind == TaskKind::Issue
                    && t.domain == FQDN::from_str("example.org").unwrap()
                    && !t.wildcard
                    && t.canister_id.is_none()
            })
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = create_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
            query(false, None),
            None,
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "success");
        assert_eq!(body["data"]["domain"], "example.org");
        assert_eq!(body["data"]["canister_id"], CANISTER_ID);
        assert_eq!(
            body["message"],
            "Domain registration request accepted and may take a few minutes to process"
        );
        assert!(body.get("errors").is_none());
    }

    #[tokio::test]
    async fn create_handler_forwards_wildcard_flag_to_the_task() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| t.wildcard && t.kind == TaskKind::Issue)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = create_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
            query(true, None),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn create_handler_uses_query_canister_id_only_with_a_matching_bypass_token() {
        let mut validator = MockValidatesDomains::new();
        // `validate()` is intentionally not mocked: the bypass path must not call it.
        validator
            .expect_validate_limited()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| t.canister_id == Some(principal!(OTHER_CANISTER_ID)))
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = create_handler(
            service(repository, validator, Some(BYPASS_TOKEN)),
            Path("example.org".to_string()),
            query(true, Some(OTHER_CANISTER_ID)),
            bearer(BYPASS_TOKEN),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["data"]["canister_id"], OTHER_CANISTER_ID);
    }

    #[tokio::test]
    async fn create_handler_ignores_canister_id_when_token_differs_in_a_single_byte() {
        // Same length as the configured token, differing only in the last byte.
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .times(1)
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));
        // `validate_limited()` must not be called.

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| t.canister_id.is_none())
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = create_handler(
            service(repository, validator, Some(BYPASS_TOKEN)),
            Path("example.org".to_string()),
            query(false, Some(OTHER_CANISTER_ID)),
            bearer(WRONG_TOKEN),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        // The derived canister id wins, not the one from the query.
        assert_eq!(body["data"]["canister_id"], CANISTER_ID);
    }

    #[tokio::test]
    async fn create_handler_ignores_canister_id_when_no_bypass_token_is_configured() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .times(1)
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| t.canister_id.is_none())
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = create_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
            query(false, Some(OTHER_CANISTER_ID)),
            bearer(BYPASS_TOKEN),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn create_handler_rejects_an_empty_domain_without_touching_the_backend() {
        // Not reachable through the router (it 404s on `/v1/`), so exercise it directly.
        let resp = create_handler(
            service(MockRepository::new(), MockValidatesDomains::new(), None),
            Path(String::new()),
            query(false, None),
            None,
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["status"], "error");
        assert_eq!(body["data"]["domain"], "");
        assert_eq!(body["errors"], "bad_request: Domain cannot be empty");
        assert_eq!(body["message"], "Domain registration request failed");
    }

    #[tokio::test]
    async fn create_handler_masks_unmapped_repository_errors_as_500() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .returning(|_| Box::pin(async { Err(RepositoryError::Unauthorized) }));

        let resp = create_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
            query(false, None),
            None,
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["errors"],
            "internal_server_error: An unexpected error occurred. Please try again later or contact support."
        );
        assert!(!body.to_string().contains("Unauthorized"));
    }

    // --- update_handler -------------------------------------------------------

    #[tokio::test]
    async fn update_handler_never_requests_a_wildcard_even_if_asked_to() {
        // `wildcard` is only meaningful for `Issue`; `Update` must always submit `false`.
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .times(1)
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| t.kind == TaskKind::Update && !t.wildcard)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = update_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
            query(true, None),
            None,
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            body["message"],
            "Update domain registration request accepted and may take a few minutes to process"
        );
        assert_eq!(body["data"]["canister_id"], CANISTER_ID);
    }

    #[tokio::test]
    async fn update_handler_maps_missing_certificate_to_400() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));

        let mut repository = MockRepository::new();
        repository.expect_try_add_task().returning(|_| {
            Box::pin(async {
                Err(RepositoryError::MissingCertificateForUpdate(
                    FQDN::from_str("example.org").unwrap(),
                ))
            })
        });

        let resp = update_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
            query(false, None),
            None,
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["message"], "Update domain registration request failed");
        assert_eq!(
            body["errors"],
            "bad_request: Cannot update domain-to-canister mapping: no valid certificate found for domain example.org."
        );
    }

    // --- get_handler ----------------------------------------------------------

    #[tokio::test]
    async fn get_handler_returns_status_and_canister_id_from_the_repository() {
        let mut repository = MockRepository::new();
        repository
            .expect_get_domain_status()
            .times(1)
            .returning(|_| {
                Box::pin(async {
                    Ok(Some(DomainStatus {
                        domain: FQDN::from_str("example.org").unwrap(),
                        canister_id: Some(principal!(OTHER_CANISTER_ID)),
                        status: RegistrationStatus::Registering,
                    }))
                })
            });

        let resp = get_handler(
            service(repository, MockValidatesDomains::new(), None),
            Path("example.org".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["domain"], "example.org");
        assert_eq!(body["data"]["canister_id"], OTHER_CANISTER_ID);
        assert_eq!(body["data"]["registration_status"], "registering");
        assert_eq!(body["message"], "Registration status of the domain");
    }

    #[tokio::test]
    async fn get_handler_echoes_the_requested_domain_not_the_stored_one() {
        // The response must be built from the path parameter.
        let mut repository = MockRepository::new();
        repository.expect_get_domain_status().returning(|_| {
            Box::pin(async {
                Ok(Some(DomainStatus {
                    domain: FQDN::from_str("stored.example.org").unwrap(),
                    canister_id: None,
                    status: RegistrationStatus::Expired,
                }))
            })
        });

        let resp = get_handler(
            service(repository, MockValidatesDomains::new(), None),
            Path("Requested.Example.ORG".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["domain"], "Requested.Example.ORG");
        assert!(body["data"]["canister_id"].is_null());
        assert_eq!(body["data"]["registration_status"], "expired");
    }

    #[tokio::test]
    async fn get_handler_maps_a_too_long_domain_to_400_without_calling_the_repository() {
        let resp = get_handler(
            service(MockRepository::new(), MockValidatesDomains::new(), None),
            Path("a".repeat(256)),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["errors"], "bad_request: Domain is too long");
    }

    // --- validate_handler -----------------------------------------------------

    #[tokio::test]
    async fn validate_handler_reports_valid_status() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .times(1)
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));

        let resp = validate_handler(
            service(MockRepository::new(), validator, None),
            Path("example.org".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["validation_status"], "valid");
        assert_eq!(body["data"]["canister_id"], CANISTER_ID);
    }

    #[tokio::test]
    async fn validate_handler_maps_validation_failures_to_422_but_bad_domains_to_400() {
        // A failed DNS check is 422 ...
        let mut validator = MockValidatesDomains::new();
        validator.expect_validate().times(1).returning(|_| {
            Box::pin(async {
                Err(ValidationError::MissingKnownDomains {
                    id: CANISTER_ID.to_string(),
                })
            })
        });

        let resp = validate_handler(
            service(MockRepository::new(), validator, None),
            Path("example.org".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["errors"],
            format!(
                "unprocessable_entity: domain is missing from canister {CANISTER_ID} list of known domains"
            )
        );
        assert_eq!(
            body["message"],
            "Failed to validate DNS records or verify canister ownership"
        );

        // ... but a syntactically invalid domain is rejected before validation runs, as 400.
        let resp = validate_handler(
            service(MockRepository::new(), MockValidatesDomains::new(), None),
            Path("invalid..domain".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["errors"]
                .as_str()
                .unwrap()
                .starts_with("bad_request: Invalid domain format:"),
            "unexpected error: {}",
            body["errors"]
        );
    }

    // --- delete_handler -------------------------------------------------------

    #[tokio::test]
    async fn delete_handler_accepts_and_returns_only_the_domain() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate_deletion()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| t.kind == TaskKind::Delete && !t.wildcard && t.canister_id.is_none())
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = delete_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            body["data"].as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["domain"]
        );
        assert_eq!(body["data"]["domain"], "example.org");
        assert_eq!(
            body["message"],
            "Delete domain registration request accepted and may take a few minutes to process"
        );
    }

    #[tokio::test]
    async fn delete_handler_maps_deletion_validation_failure_to_400() {
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

        // `try_add_task` is intentionally not mocked: it must not be called.
        let resp = delete_handler(
            service(MockRepository::new(), validator, None),
            Path("example.org".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["errors"],
            "bad_request: existing DNS TXT _canister-id record at _canister-id.example.org."
        );
        assert_eq!(body["message"], "Delete domain registration request failed");
    }

    #[test]
    fn create_query_rejects_repeated_parameters_instead_of_picking_one() {
        // Security-relevant for `canister_id`: rather than silently choosing the
        // first or the last value, a duplicated parameter is a 400. A switch to
        // last-one-wins would let a caller smuggle a value past a check that only
        // inspected the other occurrence.
        assert_eq!(
            parse_query("/v1/example.org?wildcard=false&wildcard=true").unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            parse_query(&format!(
                "/v1/example.org?canister_id={CANISTER_ID}&canister_id={OTHER_CANISTER_ID}"
            ))
            .unwrap_err(),
            StatusCode::BAD_REQUEST
        );

        // A single occurrence of each is of course still accepted.
        let q = parse_query(&format!(
            "/v1/example.org?wildcard=true&canister_id={OTHER_CANISTER_ID}"
        ))
        .unwrap();
        assert!(q.wildcard);
        assert_eq!(q.canister_id, Some(principal!(OTHER_CANISTER_ID)));
    }

    #[tokio::test]
    async fn create_handler_ignores_canister_id_when_the_bearer_token_is_a_prefix_of_the_real_one()
    {
        // `constant_time_eq` short-circuits on a length mismatch, so a truncated
        // token must not be accepted.
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate()
            .times(1)
            .returning(|_| Box::pin(async { Ok(principal!(CANISTER_ID)) }));
        // `validate_limited()` is intentionally not mocked: it must not be called.

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| t.canister_id.is_none())
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = create_handler(
            service(repository, validator, Some(BYPASS_TOKEN)),
            Path("example.org".to_string()),
            query(false, Some(OTHER_CANISTER_ID)),
            bearer(&BYPASS_TOKEN[..BYPASS_TOKEN.len() - 1]),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        // The derived canister id wins, not the one from the query.
        assert_eq!(body["data"]["canister_id"], CANISTER_ID);
    }

    #[tokio::test]
    async fn update_handler_takes_the_bypass_canister_id_but_still_never_requests_a_wildcard() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate_limited()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut repository = MockRepository::new();
        repository
            .expect_try_add_task()
            .withf(|t| {
                t.kind == TaskKind::Update
                    && !t.wildcard
                    && t.canister_id == Some(principal!(OTHER_CANISTER_ID))
            })
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let resp = update_handler(
            service(repository, validator, Some(BYPASS_TOKEN)),
            Path("example.org".to_string()),
            // `wildcard=true` is requested, but an update must still submit `false`.
            query(true, Some(OTHER_CANISTER_ID)),
            bearer(BYPASS_TOKEN),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(body["data"]["canister_id"], OTHER_CANISTER_ID);
    }

    #[tokio::test]
    async fn get_handler_accepts_a_domain_of_exactly_255_bytes() {
        // Boundary: `parse_domain` rejects only `len() > 255`, so a valid 255-byte
        // name must reach the repository (256 is covered above). Four 63-byte
        // labels joined by three dots are exactly 255 bytes.
        let domain = vec!["a".repeat(63); 4].join(".");
        assert_eq!(domain.len(), 255);

        let mut repository = MockRepository::new();
        repository
            .expect_get_domain_status()
            .times(1)
            .returning(|_| {
                Box::pin(async {
                    Ok(Some(DomainStatus {
                        domain: FQDN::from_str("a.org").unwrap(),
                        canister_id: None,
                        status: RegistrationStatus::Registered,
                    }))
                })
            });

        let resp = get_handler(
            service(repository, MockValidatesDomains::new(), None),
            Path(domain.clone()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["domain"], domain);
        assert_eq!(body["data"]["registration_status"], "registered");
    }

    #[tokio::test]
    async fn validate_handler_rejects_an_empty_domain_without_calling_the_validator() {
        // `/v1//validate` is not routable, so exercise the guard directly.
        let resp = validate_handler(
            service(MockRepository::new(), MockValidatesDomains::new(), None),
            Path(String::new()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["errors"], "bad_request: Domain cannot be empty");
        assert_eq!(body["data"]["domain"], "");
        assert_eq!(
            body["message"],
            "Failed to validate DNS records or verify canister ownership"
        );
    }

    #[tokio::test]
    async fn delete_handler_maps_a_task_already_in_progress_to_409() {
        let mut validator = MockValidatesDomains::new();
        validator
            .expect_validate_deletion()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut repository = MockRepository::new();
        repository.expect_try_add_task().times(1).returning(|_| {
            Box::pin(async {
                Err(RepositoryError::AnotherTaskInProgress(
                    FQDN::from_str("example.org").unwrap(),
                ))
            })
        });

        let resp = delete_handler(
            service(repository, validator, None),
            Path("example.org".to_string()),
        )
        .await;

        let (status, body) = into_json(resp).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body["errors"],
            "conflict: Another task for example.org is already in progress. Please retry after it completes."
        );
        assert_eq!(body["data"]["domain"], "example.org");
        assert_eq!(body["message"], "Delete domain registration request failed");
    }
}
