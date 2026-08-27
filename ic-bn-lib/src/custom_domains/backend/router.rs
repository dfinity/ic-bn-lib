#![allow(clippy::literal_string_with_formatting_args)]

use std::sync::Arc;

use axum::{
    Router,
    extract::Request,
    middleware::from_fn_with_state,
    routing::{delete, get, patch, post},
};
use axum_extra::middleware::option_layer;
use prometheus::Registry;
use tower_http::{
    LatencyUnit,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
#[cfg(feature = "custom-domains-openapi")]
use utoipa_swagger_ui::SwaggerUi;

#[cfg(feature = "custom-domains-openapi")]
use super::openapi::get_openapi_json;
use super::{
    backend_service::BackendService,
    handlers::{create_handler, delete_handler, get_handler, update_handler, validate_handler},
    metrics::{HttpMetrics, metrics_handler, metrics_middleware},
};
use crate::{
    custom_domains::base::traits::{repository::Repository, validation::ValidatesDomains},
    http::middleware::rate_limiter::layer_by_ip,
    reqwest::StatusCode,
};

/// Options for configuring rate limits on various endpoints.
#[derive(Clone, Debug, Default)]
pub struct RateLimitConfig {
    pub limit_get: Option<u32>,
    pub limit_create: Option<u32>,
    pub limit_patch: Option<u32>,
    pub limit_delete: Option<u32>,
    pub limit_validate: Option<u32>,
}

pub fn create_router(
    repository: Arc<dyn Repository>,
    validator: Arc<dyn ValidatesDomains>,
    metrics_registry: Registry,
    rate_limits: RateLimitConfig,
    with_metrics_endpoint: bool,
    bypass_token: Option<String>,
) -> Router {
    let backend_service = BackendService::new(repository, validator, bypass_token.clone());
    let response = (StatusCode::TOO_MANY_REQUESTS, "Too many requests");

    // Use ic-bn-lib rate limiting middleware, with key by IP address.
    let create_rate_limiter = |limit: Option<u32>, response| {
        option_layer(
            limit.map(|lim| layer_by_ip(lim, 2 * lim, response, bypass_token.clone()).unwrap()),
        )
    };

    let rl_get = create_rate_limiter(rate_limits.limit_get, response);
    let rl_create = create_rate_limiter(rate_limits.limit_create, response);
    let rl_patch = create_rate_limiter(rate_limits.limit_patch, response);
    let rl_delete = create_rate_limiter(rate_limits.limit_delete, response);
    let rl_validate = create_rate_limiter(rate_limits.limit_validate, response);

    let api_router = Router::new()
        .route("/v1/{:id}", post(create_handler).layer(rl_create))
        .route("/v1/{:id}", get(get_handler).layer(rl_get))
        .route("/v1/{:id}", patch(update_handler).layer(rl_patch))
        .route("/v1/{:id}", delete(delete_handler).layer(rl_delete))
        .route(
            "/v1/{:id}/validate",
            get(validate_handler).layer(rl_validate),
        )
        .layer(from_fn_with_state(
            Arc::new(HttpMetrics::new(metrics_registry.clone())),
            metrics_middleware,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request| {
                    tracing::info_span!(
                        "custom_domains",
                        method = %req.method(),
                        url = %req.uri(),
                        http = ?req.version(),
                    )
                })
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(
                    DefaultOnResponse::new()
                        .level(Level::INFO)
                        .latency_unit(LatencyUnit::Seconds),
                ),
        )
        .with_state(backend_service);

    // Optionally add /metrics endpoint
    let metrics_router = if with_metrics_endpoint {
        Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(metrics_registry)
    } else {
        Router::new()
    };

    #[cfg(feature = "custom-domains-openapi")]
    let router = {
        let swagger_ui =
            SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", get_openapi_json());
        api_router.merge(metrics_router).merge(swagger_ui)
    };
    #[cfg(not(feature = "custom-domains-openapi"))]
    let router = api_router.merge(metrics_router);

    router
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr, sync::Arc};

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use fqdn::FQDN;
    use prometheus::Registry;
    use serde_json::Value;
    use tower::{Service, util::ServiceExt};

    use crate::{
        custom_domains::{
            backend::router::{RateLimitConfig, create_router},
            base::{
                traits::{
                    repository::{MockRepository, RepositoryError},
                    validation::{MockValidatesDomains, ValidationError},
                },
                types::{
                    domain::{DomainStatus, RegistrationStatus},
                    task::{InputTask, TaskKind},
                },
            },
        },
        http::middleware::RemoteAddr,
        principal,
    };

    const BODY_LIMIT: usize = 5000;

    /// Helper function to create a router with mocked dependencies
    fn create_test_router(
        mock_repository: MockRepository,
        mock_validator: MockValidatesDomains,
    ) -> axum::Router {
        let registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
        create_router(
            Arc::new(mock_repository),
            Arc::new(mock_validator),
            registry,
            RateLimitConfig::default(),
            true,
            None,
        )
    }

    fn create_test_router_with_rate_limiter(
        mock_repository: MockRepository,
        mock_validator: MockValidatesDomains,
        rate_limits: RateLimitConfig,
    ) -> axum::Router {
        let registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
        create_router(
            Arc::new(mock_repository),
            Arc::new(mock_validator),
            registry,
            rate_limits,
            true,
            None,
        )
    }

    /// Helper function to make a POST request to /v1/{domain}
    async fn post_domain_request(router: axum::Router, domain: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/{domain}"))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body_json)
    }

    #[tokio::test]
    async fn test_post_domain_success_accepted() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let expected_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .returning(move |_| Box::pin(async move { Ok(expected_canister_id) }));

        let mut mock_repository = MockRepository::new();
        let domain_normal = "example.org";
        let subdomain_unicode = "тест.unicode.org";

        let expected_task_normal = InputTask::new(
            TaskKind::Issue,
            FQDN::from_str(domain_normal).unwrap(),
            false,
        );
        let expected_task_unicode = InputTask::new(
            TaskKind::Issue,
            FQDN::from_str(subdomain_unicode).unwrap(),
            false,
        );
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_normal)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_unicode)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router.clone(), domain_normal).await;
        let (status_unicode, response_json_unicode) =
            post_domain_request(router, subdomain_unicode).await;

        // Assert
        for (status, response_json, domain) in [
            (status, response_json, domain_normal),
            (status_unicode, response_json_unicode, subdomain_unicode),
        ] {
            assert_eq!(status, StatusCode::ACCEPTED);
            assert_eq!(response_json["status"], "success");
            assert_eq!(response_json["data"]["domain"], domain);
            assert_eq!(
                response_json["data"]["canister_id"],
                "rrkah-fqaaa-aaaaa-aaaaq-cai"
            );
            assert_eq!(
                response_json["message"].as_str().unwrap(),
                "Domain registration request accepted and may take a few minutes to process"
            );
        }
    }

    #[tokio::test]
    async fn test_post_domain_conflict_certificate_already_issued() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(principal!("rrkah-fqaaa-aaaaa-aaaaq-cai")) })
        });

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            let domain = FQDN::from_str(domain).unwrap();
            Box::pin(async { Err(RepositoryError::CertificateAlreadyIssued(domain)) })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, domain).await;

        // Assert
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response_json["status"], "error");
        assert_eq!(
            response_json["message"],
            "Domain registration request failed"
        );
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            format!(
                "conflict: Certificate for {domain} already exists; reissuance is not permitted."
            )
        );
    }

    #[tokio::test]
    async fn test_post_domain_conflict_another_task_in_progress() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(principal!("rrkah-fqaaa-aaaaa-aaaaq-cai")) })
        });

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            let domain = FQDN::from_str(domain).unwrap();
            Box::pin(async { Err(RepositoryError::AnotherTaskInProgress(domain)) })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, domain).await;

        // Assert
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], domain);
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            format!(
                "conflict: Another task for {domain} is already in progress. Please retry after it completes."
            )
        );
    }

    #[tokio::test]
    async fn test_post_domain_bad_request_invalid_domain() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "invalid..domain").await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], "invalid..domain");
        assert!(
            response_json["errors"]
                .as_str()
                .unwrap()
                .contains("Invalid domain")
        );
    }

    #[tokio::test]
    async fn test_post_domain_bad_request_with_validation_error() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async {
                Err(ValidationError::MissingDnsCname {
                    src: "_acme-challenge.example.org.".to_string(),
                    dst: "_acme-challenge.example.org.icp2.io.".to_string(),
                })
            })
        });

        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "bad_request: missing DNS CNAME record from _acme-challenge.example.org. to _acme-challenge.example.org.icp2.io."
        )
    }

    #[tokio::test]
    async fn test_post_domain_internal_server_error_repository_failure() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(principal!("rrkah-fqaaa-aaaaa-aaaaq-cai")) })
        });

        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            Box::pin(async {
                Err(RepositoryError::InternalError(anyhow::anyhow!(
                    "Some internal error"
                )))
            })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = post_domain_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["errors"],
            "internal_server_error: An unexpected error occurred. Please try again later or contact support."
        );
    }

    #[tokio::test]
    async fn test_post_domain_very_long_domain() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let long_domain = "a".repeat(250) + ".example.org";
        let (status, response_json) = post_domain_request(router, &long_domain).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["errors"], "bad_request: Domain is too long");
    }

    /// Helper function to make a GET request to /v1/{domain}/status
    async fn get_domain_status_request(router: axum::Router, domain: &str) -> (StatusCode, Value) {
        let uri = format!("/v1/{domain}");
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body_json)
    }

    #[tokio::test]
    async fn test_get_domain_status_success_various_statuses() {
        let test_cases = vec![
            ("registered", RegistrationStatus::Registered),
            ("registering", RegistrationStatus::Registering),
            ("expired", RegistrationStatus::Expired),
        ];

        let domains = vec!["example.org", "тест.unicode.org"];

        for (expected_status_str, registration_status) in test_cases {
            for domain in &domains {
                // Arrange
                let mock_validator = MockValidatesDomains::new();
                let mut mock_repository = MockRepository::new();

                let expected_canister_id =
                    principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
                let domain_status = DomainStatus {
                    domain: FQDN::from_str(domain).unwrap(),
                    canister_id: Some(expected_canister_id),
                    status: registration_status.clone(),
                };

                mock_repository
                    .expect_get_domain_status()
                    .returning(move |_| {
                        let status = domain_status.clone();
                        Box::pin(async move { Ok(Some(status)) })
                    });

                let router = create_test_router(mock_repository, mock_validator);

                // Act
                let (status, response_json) = get_domain_status_request(router, domain).await;

                // Assert
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "Failed for status: {expected_status_str} with domain: {domain}",
                );
                assert_eq!(response_json["status"], "success");
                assert_eq!(response_json["data"]["domain"], *domain);
                assert_eq!(
                    response_json["data"]["canister_id"],
                    "rrkah-fqaaa-aaaaa-aaaaq-cai"
                );
                assert_eq!(
                    response_json["data"]["registration_status"],
                    expected_status_str
                );
                assert_eq!(
                    response_json["message"].as_str().unwrap(),
                    "Registration status of the domain"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_get_domain_status_success_failed() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mut mock_repository = MockRepository::new();

        let failure_message = "some failure message";
        let domain_status = DomainStatus {
            domain: FQDN::from_str("example.org").unwrap(),
            canister_id: None,
            status: RegistrationStatus::Failed(failure_message.to_string()),
        };

        mock_repository
            .expect_get_domain_status()
            .returning(move |_| {
                let status = domain_status.clone();
                Box::pin(async move { Ok(Some(status)) })
            });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = get_domain_status_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response_json["status"], "success");
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert!(response_json["data"]["canister_id"].is_null());
        // Important: internal failure message is not exposed in API response
        assert_eq!(
            response_json["data"]["registration_status"]["failed"],
            "An unexpected error occurred during registration. Please try again later or contact support."
        );
        assert_eq!(
            response_json["message"].as_str().unwrap(),
            "Registration status of the domain"
        );
    }

    #[tokio::test]
    async fn test_get_domain_status_not_found() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mut mock_repository = MockRepository::new();

        mock_repository
            .expect_get_domain_status()
            .returning(|_| Box::pin(async move { Ok(None) }));

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = get_domain_status_request(router, "nonexistent.org").await;

        // Assert
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], "nonexistent.org");
        assert_eq!(
            response_json["message"].as_str().unwrap(),
            "Registration status request failed"
        );
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "not_found: Domain nonexistent.org not found"
        );
    }

    #[tokio::test]
    async fn test_get_domain_status_bad_request_invalid_domain() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = get_domain_status_request(router, "invalid..domain").await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], "invalid..domain");
        assert_eq!(
            response_json["message"].as_str().unwrap(),
            "Registration status request failed"
        );
        assert!(
            response_json["errors"]
                .as_str()
                .unwrap()
                .contains("Invalid domain")
        );
    }

    #[tokio::test]
    async fn test_get_domain_status_bad_request_empty_domain() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let uri = "/v1/".to_string(); // Missing domain
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();

        // Assert
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_domain_status_bad_request_very_long_domain() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let long_domain = "a".repeat(250) + ".example.org";
        let (status, response_json) = get_domain_status_request(router, &long_domain).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], long_domain);
        assert_eq!(
            response_json["message"].as_str().unwrap(),
            "Registration status request failed"
        );
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "bad_request: Domain is too long"
        );
    }

    #[tokio::test]
    async fn test_get_domain_status_internal_server_error_repository_failure() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mut mock_repository = MockRepository::new();

        mock_repository.expect_get_domain_status().returning(|_| {
            Box::pin(async {
                Err(RepositoryError::InternalError(anyhow::anyhow!(
                    "some real internal error"
                )))
            })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = get_domain_status_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["message"].as_str().unwrap(),
            "Registration status request failed"
        );
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "internal_server_error: An unexpected error occurred. Please try again later or contact support."
        );
    }

    #[tokio::test]
    async fn test_get_domain_status_invalid_path() {
        // Arrange
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act: request with wrong path
        let request = Request::builder()
            .method("GET")
            .uri("/v1/example.org/wrong-path")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Helper function to make a GET request to /v1/{domain}/validate
    async fn get_domain_validate_request(
        router: axum::Router,
        domain: &str,
    ) -> (StatusCode, Value) {
        let uri = format!("/v1/{domain}/validate");
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body_json)
    }

    #[tokio::test]
    async fn test_get_domain_validate_success() {
        let domains = vec!["example.org", "тест.unicode.org"];

        for domain in &domains {
            // Arrange
            let mut mock_validator = MockValidatesDomains::new();
            let expected_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");

            mock_validator
                .expect_validate()
                .returning(move |_| Box::pin(async move { Ok(expected_canister_id) }));

            let mock_repository = MockRepository::new();
            let router = create_test_router(mock_repository, mock_validator);

            // Act
            let (status, response_json) = get_domain_validate_request(router, domain).await;

            // Assert
            assert_eq!(status, StatusCode::OK,);
            assert_eq!(response_json["status"], "success");
            assert_eq!(response_json["data"]["domain"], *domain);
            assert_eq!(
                response_json["data"]["canister_id"],
                "rrkah-fqaaa-aaaaa-aaaaq-cai"
            );
            assert_eq!(response_json["data"]["validation_status"], "valid");
            assert_eq!(
                response_json["message"].as_str().unwrap(),
                "Domain is eligible for registration: DNS records are valid and canister ownership is verified"
            );
        }
    }

    #[tokio::test]
    async fn test_get_domain_validate_invalid_dns_record() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async {
                Err(ValidationError::MissingDnsCname {
                    src: "_acme-challenge.example.org.".to_string(),
                    dst: "_acme-challenge.example.org.icp2.io.".to_string(),
                })
            })
        });

        let mock_repository = MockRepository::new();
        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = get_domain_validate_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response_json["status"], "error");
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["message"].as_str().unwrap(),
            "Failed to validate DNS records or verify canister ownership"
        );
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "unprocessable_entity: missing DNS CNAME record from _acme-challenge.example.org. to _acme-challenge.example.org.icp2.io."
        );
    }

    /// Helper function to make a PATCH request to /v1/{domain}
    async fn domain_update_request(router: axum::Router, domain: &str) -> (StatusCode, Value) {
        let uri = format!("/v1/{domain}");
        let request = Request::builder()
            .method("PATCH")
            .uri(uri)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body_json)
    }

    #[tokio::test]
    async fn test_post_domain_update_success_accepted() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let expected_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .returning(move |_| Box::pin(async move { Ok(expected_canister_id) }));

        let mut mock_repository = MockRepository::new();
        let domain_normal = "example.org";
        let subdomain_unicode = "тест.unicode.org";

        let expected_task_normal = InputTask::new(
            TaskKind::Update,
            FQDN::from_str(domain_normal).unwrap(),
            false,
        );
        let expected_task_unicode = InputTask::new(
            TaskKind::Update,
            FQDN::from_str(subdomain_unicode).unwrap(),
            false,
        );
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_normal)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_unicode)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = domain_update_request(router.clone(), domain_normal).await;
        let (status_unicode, response_json_unicode) =
            domain_update_request(router, subdomain_unicode).await;

        // Assert
        for (status, response_json, domain) in [
            (status, response_json, domain_normal),
            (status_unicode, response_json_unicode, subdomain_unicode),
        ] {
            assert_eq!(status, StatusCode::ACCEPTED);
            assert_eq!(response_json["status"], "success");
            assert_eq!(response_json["data"]["domain"], domain);
            assert_eq!(
                response_json["data"]["canister_id"],
                "rrkah-fqaaa-aaaaa-aaaaq-cai"
            );
            assert_eq!(
                response_json["message"].as_str().unwrap(),
                "Update domain registration request accepted and may take a few minutes to process"
            );
        }
    }

    #[tokio::test]
    async fn test_post_domain_update_bad_request_missing_certificate() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator.expect_validate().returning(|_| {
            Box::pin(async { Ok(principal!("rrkah-fqaaa-aaaaa-aaaaq-cai")) })
        });

        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            let domain = FQDN::from_str("example.org").unwrap();
            Box::pin(async { Err(RepositoryError::MissingCertificateForUpdate(domain)) })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = domain_update_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(
            response_json["message"],
            "Update domain registration request failed"
        );
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "bad_request: Cannot update domain-to-canister mapping: no valid certificate found for domain example.org."
        );
    }

    /// Helper function to make a DELETE request to /v1/{domain}
    async fn delete_domain_request(router: axum::Router, domain: &str) -> (StatusCode, Value) {
        let uri = format!("/v1/{domain}");
        let request = Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body_json)
    }

    #[tokio::test]
    async fn test_delete_domain_success_accepted() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator
            .expect_validate_deletion()
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut mock_repository = MockRepository::new();
        let domain_normal = "example.org";
        let subdomain_unicode = "тест.unicode.org";

        let expected_task_normal = InputTask::new(
            TaskKind::Delete,
            FQDN::from_str(domain_normal).unwrap(),
            false,
        );
        let expected_task_unicode = InputTask::new(
            TaskKind::Delete,
            FQDN::from_str(subdomain_unicode).unwrap(),
            false,
        );
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_normal)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task_unicode)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = delete_domain_request(router.clone(), domain_normal).await;
        let (status_unicode, response_json_unicode) =
            delete_domain_request(router, subdomain_unicode).await;

        // Assert
        for (status, response_json, domain) in [
            (status, response_json, domain_normal),
            (status_unicode, response_json_unicode, subdomain_unicode),
        ] {
            assert_eq!(status, StatusCode::ACCEPTED);
            assert_eq!(response_json["status"], "success");
            assert_eq!(response_json["data"]["domain"], domain);
            assert!(response_json["data"]["canister_id"].is_null());
            assert_eq!(
                response_json["message"].as_str().unwrap(),
                "Delete domain registration request accepted and may take a few minutes to process"
            );
        }
    }

    #[tokio::test]
    async fn test_delete_domain_not_found() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator
            .expect_validate_deletion()
            .returning(|_| Box::pin(async { Ok(()) }));

        let mut mock_repository = MockRepository::new();
        mock_repository.expect_try_add_task().returning(|_| {
            let domain = FQDN::from_str("example.org").unwrap();
            Box::pin(async { Err(RepositoryError::DomainNotFound(domain)) })
        });

        let router = create_test_router(mock_repository, mock_validator);

        // Act
        let (status, response_json) = delete_domain_request(router, "example.org").await;

        // Assert
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(response_json["status"], "error");
        assert_eq!(
            response_json["message"],
            "Delete domain registration request failed"
        );
        assert_eq!(response_json["data"]["domain"], "example.org");
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "not_found: Domain example.org not found."
        );
    }

    #[tokio::test]
    async fn test_rate_limiting_by_ip() {
        use tower::ServiceExt;

        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let expected_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .returning(move |_| Box::pin(async move { Ok(expected_canister_id) }))
            .times(2); // Only two requests should reach this point

        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .returning(|_| Box::pin(async { Ok(()) }))
            .times(2); // Only two requests should reach this point

        // Add additional rate-limiter for POST endpoint
        let rate_limits = RateLimitConfig {
            limit_create: Some(1),
            ..Default::default()
        };

        let router =
            create_test_router_with_rate_limiter(mock_repository, mock_validator, rate_limits);
        let test_ip = IpAddr::from_str("192.168.1.100").unwrap();

        // Create a service that maintains state between calls (needed for rate limiting)
        let mut service = router.into_service();

        let request1 = Request::builder()
            .method("POST")
            .uri("/v1/example1.org")
            .extension(RemoteAddr(test_ip))
            .body(Body::empty())
            .unwrap();

        let request2 = Request::builder()
            .method("POST")
            .uri("/v1/example2.org")
            .extension(RemoteAddr(test_ip))
            .body(Body::empty())
            .unwrap();

        // Should be rate-limited, as it's 3nd request from the same IP
        let request3 = Request::builder()
            .method("POST")
            .uri("/v1/example3.org")
            .extension(RemoteAddr(test_ip))
            .body(Body::empty())
            .unwrap();

        // Act
        let response1 = service.ready().await.unwrap().call(request1).await.unwrap();
        let response2 = service.ready().await.unwrap().call(request2).await.unwrap();
        let response3 = service.ready().await.unwrap().call(request3).await.unwrap();

        // Assert
        let status1 = response1.status();
        assert_eq!(status1, StatusCode::ACCEPTED);
        let status2 = response2.status();
        assert_eq!(status2, StatusCode::ACCEPTED);
        let status3 = response3.status();
        assert_eq!(status3, StatusCode::TOO_MANY_REQUESTS);
        let body_bytes = to_bytes(response3.into_body(), BODY_LIMIT).await.unwrap();
        assert_eq!(body_bytes.to_vec(), b"Too many requests");
    }

    // --- Bypass token & custom canister_id tests ---

    const BYPASS_TOKEN: &str = "s3cr3t-bypass-token";
    const OVERRIDE_CANISTER_ID: &str = "aaaaa-aa";

    /// Helper function to create a router with a bypass token configured on the backend service.
    fn create_test_router_with_bypass_token(
        mock_repository: MockRepository,
        mock_validator: MockValidatesDomains,
        bypass_token: Option<String>,
    ) -> axum::Router {
        let registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
        create_router(
            Arc::new(mock_repository),
            Arc::new(mock_validator),
            registry,
            RateLimitConfig::default(),
            true,
            bypass_token,
        )
    }

    /// Helper function to make a request to /v1/{domain} with an optional query string and an
    /// optional `Authorization` header, parsing the response body as JSON.
    async fn domain_request_with_query_and_auth(
        router: axum::Router,
        method: &str,
        domain: &str,
        query: Option<&str>,
        auth_header: Option<&str>,
    ) -> (StatusCode, Value) {
        let uri = query.map_or_else(
            || format!("/v1/{domain}"),
            |query| format!("/v1/{domain}?{query}"),
        );
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(auth) = auth_header {
            builder = builder.header("authorization", auth);
        }
        let request = builder.body(Body::empty()).unwrap();

        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), BODY_LIMIT).await.unwrap();
        let body_json: Value = serde_json::from_slice(&body_bytes).unwrap();
        (status, body_json)
    }

    #[tokio::test]
    async fn test_post_domain_bypass_token_and_canister_id_uses_limited_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator
            .expect_validate_limited()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));
        // `validate()` is intentionally left unmocked: it must not be called on the bypass path.

        let domain = "example.org";
        let expected_task =
            InputTask::new(TaskKind::Issue, FQDN::from_str(domain).unwrap(), false);
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "POST",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response_json["status"], "success");
        assert_eq!(response_json["data"]["domain"], domain);
        assert_eq!(response_json["data"]["canister_id"], OVERRIDE_CANISTER_ID);
    }

    #[tokio::test]
    async fn test_post_domain_wrong_bypass_token_falls_back_to_full_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));
        // `validate_limited()` is intentionally left unmocked: it must not be called when the
        // provided token doesn't match the configured bypass token.

        let domain = "example.org";
        let expected_task =
            InputTask::new(TaskKind::Issue, FQDN::from_str(domain).unwrap(), false);
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "POST",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some("Bearer this-is-not-the-right-token"),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_post_domain_canister_id_without_auth_header_uses_full_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act: canister_id is provided but there's no Authorization header at all
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "POST",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            None,
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_post_domain_valid_bypass_token_without_canister_id_uses_full_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act: correct bypass token, but no canister_id query param
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "POST",
            domain,
            None,
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_post_domain_no_bypass_token_configured_ignores_header_and_canister_id() {
        // Arrange: backend service has no bypass token configured at all
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router =
            create_test_router_with_bypass_token(mock_repository, mock_validator, None);

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "POST",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_post_domain_bypass_token_validate_limited_error() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator
            .expect_validate_limited()
            .times(1)
            .returning(|_| {
                Box::pin(async {
                    Err(ValidationError::MissingDnsCname {
                        src: "_acme-challenge.example.org.".to_string(),
                        dst: "_acme-challenge.example.org.icp2.io.".to_string(),
                    })
                })
            });

        let mock_repository = MockRepository::new();
        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "POST",
            "example.org",
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "bad_request: missing DNS CNAME record from _acme-challenge.example.org. to _acme-challenge.example.org.icp2.io."
        );
    }

    #[tokio::test]
    async fn test_post_domain_malformed_authorization_header_is_rejected() {
        // Arrange: a non-Bearer Authorization header should be rejected by the extractor
        // itself, before the bypass logic ever runs.
        let mock_validator = MockValidatesDomains::new();
        let mock_repository = MockRepository::new();
        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/example.org?canister_id={OVERRIDE_CANISTER_ID}"))
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_patch_domain_bypass_token_and_canister_id_uses_limited_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator
            .expect_validate_limited()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));
        // `validate()` is intentionally left unmocked: it must not be called on the bypass path.

        let domain = "example.org";
        let expected_task =
            InputTask::new(TaskKind::Update, FQDN::from_str(domain).unwrap(), false);
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "PATCH",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(response_json["status"], "success");
        assert_eq!(response_json["data"]["domain"], domain);
        assert_eq!(response_json["data"]["canister_id"], OVERRIDE_CANISTER_ID);
    }

    #[tokio::test]
    async fn test_patch_domain_wrong_bypass_token_falls_back_to_full_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));
        // `validate_limited()` is intentionally left unmocked: it must not be called when the
        // provided token doesn't match the configured bypass token.

        let domain = "example.org";
        let expected_task =
            InputTask::new(TaskKind::Update, FQDN::from_str(domain).unwrap(), false);
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .withf(move |task| *task == expected_task)
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "PATCH",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some("Bearer this-is-not-the-right-token"),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_patch_domain_canister_id_without_auth_header_uses_full_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act: canister_id is provided but there's no Authorization header at all
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "PATCH",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            None,
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_patch_domain_valid_bypass_token_without_canister_id_uses_full_validation() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act: correct bypass token, but no canister_id query param
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "PATCH",
            domain,
            None,
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_patch_domain_no_bypass_token_configured_ignores_header_and_canister_id() {
        // Arrange: backend service has no bypass token configured at all
        let mut mock_validator = MockValidatesDomains::new();
        let derived_canister_id = principal!("rrkah-fqaaa-aaaaa-aaaaq-cai");
        mock_validator
            .expect_validate()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(derived_canister_id) }));

        let domain = "example.org";
        let mut mock_repository = MockRepository::new();
        mock_repository
            .expect_try_add_task()
            .times(1)
            .returning(|_| Box::pin(async { Ok(()) }));

        let router =
            create_test_router_with_bypass_token(mock_repository, mock_validator, None);

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "PATCH",
            domain,
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            response_json["data"]["canister_id"],
            "rrkah-fqaaa-aaaaa-aaaaq-cai"
        );
    }

    #[tokio::test]
    async fn test_patch_domain_bypass_token_validate_limited_error() {
        // Arrange
        let mut mock_validator = MockValidatesDomains::new();
        mock_validator
            .expect_validate_limited()
            .times(1)
            .returning(|_| {
                Box::pin(async {
                    Err(ValidationError::MissingDnsCname {
                        src: "_acme-challenge.example.org.".to_string(),
                        dst: "_acme-challenge.example.org.icp2.io.".to_string(),
                    })
                })
            });

        let mock_repository = MockRepository::new();
        let router = create_test_router_with_bypass_token(
            mock_repository,
            mock_validator,
            Some(BYPASS_TOKEN.to_string()),
        );

        // Act
        let (status, response_json) = domain_request_with_query_and_auth(
            router,
            "PATCH",
            "example.org",
            Some(&format!("canister_id={OVERRIDE_CANISTER_ID}")),
            Some(&format!("Bearer {BYPASS_TOKEN}")),
        )
        .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response_json["status"], "error");
        assert_eq!(
            response_json["errors"].as_str().unwrap(),
            "bad_request: missing DNS CNAME record from _acme-challenge.example.org. to _acme-challenge.example.org.icp2.io."
        );
    }
}
