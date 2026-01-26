use std::{
    net::IpAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use ::governor::{clock::QuantaInstant, middleware::NoOpMiddleware};
use anyhow::{Error, anyhow};
use axum::{body::Body, extract::Request, response::IntoResponse, response::Response};
use futures::future::BoxFuture;
use http::{HeaderName, HeaderValue, StatusCode};
use tower::{Layer, Service};
use tower_governor::{
    GovernorError, GovernorLayer,
    governor::{Governor, GovernorConfig, GovernorConfigBuilder},
    key_extractor::{GlobalKeyExtractor, KeyExtractor},
};

use crate::{hname, http::middleware::extract_ip_from_request};

pub type GovernorLayerAxum<K> = GovernorLayer<K, NoOpMiddleware<QuantaInstant>, Body>;

const BYPASS_HEADER: HeaderName = hname!("x-ratelimit-bypass-token");

/// Extracts an IP from the request as a rate-limiting key
#[derive(Clone)]
pub struct IpKeyExtractor;

impl KeyExtractor for IpKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        extract_ip_from_request(req).ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Ratelimiter that implements Tower Service
#[derive(Clone)]
pub struct RateLimiter<S, K: KeyExtractor> {
    governor: Governor<K, NoOpMiddleware<QuantaInstant>, S, Body>,
    bypass_token: Option<String>,
    inner: S,
}

/// Implement Tower Service for RateLimiter
impl<S, K> Service<Request> for RateLimiter<S, K>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    K: KeyExtractor,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // Check that bypass token is configured, header was sent and it matches
        let bypass = request
            .headers()
            .get(BYPASS_HEADER)
            .zip(self.bypass_token.as_ref())
            .map(|(hdr, token)| hdr.as_bytes() == token.as_bytes())
            == Some(true);

        // If bypassing - call the wrapped service directly
        if bypass {
            let fut = self.inner.call(request);
            return Box::pin(fut);
        }

        // Otherwise go through Governor
        let fut = self.governor.call(request);
        Box::pin(fut)
    }
}

/// Layer usable as an Axum middleware
#[derive(Clone, derive_new::new)]
pub struct RateLimiterLayer<K: KeyExtractor, R> {
    config: Arc<GovernorConfig<K, NoOpMiddleware<QuantaInstant>>>,
    rate_limited_response: R,
    bypass_token: Option<String>,
}

impl<S, K, R> Layer<S> for RateLimiterLayer<K, R>
where
    S: Clone,
    K: KeyExtractor,
    R: IntoResponse + Clone + Send + Sync + 'static,
{
    type Service = RateLimiter<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        let rate_limited_response = self.rate_limited_response.clone();

        let governor = Governor::new(inner.clone(), &self.config).error_handler(move |err| {
            match err {
                GovernorError::TooManyRequests { wait_time, headers: _ } => {
                    let mut response = rate_limited_response.clone().into_response();
                    
                    // Add Retry-After header using timing from governor
                    // wait_time is in milliseconds, convert to seconds (minimum 1 second)
                    let retry_secs = ((wait_time / 1000).max(1)) as u32;
                    if let Ok(header_value) = HeaderValue::from_str(&retry_secs.to_string()) {
                        response.headers_mut().insert(http::header::RETRY_AFTER, header_value);
                    }
                    
                    response
                },
                GovernorError::UnableToExtractKey => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Unable to extract rate limiting key",
                )
                    .into_response(),
                GovernorError::Other { code, msg, headers } => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Rate limiter failed unexpectedly: code={code}, msg={msg:?}, headers={headers:?}"
                    ),
                )
                    .into_response()
            }
        });

        RateLimiter {
            governor,
            bypass_token: self.bypass_token.clone(),
            inner,
        }
    }
}

/// Create unkeyed rate-limiter
pub fn layer_global<R: IntoResponse + Clone + Send + Sync + 'static>(
    rps: u32,
    burst_size: u32,
    rate_limited_response: R,
    bypass_token: Option<String>,
) -> Result<RateLimiterLayer<GlobalKeyExtractor, R>, Error> {
    layer(
        rps,
        burst_size,
        GlobalKeyExtractor,
        rate_limited_response,
        bypass_token,
    )
}

/// Create ratelimiter keyed by IP
pub fn layer_by_ip<R: IntoResponse + Clone + Send + Sync + 'static>(
    rps: u32,
    burst_size: u32,
    rate_limited_response: R,
    bypass_token: Option<String>,
) -> Result<RateLimiterLayer<IpKeyExtractor, R>, Error> {
    layer(
        rps,
        burst_size,
        IpKeyExtractor,
        rate_limited_response,
        bypass_token,
    )
}

/// Create a ratelimiter with a provided key extractor
pub fn layer<K: KeyExtractor, R: IntoResponse + Clone + Send + Sync + 'static>(
    rps: u32,
    burst_size: u32,
    key_extractor: K,
    rate_limited_response: R,
    bypass_token: Option<String>,
) -> Result<RateLimiterLayer<K, R>, Error> {
    let period = Duration::from_secs(1)
        .checked_div(rps)
        .ok_or_else(|| anyhow!("RPS is zero"))?;

    let config = GovernorConfigBuilder::default()
        .period(period)
        .burst_size(burst_size)
        .key_extractor(key_extractor)
        .finish()
        .ok_or_else(|| anyhow!("unable to build governor config"))?;

    Ok(RateLimiterLayer::new(
        Arc::new(config),
        rate_limited_response,
        bypass_token,
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::Request,
        response::IntoResponse,
        routing::post,
    };
    use http::{Method, StatusCode};
    use ic_bn_lib_common::types::http::ConnInfo;
    use std::{sync::Arc, time::Duration};
    use tokio::time::sleep;
    use tower::Service;

    async fn handler(_request: Request<Body>) -> impl IntoResponse {
        "test_call"
    }

    async fn send_request(
        router: &mut Router,
    ) -> Result<http::Response<Body>, std::convert::Infallible> {
        let conn_info = ConnInfo::default();
        let mut request = Request::post("/").body(Body::from("".to_string())).unwrap();
        request.extensions_mut().insert(Arc::new(conn_info));
        router.call(request).await
    }

    #[tokio::test]
    async fn test_rate_limiter_rps_limit() {
        let rps = 5;
        let burst_size = 5; // how many requests can go through at once (without delay)

        let rate_limiter_mw = layer(
            rps,
            burst_size,
            IpKeyExtractor,
            (StatusCode::TOO_MANY_REQUESTS, "foo"),
            None,
        )
        .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // Test cases: (delay_ms, expected_status)
        let delay_for_token_ms = 230; // when a token should become available ~ 1000ms/rps=200ms (we add some delta=30 ms to avoid flakiness)
        let test_cases = vec![
            // Initial burst of 5 requests should succeed and fills full burst capacity
            (0, StatusCode::OK),
            (0, StatusCode::OK),
            (0, StatusCode::OK),
            (0, StatusCode::OK),
            (0, StatusCode::OK),
            // For 6th request no tokens left => 429
            (0, StatusCode::TOO_MANY_REQUESTS),
            // Wait for 1 token to be available
            (delay_for_token_ms, StatusCode::OK),
            // Bucket is empty again, request should fail
            (0, StatusCode::TOO_MANY_REQUESTS),
            // Wait for 2 tokens to be available, next 2 requests succeed
            (2 * delay_for_token_ms, StatusCode::OK),
            (0, StatusCode::OK),
            // Bucket is empty again, request should fail
            (0, StatusCode::TOO_MANY_REQUESTS),
            // Wait for 5 tokens, next 5 requests succeed
            (5 * delay_for_token_ms, StatusCode::OK),
            (0, StatusCode::OK),
            (0, StatusCode::OK),
            (0, StatusCode::OK),
            (0, StatusCode::OK),
            // Bucket is empty again, requests should fail
            (0, StatusCode::TOO_MANY_REQUESTS),
            (0, StatusCode::TOO_MANY_REQUESTS),
        ];

        // Execute all tests
        for (idx, (delay_ms, expected_status)) in test_cases.into_iter().enumerate() {
            if delay_ms > 0 {
                sleep(Duration::from_millis(delay_ms)).await;
            }
            let result = send_request(&mut app).await.unwrap();
            assert_eq!(result.status(), expected_status, "test {idx} failed");
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_server_error() {
        let rps = 1;
        let burst_size = 1;

        let rate_limiter_mw = layer(
            rps,
            burst_size,
            IpKeyExtractor,
            (StatusCode::TOO_MANY_REQUESTS, "foo"),
            None,
        )
        .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // Send request without connection info, i.e. without ip address.
        let request = Request::post("/").body(Body::from("".to_string())).unwrap();
        let result = app.call(request).await.unwrap();

        assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(result.into_body(), 1024).await.unwrap().to_vec();
        assert_eq!(body, b"Unable to extract rate limiting key");
    }

    #[tokio::test]
    async fn test_rate_limiter_bypass_token() {
        let rate_limiter_mw = layer(
            1,
            10,
            GlobalKeyExtractor,
            (StatusCode::TOO_MANY_REQUESTS, "foo"),
            Some("top_secret_token".into()),
        )
        .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // First 10 pass
        for _ in 0..10 {
            let req = Request::builder()
                .method(Method::POST)
                .body(Body::empty())
                .unwrap();
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        // Then all blocked
        for _ in 0..100 {
            let req = Request::builder()
                .method(Method::POST)
                .body(Body::empty())
                .unwrap();
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        }

        // But pass with a token
        for _ in 0..100 {
            let req = Request::builder()
                .method(Method::POST)
                .header(BYPASS_HEADER, "top_secret_token")
                .body(Body::empty())
                .unwrap();
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        // And doesn't work with a bad token
        for _ in 0..100 {
            let req = Request::builder()
                .method(Method::POST)
                .header(BYPASS_HEADER, "not_very_secret")
                .body(Body::empty())
                .unwrap();
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}
