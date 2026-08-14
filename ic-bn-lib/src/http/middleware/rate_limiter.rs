use std::{
    future::ready,
    hash::Hash,
    net::IpAddr,
    num::NonZeroU32,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Error, anyhow};
use arc_swap::ArcSwap;
use axum::{extract::Request, response::IntoResponse, response::Response};
use bytes::Bytes;
use futures::future::BoxFuture;
use governor::{
    Quota,
    clock::{Clock, DefaultClock, Reference},
    middleware::NoOpMiddleware,
    nanos::Nanos,
    state::keyed::DashMapStateStore,
};
use http::{HeaderName, HeaderValue, StatusCode, header::RETRY_AFTER};
use tower::{Layer, Service};

use crate::{constant_time_eq, hname, http::middleware::RemoteAddr};

const BYPASS_TOKEN_HEADER: HeaderName = hname!("x-ratelimit-bypass-token");

/// The `governor` rate limiter type that backs this middleware, generic over the clock so
/// that tests can inject `governor::clock::FakeRelativeClock` instead of the real-time
/// default clock.
type GovRateLimiter<K, C> =
    governor::RateLimiter<K, DashMapStateStore<K>, C, NoOpMiddleware<<C as Clock>::Instant>>;

/// Converts a `governor` wait-time into a whole-second `Retry-After` value. Rounds down, but
/// never advertises less than 1 second.
fn retry_after_seconds(wait_time: Duration) -> u32 {
    wait_time.as_secs().max(1) as u32
}

/// Extracts a rate-limiting key from the request. Returns `None` if a key cannot be
/// determined, in which case the request is rejected rather than let through unlimited.
pub trait KeyExtractor: Clone + Send + Sync + 'static {
    type Key: Clone + Eq + Hash + Send + Sync + 'static;

    fn extract<B>(&self, req: &Request<B>) -> Option<Self::Key>;
}

/// Extracts an IP from the request as a rate-limiting key
#[derive(Clone)]
pub struct IpKeyExtractor;

impl KeyExtractor for IpKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Option<Self::Key> {
        req.extensions().get::<RemoteAddr>().map(|x| x.0)
    }
}

/// Extracts a constant key so that all requests share a single rate-limiting bucket
#[derive(Clone)]
pub struct GlobalKeyExtractor;

impl KeyExtractor for GlobalKeyExtractor {
    type Key = ();

    fn extract<B>(&self, _req: &Request<B>) -> Option<Self::Key> {
        Some(())
    }
}

/// Ratelimiter that implements Tower Service
#[derive(Clone)]
pub struct RateLimiter<S, K: KeyExtractor, R, C: Clock = DefaultClock> {
    key_extractor: K,
    limiter: Arc<GovRateLimiter<K::Key, C>>,
    rate_limited_response: R,
    bypass_token: Option<Arc<String>>,
    inner: S,
    last_cleanup: Arc<ArcSwap<C::Instant>>,
}

/// Implement Tower Service for RateLimiter
impl<S, K, R, C> Service<Request> for RateLimiter<S, K, R, C>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    K: KeyExtractor,
    R: IntoResponse + Clone + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        /// Stale entries cleanup interval - 5 minutes
        const CLEANUP_INTERVAL: Nanos = Nanos::new(300_000_000_000);

        // Check that bypass token is configured, header was sent and it matches
        let bypass = request
            .headers()
            .get(BYPASS_TOKEN_HEADER)
            .zip(self.bypass_token.as_ref())
            .is_some_and(|(hdr, token)| constant_time_eq(hdr.as_bytes(), token.as_bytes()));

        // Clean up stale entries from time to time
        let now = self.limiter.clock().now();
        if now.duration_since(*self.last_cleanup.load_full()) > CLEANUP_INTERVAL {
            self.last_cleanup.store(Arc::new(now));
            self.limiter.retain_recent();
        }

        // If bypassing - call the wrapped service directly
        if bypass {
            let fut = self.inner.call(request);
            return Box::pin(fut);
        }

        // Fail if we can't determine a rate-limiting key for the request
        let Some(key) = self.key_extractor.extract(&request) else {
            let response = (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to extract rate limiting key",
            )
                .into_response();

            return Box::pin(ready(Ok(response)));
        };

        match self.limiter.check_key(&key) {
            Ok(()) => Box::pin(self.inner.call(request)),

            Err(not_until) => {
                let wait_time = not_until.wait_time_from(self.limiter.clock().now());
                let retry_secs = retry_after_seconds(wait_time);

                let mut response = self.rate_limited_response.clone().into_response();
                let header_value =
                    HeaderValue::from_maybe_shared(Bytes::from(retry_secs.to_string())).unwrap();
                response.headers_mut().insert(RETRY_AFTER, header_value);

                Box::pin(ready(Ok(response)))
            }
        }
    }
}

/// Layer usable as an Axum middleware
#[derive(Clone, derive_new::new)]
pub struct RateLimiterLayer<K: KeyExtractor, R, C: Clock = DefaultClock> {
    key_extractor: K,
    limiter: Arc<GovRateLimiter<K::Key, C>>,
    rate_limited_response: R,
    bypass_token: Option<Arc<String>>,
    last_cleanup: Arc<ArcSwap<C::Instant>>,
}

impl<S, K, R, C> Layer<S> for RateLimiterLayer<K, R, C>
where
    S: Clone,
    K: KeyExtractor,
    R: IntoResponse + Clone + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    type Service = RateLimiter<S, K, R, C>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimiter {
            key_extractor: self.key_extractor.clone(),
            limiter: self.limiter.clone(),
            rate_limited_response: self.rate_limited_response.clone(),
            bypass_token: self.bypass_token.clone(),
            inner,
            last_cleanup: self.last_cleanup.clone(),
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
    layer_with_clock(
        rps,
        burst_size,
        key_extractor,
        rate_limited_response,
        bypass_token,
        DefaultClock::default(),
    )
}

/// Create a ratelimiter with a provided key extractor and clock. This custom clock is there so
/// that tests can supply a `FakeRelativeClock` and drive the rate limiter's
/// time deterministically, without depending on real wall-clock delays.
fn layer_with_clock<K: KeyExtractor, R: IntoResponse + Clone + Send + Sync + 'static, C: Clock>(
    rps: u32,
    burst_size: u32,
    key_extractor: K,
    rate_limited_response: R,
    bypass_token: Option<String>,
    clock: C,
) -> Result<RateLimiterLayer<K, R, C>, Error> {
    let period = Duration::from_secs(1)
        .checked_div(rps)
        .ok_or_else(|| anyhow!("RPS is zero"))?;

    let burst = NonZeroU32::new(burst_size).ok_or_else(|| anyhow!("burst size is zero"))?;

    let quota = Quota::with_period(period)
        .ok_or_else(|| anyhow!("period is zero"))?
        .allow_burst(burst);

    let limiter = Arc::new(GovRateLimiter::<K::Key, C>::dashmap_with_clock(
        quota, clock,
    ));
    let last_cleanup = Arc::new(ArcSwap::new(limiter.clock().now().into()));

    Ok(RateLimiterLayer::new(
        key_extractor,
        limiter,
        rate_limited_response,
        bypass_token.map(Arc::new),
        last_cleanup,
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
    use governor::clock::FakeRelativeClock;
    use http::{Method, StatusCode};
    use std::str::FromStr;
    use tower::Service;

    async fn handler(_request: Request<Body>) -> impl IntoResponse {
        "test_call"
    }

    async fn send_request(
        router: &mut Router,
        ip: &str,
    ) -> Result<http::Response<Body>, std::convert::Infallible> {
        let mut request = Request::post("/").body(Body::from("".to_string())).unwrap();
        request
            .extensions_mut()
            .insert(RemoteAddr(IpAddr::from_str(ip).unwrap()));
        router.call(request).await
    }

    fn retry_after_header(response: &http::Response<Body>) -> u32 {
        response
            .headers()
            .get(http::header::RETRY_AFTER)
            .expect("Retry-After header missing on 429 response")
            .to_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn test_retry_after_seconds() {
        // Rounds down, but never below 1 second
        assert_eq!(retry_after_seconds(Duration::from_millis(0)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(500)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(999)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(1000)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(1999)), 1);
        assert_eq!(retry_after_seconds(Duration::from_millis(2000)), 2);
        assert_eq!(retry_after_seconds(Duration::from_millis(2999)), 2);
        assert_eq!(retry_after_seconds(Duration::from_secs(10)), 10);
    }

    #[test]
    fn test_layer_rejects_zero_rps() {
        assert!(
            layer(
                0,
                5,
                IpKeyExtractor,
                (StatusCode::TOO_MANY_REQUESTS, "foo"),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn test_layer_rejects_zero_burst_size() {
        assert!(
            layer(
                5,
                0,
                IpKeyExtractor,
                (StatusCode::TOO_MANY_REQUESTS, "foo"),
                None,
            )
            .is_err()
        );
    }

    // Uses a `FakeRelativeClock` so token refills are driven by explicit
    // advances rather than sleeps
    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_rps_limit() {
        let rps = 5;
        let burst_size = 5; // how many requests can go through at once (without delay)
        let period = Duration::from_secs(1) / rps; // time for one token to refill

        let clock = FakeRelativeClock::default();
        let rate_limiter_mw = layer_with_clock(
            rps,
            burst_size,
            IpKeyExtractor,
            (StatusCode::TOO_MANY_REQUESTS, "foo"),
            None,
            clock.clone(),
        )
        .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // Initial burst of 5 requests should succeed and fills full burst capacity
        for _ in 0..5 {
            let result = send_request(&mut app, "1.1.1.1").await.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }

        // For 6th request no tokens left => 429
        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after_header(&result), 1);

        // Advance the fake clock by exactly one token's worth of time (no real waiting)
        clock.advance(period);
        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // Bucket is empty again, request should fail
        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);

        // Advance for 2 tokens to be available, next 2 requests succeed
        clock.advance(2 * period);
        for _ in 0..2 {
            let result = send_request(&mut app, "1.1.1.1").await.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }

        // Bucket is empty again, request should fail
        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);

        // Advance for 5 tokens (full burst), next 5 requests succeed
        clock.advance(5 * period);
        for _ in 0..5 {
            let result = send_request(&mut app, "1.1.1.1").await.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }

        // Bucket is empty again, requests should fail
        for _ in 0..2 {
            let result = send_request(&mut app, "1.1.1.1").await.unwrap();
            assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_retry_after_decreases_as_clock_advances() {
        let clock = FakeRelativeClock::default();
        let rate_limiter_mw = layer_with_clock(
            1,
            1,
            IpKeyExtractor,
            (StatusCode::TOO_MANY_REQUESTS, "foo"),
            None,
            clock.clone(),
        )
        .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // Consume the only token
        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        // Full period (1s) remaining
        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after_header(&result), 1);

        // Once the period has fully elapsed the token is available again
        clock.advance(Duration::from_secs(1));
        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_per_key_independence() {
        let clock = FakeRelativeClock::default();
        let rate_limiter_mw = layer_with_clock(
            1,
            1,
            IpKeyExtractor,
            (StatusCode::TOO_MANY_REQUESTS, "foo"),
            None,
            clock.clone(),
        )
        .expect("failed to build middleware");

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // IP A consumes its only token and gets rate-limited
        assert_eq!(
            send_request(&mut app, "1.1.1.1").await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            send_request(&mut app, "1.1.1.1").await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // IP B has its own independent bucket and is unaffected
        assert_eq!(
            send_request(&mut app, "2.2.2.2").await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            send_request(&mut app, "2.2.2.2").await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test(start_paused = true)]
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

    #[tokio::test(start_paused = true)]
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
                .header(BYPASS_TOKEN_HEADER, "top_secret_token")
                .body(Body::empty())
                .unwrap();
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        // And doesn't work with a bad token
        for _ in 0..100 {
            let req = Request::builder()
                .method(Method::POST)
                .header(BYPASS_TOKEN_HEADER, "not_very_secret")
                .body(Body::empty())
                .unwrap();
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_cleans_up_stale_entries() {
        let clock = FakeRelativeClock::default();
        let rate_limiter_mw = layer_with_clock(
            1,
            1,
            IpKeyExtractor,
            (StatusCode::TOO_MANY_REQUESTS, "foo"),
            None,
            clock.clone(),
        )
        .expect("failed to build middleware");

        // Keep a handle to the underlying governor limiter so we can observe how many
        // keys it's tracking, independently of the middleware wrapping it.
        let limiter = rate_limiter_mw.limiter.clone();

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        // Two distinct keys get tracked in the limiter's state
        send_request(&mut app, "1.1.1.1").await.unwrap();
        send_request(&mut app, "2.2.2.2").await.unwrap();
        assert_eq!(limiter.len(), 2);

        // Advancing by less than the cleanup interval (10 minutes) leaves stale
        // entries in place, even though their buckets have long since refilled.
        clock.advance(Duration::from_secs(60));
        send_request(&mut app, "3.3.3.3").await.unwrap();
        assert_eq!(limiter.len(), 3);

        // Once the cleanup interval has elapsed, the next request triggers a sweep
        // that drops entries indistinguishable from a fresh bucket -- i.e. all three
        // previously-seen keys -- before the new key is inserted.
        clock.advance(Duration::from_secs(600));
        send_request(&mut app, "4.4.4.4").await.unwrap();
        assert_eq!(limiter.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_layer_global_wrapper() {
        let rate_limiter_mw =
            layer_global(2, 2, (StatusCode::TOO_MANY_REQUESTS, "foo"), None).unwrap();

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        for _ in 0..2 {
            let req = Request::builder()
                .method(Method::POST)
                .body(Body::empty())
                .unwrap();
            let res = app.call(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }

        let req = Request::builder()
            .method(Method::POST)
            .body(Body::empty())
            .unwrap();
        let res = app.call(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test(start_paused = true)]
    async fn test_layer_by_ip_wrapper() {
        let rate_limiter_mw =
            layer_by_ip(2, 2, (StatusCode::TOO_MANY_REQUESTS, "foo"), None).unwrap();

        let mut app = Router::new()
            .route("/", post(handler))
            .layer(rate_limiter_mw);

        for _ in 0..2 {
            let result = send_request(&mut app, "1.1.1.1").await.unwrap();
            assert_eq!(result.status(), StatusCode::OK);
        }

        let result = send_request(&mut app, "1.1.1.1").await.unwrap();
        assert_eq!(result.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
