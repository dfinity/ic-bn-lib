use std::{
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
    mem::size_of,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::RandomState;
use async_trait::async_trait;
use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::{
    Method,
    header::{CACHE_CONTROL, RANGE},
};
use http_body::Body as _;
use moka::{
    Expiry,
    sync::{Cache as MokaCache, CacheBuilder as MokaCacheBuilder},
};
use prometheus::{
    Counter, CounterVec, Histogram, HistogramVec, IntGauge, Registry,
    register_counter_vec_with_registry, register_counter_with_registry,
    register_histogram_vec_with_registry, register_histogram_with_registry,
    register_int_gauge_with_registry,
};
use sha1::{Digest, Sha1};
use strum_macros::{Display, IntoStaticStr};
use tokio::{select, sync::Mutex, time::sleep};
use tokio_util::sync::CancellationToken;

use super::{Error as HttpError, body::buffer_body, calc_headers_size, extract_authority};
use crate::{http::headers::X_CACHE_TTL, tasks::Run};

pub trait CustomBypassReason:
    Debug + Clone + std::fmt::Display + Into<&'static str> + PartialEq + Eq + Send + Sync + 'static
{
}

#[derive(Debug, Clone, Display, PartialEq, Eq, IntoStaticStr)]
pub enum CustomBypassReasonDummy {}
impl CustomBypassReason for CustomBypassReasonDummy {}

#[derive(Debug, Clone, Display, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum CacheBypassReason<R: CustomBypassReason> {
    MethodNotCacheable,
    SizeUnknown,
    BodyTooBig,
    HTTPError,
    UnableToExtractKey,
    UnableToRunBypasser,
    CacheControl,
    Custom(R),
}

impl<R: CustomBypassReason> CacheBypassReason<R> {
    pub fn into_str(self) -> &'static str {
        match self {
            Self::Custom(v) => v.into(),
            _ => self.into(),
        }
    }
}

#[derive(Debug, Clone, Display, PartialEq, Eq, Default, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CacheStatus<R: CustomBypassReason = CustomBypassReasonDummy> {
    #[default]
    Disabled,
    Bypass(CacheBypassReason<R>),
    Hit,
    Miss,
}

// Injects itself into a given response to be accessible by middleware
impl<B: CustomBypassReason> CacheStatus<B> {
    pub fn with_response<T>(self, mut resp: Response<T>) -> Response<T> {
        resp.extensions_mut().insert(self);
        resp
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unable to extract key from request: {0}")]
    ExtractKey(String),
    #[error("unable to execute bypasser: {0}")]
    ExecuteBypasser(String),
    #[error("timed out while fetching body")]
    FetchBodyTimeout,
    #[error("body is too big")]
    FetchBodyTooBig,
    #[error("unable to fetch request body: {0}")]
    FetchBody(String),
    #[error("unable to parse content-length header")]
    ParseContentLength,
    #[error("{0}")]
    Other(String),
}

enum ResponseType<R: CustomBypassReason> {
    Fetched(Response<Bytes>, Duration),
    Streamed(Response, CacheBypassReason<R>),
}

#[derive(Clone)]
pub struct Entry {
    response: Response<Bytes>,
    /// Time it took to generate the response for given entry.
    /// Used for x-fetch algorithm.
    delta: f64,
    expires: Instant,
}

impl Entry {
    /// Probabilistically decide if we need to refresh the given cache entry early.
    /// This is an implementation of x-fetch algorigthm, see:
    /// https://en.wikipedia.org/wiki/Cache_stampede#Probabilistic_early_expiration
    fn need_to_refresh(&self, now: Instant, beta: f64) -> bool {
        // fast path
        if beta == 0.0 {
            return false;
        }

        let rnd = rand::random::<f64>();
        let xfetch = -(self.delta * beta * rnd.ln());
        let ttl_left = (self.expires - now).as_secs_f64();

        xfetch > ttl_left
    }
}

/// Trait to extract the caching key from the given HTTP request
pub trait KeyExtractor: Clone + Send + Sync + Debug + 'static {
    /// The type of the key.
    type Key: Clone + Send + Sync + Debug + Hash + Eq + 'static;

    /// Extraction method, will return [`Error`] response when the extraction failed
    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, Error>;
}

/// Trait to decide if we need to bypass caching of the given request
pub trait Bypasser: Clone + Send + Sync + Debug + 'static {
    /// Custom bypass reason
    type BypassReason: CustomBypassReason;

    /// Checks if we should bypass the given request
    fn bypass<T>(&self, req: &Request<T>) -> Result<Option<Self::BypassReason>, Error>;
}

#[derive(Debug, Clone)]
pub struct NoopBypasser;

impl Bypasser for NoopBypasser {
    type BypassReason = CustomBypassReasonDummy;

    fn bypass<T>(&self, _req: &Request<T>) -> Result<Option<Self::BypassReason>, Error> {
        Ok(None)
    }
}

#[derive(Clone)]
pub struct Metrics {
    lock_await: HistogramVec,
    requests_count: CounterVec,
    requests_duration: HistogramVec,
    ttl: Histogram,
    x_fetch: Counter,
    memory: IntGauge,
    entries: IntGauge,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        let lbls = &["cache_status", "cache_bypass_reason"];

        Self {
            lock_await: register_histogram_vec_with_registry!(
                "cache_proxy_lock_await",
                "Time spent waiting for the proxy cache lock",
                &["lock_obtained"],
                registry,
            )
            .unwrap(),

            requests_count: register_counter_vec_with_registry!(
                "cache_requests_count",
                "Cache requests count",
                lbls,
                registry,
            )
            .unwrap(),

            requests_duration: register_histogram_vec_with_registry!(
                "cache_requests_duration",
                "Time it took to execute the request",
                lbls,
                registry,
            )
            .unwrap(),

            ttl: register_histogram_with_registry!(
                "cache_ttl",
                "TTL that was set when storing the response",
                vec![1.0, 10.0, 100.0, 1000.0, 10000.0, 86400.0],
                registry,
            )
            .unwrap(),

            x_fetch: register_counter_with_registry!(
                "cache_xfetch_count",
                "Number of requests that x-fetch refreshed",
                registry,
            )
            .unwrap(),

            memory: register_int_gauge_with_registry!(
                "cache_memory",
                "Memory usage by the cache in bytes",
                registry,
            )
            .unwrap(),

            entries: register_int_gauge_with_registry!(
                "cache_entries",
                "Count of entries in the cache",
                registry,
            )
            .unwrap(),
        }
    }
}

pub struct Opts {
    pub cache_size: u64,
    pub max_item_size: usize,
    pub ttl: Duration,
    pub max_ttl: Duration,
    pub obey_cache_control: bool,
    pub lock_timeout: Duration,
    pub body_timeout: Duration,
    pub xfetch_beta: f64,
    pub methods: Vec<Method>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            cache_size: 128 * 1024 * 1024,
            max_item_size: 16 * 1024 * 1024,
            ttl: Duration::from_secs(10),
            max_ttl: Duration::from_secs(86400),
            obey_cache_control: false,
            lock_timeout: Duration::from_secs(5),
            body_timeout: Duration::from_secs(60),
            xfetch_beta: 0.0,
            methods: vec![Method::GET],
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CacheControl {
    NoCache,
    MaxAge(Duration),
}

/// Tries to infer the caching TTL from the response headers
fn infer_ttl<T>(req: &Response<T>) -> Option<CacheControl> {
    // Extract the Cache-Control header & try to parse it as a string
    let hdr = req
        .headers()
        .get(CACHE_CONTROL)
        .and_then(|x| x.to_str().ok())?;

    // Iterate over the key-value pairs (or just keys)
    hdr.split(',').find_map(|x| {
        let (k, v) = {
            let mut split = x.split('=').map(|s| s.trim());
            (split.next().unwrap(), split.next())
        };

        if ["no-cache", "no-store"].contains(&k) {
            Some(CacheControl::NoCache)
        } else if k == "max-age" {
            let v = v.and_then(|x| x.parse::<u64>().ok());
            if v == Some(0) {
                Some(CacheControl::NoCache)
            } else {
                v.map(|x| CacheControl::MaxAge(Duration::from_secs(x)))
            }
        } else {
            None
        }
    })
}

/// Extracts TTL from the Entry
struct Expirer<K: KeyExtractor>(PhantomData<K>);

impl<K: KeyExtractor> Expiry<K::Key, Arc<Entry>> for Expirer<K> {
    fn expire_after_create(
        &self,
        _key: &K::Key,
        value: &Arc<Entry>,
        created_at: Instant,
    ) -> Option<Duration> {
        Some(value.expires - created_at)
    }
}

/// Builds a cache using some overridable defaults
pub struct CacheBuilder<K: KeyExtractor, B: Bypasser> {
    key_extractor: K,
    bypasser: Option<B>,
    opts: Opts,
    registry: Registry,
}

impl<K: KeyExtractor> CacheBuilder<K, NoopBypasser> {
    pub fn new(key_extractor: K) -> Self {
        Self {
            key_extractor,
            bypasser: None,
            opts: Opts::default(),
            registry: Registry::new(),
        }
    }
}

impl<K: KeyExtractor, B: Bypasser> CacheBuilder<K, B> {
    pub fn new_with_bypasser(key_extractor: K, bypasser: B) -> Self {
        Self {
            key_extractor,
            bypasser: Some(bypasser),
            opts: Opts::default(),
            registry: Registry::new(),
        }
    }

    /// Sets the cache size. Default 128MB.
    pub const fn cache_size(mut self, v: u64) -> Self {
        self.opts.cache_size = v;
        self
    }

    /// Sets the maximum entry size. Default 16MB.
    pub const fn max_item_size(mut self, v: usize) -> Self {
        self.opts.max_item_size = v;
        self
    }

    /// Sets the default cache entry TTL. Default 10 sec.
    pub const fn ttl(mut self, v: Duration) -> Self {
        self.opts.ttl = v;
        self
    }

    /// Sets the maximum cache entry TTL that can be overriden by `Cache-Control` header. Default 1 day.
    pub const fn max_ttl(mut self, v: Duration) -> Self {
        self.opts.max_ttl = v;
        self
    }

    /// Sets the cache lock timeout. Default 5 sec.
    pub const fn lock_timeout(mut self, v: Duration) -> Self {
        self.opts.lock_timeout = v;
        self
    }

    /// Sets the body reading timeout. Default 1 min.
    pub const fn body_timeout(mut self, v: Duration) -> Self {
        self.opts.body_timeout = v;
        self
    }

    /// Sets the beta term of X-Fetch algorithm. Default 0.0
    pub const fn xfetch_beta(mut self, v: f64) -> Self {
        self.opts.xfetch_beta = v;
        self
    }

    /// Sets cacheable methods. Defaults to only GET.
    pub fn methods(mut self, v: &[Method]) -> Self {
        self.opts.methods = v.into();
        self
    }

    /// Whether to obey `Cache-Control` headers in the *response*. Defaults to false.
    pub const fn obey_cache_control(mut self, v: bool) -> Self {
        self.opts.obey_cache_control = v;
        self
    }

    /// Sets the metrics registry to use.
    pub fn registry(mut self, v: &Registry) -> Self {
        self.registry = v.clone();
        self
    }

    /// Try to build the cache from this builder
    pub fn build(self) -> Result<Cache<K, B>, Error> {
        Cache::new(self.opts, self.key_extractor, self.bypasser, &self.registry)
    }
}

pub struct Cache<K: KeyExtractor, B: Bypasser = NoopBypasser> {
    store: MokaCache<K::Key, Arc<Entry>, RandomState>,
    locks: MokaCache<K::Key, Arc<Mutex<()>>, RandomState>,
    key_extractor: K,
    bypasser: Option<B>,
    metrics: Metrics,
    opts: Opts,
}

fn weigh_entry<K: KeyExtractor>(_k: &K::Key, v: &Arc<Entry>) -> u32 {
    let mut size = size_of::<K::Key>() + size_of::<Arc<Entry>>();

    size += calc_headers_size(v.response.headers());
    size += v.response.body().len();

    size as u32
}

impl<K: KeyExtractor + 'static, B: Bypasser + 'static> Cache<K, B> {
    pub fn new(
        opts: Opts,
        key_extractor: K,
        bypasser: Option<B>,
        registry: &Registry,
    ) -> Result<Self, Error> {
        if opts.max_item_size as u64 >= opts.cache_size {
            return Err(Error::Other(
                "Cache item size should be less than whole cache size".into(),
            ));
        }

        if opts.ttl > opts.max_ttl {
            return Err(Error::Other("TTL should be <= max TTL".into()));
        }

        Ok(Self {
            store: MokaCacheBuilder::new(opts.cache_size)
                .expire_after(Expirer::<K>(PhantomData))
                .weigher(weigh_entry::<K>)
                .build_with_hasher(RandomState::default()),

            // The params of the lock cache are somewhat arbitrary, maybe needs tuning
            locks: MokaCacheBuilder::new(32768)
                .time_to_idle(Duration::from_secs(60))
                .build_with_hasher(RandomState::default()),

            key_extractor,
            bypasser,
            metrics: Metrics::new(registry),

            opts,
        })
    }

    pub fn get(&self, key: &K::Key, now: Instant, beta: f64) -> Option<Response> {
        let val = self.store.get(key)?;

        // Run x-fetch if configured and simulate the cache miss if we need to refresh the entry
        if val.need_to_refresh(now, beta) {
            self.metrics.x_fetch.inc();
            return None;
        }

        let (parts, body) = val.response.clone().into_parts();
        Some(Response::from_parts(parts, Body::from(body)))
    }

    pub fn insert(
        &self,
        key: K::Key,
        now: Instant,
        ttl: Duration,
        delta: Duration,
        response: Response<Bytes>,
    ) {
        self.metrics.ttl.observe(ttl.as_secs_f64());

        self.store.insert(
            key,
            Arc::new(Entry {
                response,
                delta: delta.as_secs_f64(),
                expires: now + ttl,
            }),
        );
    }

    pub async fn process_request(&self, request: Request, next: Next) -> Result<Response, Error> {
        let now = Instant::now();
        let (cache_status, response) = self.process_inner(now, request, next).await?;

        // Record metrics
        let cache_status_str: &'static str = (&cache_status).into();
        let cache_bypass_reason_str: &'static str = match cache_status.clone() {
            CacheStatus::Bypass(v) => v.into_str(),
            _ => "none",
        };

        let labels = &[cache_status_str, cache_bypass_reason_str];

        self.metrics.requests_count.with_label_values(labels).inc();
        self.metrics
            .requests_duration
            .with_label_values(labels)
            .observe(now.elapsed().as_secs_f64());

        Ok(cache_status.with_response(response))
    }

    async fn process_inner(
        &self,
        now: Instant,
        request: Request,
        next: Next,
    ) -> Result<(CacheStatus<B::BypassReason>, Response), Error> {
        // Check if we have bypasser configured
        if let Some(b) = &self.bypasser {
            // Run it
            if let Ok(v) = b.bypass(&request) {
                // If it decided to bypass - return the custom reason
                if let Some(r) = v {
                    return Ok((
                        CacheStatus::Bypass(CacheBypassReason::Custom(r)),
                        next.run(request).await,
                    ));
                }
            } else {
                return Ok((
                    CacheStatus::Bypass(CacheBypassReason::UnableToRunBypasser),
                    next.run(request).await,
                ));
            }
        }

        // Check the method
        if !self.opts.methods.contains(request.method()) {
            return Ok((
                CacheStatus::Bypass(CacheBypassReason::MethodNotCacheable),
                next.run(request).await,
            ));
        }

        // Use cached response if found
        let Ok(key) = self.key_extractor.extract(&request) else {
            return Ok((
                CacheStatus::Bypass(CacheBypassReason::UnableToExtractKey),
                next.run(request).await,
            ));
        };

        if let Some(v) = self.get(&key, now, self.opts.xfetch_beta) {
            return Ok((CacheStatus::Hit, v));
        }

        // Get synchronization lock to handle parallel requests.
        let lock = self
            .locks
            .get_with_by_ref(&key, || Arc::new(Mutex::new(())));

        let mut lock_obtained = false;
        select! {
            // Only one parallel request should execute the response and populate the cache.
            // Other requests will wait for the lock to be released and get results from the cache.
            _ = lock.lock() => {
                lock_obtained = true;
            }

            // We proceed with the request as is if takes too long to get the lock
            _ = sleep(self.opts.lock_timeout) => {}
        }

        // Record prometheus metrics for the time spent waiting for the lock.
        self.metrics
            .lock_await
            .with_label_values(&[if lock_obtained { "yes" } else { "no" }])
            .observe(now.elapsed().as_secs_f64());

        // Check again the cache in case some other request filled it
        // while we were waiting for the lock
        if let Some(v) = self.get(&key, now, 0.0) {
            return Ok((CacheStatus::Hit, v));
        }

        // Otherwise pass the request forward
        let now = Instant::now();
        Ok(match self.pass_request(request, next).await? {
            // If the body was fetched - cache it
            ResponseType::Fetched(v, ttl) => {
                let delta = now.elapsed();
                self.insert(key, now + delta, ttl, delta, v.clone());

                let (mut parts, body) = v.into_parts();
                parts.headers.insert(X_CACHE_TTL, ttl.as_secs().into());
                let response = Response::from_parts(parts, Body::from(body));
                (CacheStatus::Miss, response)
            }

            // Otherwise just pass it up
            ResponseType::Streamed(v, reason) => (CacheStatus::Bypass(reason), v),
        })
    }

    // Passes the request down the line and conditionally fetches the response body
    async fn pass_request(
        &self,
        request: Request,
        next: Next,
    ) -> Result<ResponseType<B::BypassReason>, Error> {
        // Execute the response & get the headers
        let response = next.run(request).await;

        // Do not cache non-2xx responses
        if !response.status().is_success() {
            return Ok(ResponseType::Streamed(
                response,
                CacheBypassReason::HTTPError,
            ));
        }

        // Extract content length from the response header if there's one
        let body_size = response.body().size_hint().exact().map(|x| x as usize);

        // Do not cache responses that have no known size (probably streaming etc)
        let Some(body_size) = body_size else {
            return Ok(ResponseType::Streamed(
                response,
                CacheBypassReason::SizeUnknown,
            ));
        };

        // Do not cache items larger than configured
        if body_size > self.opts.max_item_size {
            return Ok(ResponseType::Streamed(
                response,
                CacheBypassReason::BodyTooBig,
            ));
        }

        // Infer the TTL if requested to obey Cache-Control headers
        let ttl = if self.opts.obey_cache_control {
            let ttl = infer_ttl(&response);

            match ttl {
                // Do not cache if we're asked not to
                Some(CacheControl::NoCache) => {
                    return Ok(ResponseType::Streamed(
                        response,
                        CacheBypassReason::CacheControl,
                    ));
                }

                // Use TTL from max-age capping it to max_ttl
                Some(CacheControl::MaxAge(v)) => v.min(self.opts.max_ttl),

                // Otherwise use default
                None => self.opts.ttl,
            }
        } else {
            self.opts.ttl
        };

        // Read the response body into a buffer
        let (parts, body) = response.into_parts();
        let body = buffer_body(body, body_size, self.opts.body_timeout)
            .await
            .map_err(|e| match e {
                HttpError::BodyTooBig => Error::FetchBodyTooBig,
                HttpError::BodyTimedOut => Error::FetchBodyTimeout,
                _ => Error::FetchBody(e.to_string()),
            })?;

        Ok(ResponseType::Fetched(
            Response::from_parts(parts, body),
            ttl,
        ))
    }

    #[cfg(test)]
    pub fn housekeep(&self) {
        self.store.run_pending_tasks();
        self.locks.run_pending_tasks();
    }

    #[cfg(test)]
    pub fn size(&self) -> u64 {
        self.store.weighted_size()
    }

    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.store.entry_count()
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.store.invalidate_all();
        self.locks.invalidate_all();
        self.housekeep();
    }
}

#[async_trait]
impl<K: KeyExtractor, B: Bypasser> Run for Cache<K, B> {
    async fn run(&self, _: CancellationToken) -> Result<(), anyhow::Error> {
        self.store.run_pending_tasks();
        self.metrics.memory.set(self.store.weighted_size() as i64);
        self.metrics.entries.set(self.store.entry_count() as i64);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct KeyExtractorUriRange;

impl KeyExtractor for KeyExtractorUriRange {
    type Key = [u8; 20];

    fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, Error> {
        let authority = extract_authority(request)
            .ok_or_else(|| Error::ExtractKey("no authority found".into()))?
            .as_bytes();
        let paq = request
            .uri()
            .path_and_query()
            .ok_or_else(|| Error::ExtractKey("no path_and_query found".into()))?
            .as_str()
            .as_bytes();

        // Compute a composite hash
        let mut hash = Sha1::new().chain_update(authority).chain_update(paq);
        if let Some(v) = request.headers().get(RANGE) {
            hash = hash.chain_update(v.as_bytes());
        }

        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use crate::hval;

    use super::*;

    use axum::{
        Router,
        body::to_bytes,
        extract::State,
        middleware::from_fn_with_state,
        response::IntoResponse,
        routing::{get, post},
    };
    use http::{Request, Response, StatusCode, Uri};
    use sha1::Digest;
    use tower::{Service, ServiceExt};

    #[derive(Clone, Debug)]
    pub struct KeyExtractorTest;

    impl KeyExtractor for KeyExtractorTest {
        type Key = [u8; 20];

        fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, Error> {
            let paq = request
                .uri()
                .path_and_query()
                .ok_or_else(|| Error::ExtractKey("no path_and_query found".into()))?
                .as_str()
                .as_bytes();

            let hash: [u8; 20] = sha1::Sha1::new().chain_update(paq).finalize().into();
            Ok(hash)
        }
    }

    const MAX_ITEM_SIZE: usize = 1024;
    const MAX_CACHE_SIZE: u64 = 32768;
    const PROXY_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

    async fn dispatch_get_request(router: &mut Router, uri: String) -> Option<CacheStatus> {
        let req = Request::get(uri).body(Body::from("")).unwrap();
        let result = router.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        result.extensions().get::<CacheStatus>().cloned()
    }

    async fn handler(_request: Request<Body>) -> impl IntoResponse {
        "test_body"
    }

    async fn handler_proxy_cache_lock(request: Request<Body>) -> impl IntoResponse {
        if request.uri().path().contains("slow_response") {
            sleep(2 * PROXY_LOCK_TIMEOUT).await;
        }

        "test_body"
    }

    async fn handler_too_big(_request: Request<Body>) -> impl IntoResponse {
        "a".repeat(MAX_ITEM_SIZE + 1)
    }

    async fn handler_cache_control_max_age_1d(_request: Request<Body>) -> impl IntoResponse {
        [(CACHE_CONTROL, "max-age=86400")]
    }

    async fn handler_cache_control_max_age_7d(_request: Request<Body>) -> impl IntoResponse {
        [(CACHE_CONTROL, "max-age=604800")]
    }

    async fn handler_cache_control_no_cache(_request: Request<Body>) -> impl IntoResponse {
        [(CACHE_CONTROL, "no-cache")]
    }

    async fn handler_cache_control_no_store(_request: Request<Body>) -> impl IntoResponse {
        [(CACHE_CONTROL, "no-store")]
    }

    async fn middleware(
        State(cache): State<Arc<Cache<KeyExtractorTest>>>,
        request: Request<Body>,
        next: Next,
    ) -> impl IntoResponse {
        cache
            .process_request(request, next)
            .await
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }

    #[test]
    fn test_bypass_reason_serialize() {
        #[derive(Debug, Clone, Display, PartialEq, Eq, IntoStaticStr)]
        #[strum(serialize_all = "snake_case")]
        enum CustomReasonTest {
            Bar,
        }
        impl CustomBypassReason for CustomReasonTest {}

        let a: CacheBypassReason<CustomReasonTest> =
            CacheBypassReason::Custom(CustomReasonTest::Bar);
        let txt = a.into_str();
        assert_eq!(txt, "bar");

        let a: CacheBypassReason<CustomReasonTest> = CacheBypassReason::BodyTooBig;
        let txt = a.into_str();
        assert_eq!(txt, "body_too_big");
    }

    #[test]
    fn test_key_extractor_uri_range() {
        let x = KeyExtractorUriRange;

        // Baseline
        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.baz:80/foo/bar?abc=1");
        let key1 = x.extract(&req).unwrap();

        // Make sure that changing authority/path/query changes the key
        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.baz:80/foo/bar?abc=2");
        let key2 = x.extract(&req).unwrap();
        assert_ne!(key1, key2);

        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.baz:80/foo/ba?abc=1");
        let key2 = x.extract(&req).unwrap();
        assert_ne!(key1, key2);

        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.ba:80/foo/bar?abc=1");
        let key2 = x.extract(&req).unwrap();
        assert_ne!(key1, key2);

        // Make sure that changing schema doesn't affect the key
        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("https://foo.bar.baz:80/foo/bar?abc=1");
        let key2 = x.extract(&req).unwrap();
        assert_eq!(key1, key2);

        // Make sure that adding Range header changes the key
        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.bar:80/foo/bar?abc=1");
        (*req.headers_mut()).insert(RANGE, hval!("1000-2000"));
        let key2 = x.extract(&req).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_infer_ttl() {
        let mut req = Response::new(());

        assert_eq!(infer_ttl(&req), None);

        // Don't cache
        req.headers_mut().insert(CACHE_CONTROL, hval!("no-cache"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        req.headers_mut().insert(CACHE_CONTROL, hval!("no-store"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("no-store, no-cache"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        // Order matters
        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("no-store, no-cache, max-age=1"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("max-age=1, no-store, no-cache"));
        assert_eq!(
            infer_ttl(&req),
            Some(CacheControl::MaxAge(Duration::from_secs(1)))
        );

        // Max-age
        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("max-age=86400"));
        assert_eq!(
            infer_ttl(&req),
            Some(CacheControl::MaxAge(Duration::from_secs(86400)))
        );
        req.headers_mut().insert(CACHE_CONTROL, hval!("max-age=0"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("max-age=foo"));
        assert_eq!(infer_ttl(&req), None);

        req.headers_mut().insert(CACHE_CONTROL, hval!("max-age="));
        assert_eq!(infer_ttl(&req), None);

        req.headers_mut().insert(CACHE_CONTROL, hval!("max-age=-1"));
        assert_eq!(infer_ttl(&req), None);

        // Empty
        req.headers_mut().insert(CACHE_CONTROL, hval!(""));
        assert_eq!(infer_ttl(&req), None);

        // Broken
        req.headers_mut()
            .insert(CACHE_CONTROL, hval!(", =foobar, "));
        assert_eq!(infer_ttl(&req), None);
    }

    #[test]
    fn test_cache_creation_errors() {
        let cache = CacheBuilder::new(KeyExtractorTest)
            .cache_size(1)
            .max_item_size(2)
            .build();
        assert!(cache.is_err());

        let cache = CacheBuilder::new(KeyExtractorTest)
            .ttl(Duration::from_secs(2))
            .max_ttl(Duration::from_secs(1))
            .build();
        assert!(cache.is_err());
    }

    #[tokio::test]
    async fn test_cache_bypass() {
        let cache = Arc::new(
            CacheBuilder::new(KeyExtractorTest)
                .max_item_size(MAX_ITEM_SIZE)
                .build()
                .unwrap(),
        );

        let mut app = Router::new()
            .route("/", post(handler))
            .route("/", get(handler))
            .route("/too_big", get(handler_too_big))
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // Test only GET requests are cached.
        let req = Request::post("/").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::MethodNotCacheable)
        );

        // Test non-2xx response are not cached
        let req = Request::get("/non_existing_path")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::HTTPError)
        );
        assert_eq!(cache.len(), 0);

        // Test body too big
        let req = Request::get("/too_big").body(Body::from("foobar")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::BodyTooBig)
        );
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let ttl = Duration::from_millis(1500);

        let cache = Arc::new(
            CacheBuilder::new(KeyExtractorTest)
                .cache_size(MAX_CACHE_SIZE)
                .max_item_size(MAX_ITEM_SIZE)
                .ttl(ttl)
                .build()
                .unwrap(),
        );

        let mut app = Router::new()
            .route("/{key}", get(handler))
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // First request doesn't hit the cache, but is stored in the cache
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Next request doesn't hit the cache, but is stored in the cache
        let req = Request::get("/2").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // Next request hits the cache
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        let (_, body) = result.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!("test_body", body);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // Next request hits again
        let req = Request::get("/2").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Hit);
        let (_, body) = result.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!("test_body", body);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // After ttl, request doesn't hit the cache anymore
        sleep(ttl + Duration::from_millis(300)).await;
        cache.housekeep();
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(cache_status, CacheStatus::Miss);

        // Before cache_size limit is reached all requests should be stored in cache.
        cache.clear();
        let req_count = 50;
        // First dispatch round, all requests miss cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }
        // Second dispatch round, all requests hit the cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Hit);
        }

        // Once cache_size limit is reached some requests should be evicted.
        cache.clear();
        let req_count = 500;
        // First dispatch round, all cache misses.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert_eq!(status.unwrap(), CacheStatus::Miss);
        }

        // Second dispatch round, some requests hit the cache, some don't
        let mut count_misses = 0;
        let mut count_hits = 0;
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            if status == Some(CacheStatus::Miss) {
                count_misses += 1;
            } else if status == Some(CacheStatus::Hit) {
                count_hits += 1;
            }
        }
        assert!(count_misses > 0);
        assert!(count_hits > 0);
        cache.housekeep();
        let entry_size = cache.size() / cache.len();

        // Make sure cache size limit was reached.
        // Check that adding one more entry to the cache would overflow its max capacity.
        assert!(MAX_CACHE_SIZE > cache.size());
        assert!(MAX_CACHE_SIZE < cache.size() + entry_size);
    }

    #[tokio::test]
    async fn test_cache_control() {
        let cache = Arc::new(
            CacheBuilder::new(KeyExtractorTest)
                .obey_cache_control(true)
                .build()
                .unwrap(),
        );

        let mut app = Router::new()
            .route("/", get(handler))
            .route(
                "/cache_control_no_store",
                get(handler_cache_control_no_store),
            )
            .route(
                "/cache_control_no_cache",
                get(handler_cache_control_no_cache),
            )
            .route(
                "/cache_control_max_age_1d",
                get(handler_cache_control_max_age_1d),
            )
            .route(
                "/cache_control_max_age_7d",
                get(handler_cache_control_max_age_7d),
            )
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // Cache-Control no-cache
        let req = Request::get("/cache_control_no_cache")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::CacheControl)
        );
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 0);

        // Cache-Control no-store
        let req = Request::get("/cache_control_no_store")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(
            cache_status,
            CacheStatus::Bypass(CacheBypassReason::CacheControl)
        );
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 0);

        // Cache-Control max-age 1 day
        let req = Request::get("/cache_control_max_age_1d")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        let ttl = result
            .headers()
            .get(X_CACHE_TTL)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(cache_status, CacheStatus::Miss);
        assert_eq!(ttl, 86400);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Cache-Control max-age 7 days should still be capped to 1 day
        let req = Request::get("/cache_control_max_age_7d")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        let ttl = result
            .headers()
            .get(X_CACHE_TTL)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(cache_status, CacheStatus::Miss);
        assert_eq!(ttl, 86400);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // w/o Cache-Control we should get a default 10s TTL
        let req = Request::get("/").body(Body::from("foobar")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        let ttl = result
            .headers()
            .get(X_CACHE_TTL)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(cache_status, CacheStatus::Miss);
        assert_eq!(ttl, 10);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 3);

        // Test when we do not obey
        let cache = Arc::new(
            CacheBuilder::new(KeyExtractorTest)
                .obey_cache_control(false)
                .build()
                .unwrap(),
        );

        let mut app = Router::new()
            .route("/", get(handler))
            .route(
                "/cache_control_no_store",
                get(handler_cache_control_no_store),
            )
            .route(
                "/cache_control_no_cache",
                get(handler_cache_control_no_cache),
            )
            .route(
                "/cache_control_max_age_1d",
                get(handler_cache_control_max_age_1d),
            )
            .route(
                "/cache_control_max_age_7d",
                get(handler_cache_control_max_age_7d),
            )
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // Cache-Control no-cache
        let req = Request::get("/cache_control_no_cache")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cache_status, CacheStatus::Miss);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Cache-Control no-store
        let req = Request::get("/cache_control_no_store")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(cache_status, CacheStatus::Miss,);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // Cache-Control max-age 1 day
        let req = Request::get("/cache_control_max_age_1d")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        let ttl = result
            .headers()
            .get(X_CACHE_TTL)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(cache_status, CacheStatus::Miss);
        assert_eq!(ttl, 10);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 3);

        // w/o Cache-Control we should get a default 10s TTL
        let req = Request::get("/").body(Body::from("foobar")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        let ttl = result
            .headers()
            .get(X_CACHE_TTL)
            .unwrap()
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        assert_eq!(cache_status, CacheStatus::Miss);
        assert_eq!(ttl, 10);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 4);
    }

    #[tokio::test]
    async fn test_proxy_cache_lock() {
        let cache = Arc::new(
            CacheBuilder::new(KeyExtractorTest)
                .lock_timeout(PROXY_LOCK_TIMEOUT)
                .build()
                .unwrap(),
        );

        let app = Router::new()
            .route("/{key}", get(handler_proxy_cache_lock))
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        let req_count = 50;
        // Expected cache misses/hits for fast/slow responses, respectively.
        let expected_misses = [1, req_count];
        let expected_hits = [req_count - 1, 0];
        for (idx, uri) in ["/fast_response", "/slow_response"].iter().enumerate() {
            let mut tasks = vec![];
            // Dispatch requests simultaneously.
            for _ in 0..req_count {
                let app = app.clone();
                tasks.push(tokio::spawn(async move {
                    let req = Request::get(*uri).body(Body::from("")).unwrap();
                    let result = app.oneshot(req).await.unwrap();
                    assert_eq!(result.status(), StatusCode::OK);
                    result.extensions().get::<CacheStatus>().cloned()
                }));
            }
            let mut count_hits = 0;
            let mut count_misses = 0;
            for task in tasks {
                task.await
                    .map(|res| match res {
                        Some(CacheStatus::Hit) => count_hits += 1,
                        Some(CacheStatus::Miss) => count_misses += 1,
                        _ => panic!("Unexpected cache status"),
                    })
                    .expect("failed to complete task");
            }
            assert_eq!(count_hits, expected_hits[idx]);
            assert_eq!(count_misses, expected_misses[idx]);
            cache.housekeep();
            cache.clear();
        }
    }

    #[test]
    fn test_xfetch() {
        let now = Instant::now();
        let reqs = 10000;

        let entry = Entry {
            response: Response::builder().body(Bytes::new()).unwrap(),
            delta: 0.5,
            expires: now + Duration::from_secs(60),
        };

        // Check close to expiration
        let now2 = now + Duration::from_secs(58);
        let mut refresh = 0;
        for _ in 0..reqs {
            if entry.need_to_refresh(now2, 1.5) {
                refresh += 1;
            }
        }

        assert!(refresh > 550 && refresh < 800);

        // Check mid-expiration with small beta
        let now2 = now + Duration::from_secs(30);
        let mut refresh = 0;
        for _ in 0..reqs {
            if entry.need_to_refresh(now2, 1.0) {
                refresh += 1;
            }
        }

        assert_eq!(refresh, 0);

        // Check mid-expiration with high beta
        let now2 = now + Duration::from_secs(30);
        let mut refresh = 0;
        for _ in 0..reqs {
            if entry.need_to_refresh(now2, 10.0) {
                refresh += 1;
            }
        }

        assert!(refresh > 9);
    }
}
