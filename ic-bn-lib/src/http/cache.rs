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
    HeaderMap, HeaderName, Method,
    header::{
        ACCEPT_ENCODING, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD,
        AUTHORIZATION, CACHE_CONTROL, ORIGIN, RANGE, SET_COOKIE, VARY,
    },
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

use super::{body::buffer_body, calc_headers_size, extract_authority};
use crate::{
    http::{
        Error as HttpError,
        headers::{X_CACHE_TTL, set_header},
    },
    tasks::Run,
};

/// HTTP Cache error
#[derive(thiserror::Error, Debug)]
pub enum CacheError {
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

/// Trait to extract the caching key from the given HTTP request
pub trait KeyExtractor: Clone + Send + Sync + Debug + 'static {
    /// The type of the key.
    type Key: Clone + Send + Sync + Debug + Hash + Eq + 'static;

    /// Extraction method, will return [`Error`] response when the extraction failed
    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, CacheError>;

    /// Request headers whose values are fully included in the extracted key.
    ///
    /// A response that varies (as per its `Vary` header) only on these headers can be cached,
    /// any other `Vary` value makes the response uncacheable.
    /// Defaults to none, i.e. any `Vary` prevents caching.
    fn vary_headers(&self) -> &[HeaderName] {
        &[]
    }
}

/// Reason for bypassing caching of the request
pub trait CustomBypassReason:
    Debug + Clone + std::fmt::Display + Into<&'static str> + PartialEq + Eq + Send + Sync + 'static
{
}

/// Trait to decide if we need to bypass caching of the given request
pub trait Bypasser: Clone + Send + Sync + Debug + 'static {
    /// Custom bypass reason
    type BypassReason: CustomBypassReason;

    /// Checks if we should bypass the given request
    fn bypass<T>(&self, req: &Request<T>) -> Result<Option<Self::BypassReason>, CacheError>;
}

/// Reason for bypassing the HTTP cache for the particular request
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
    /// Request carries `Authorization`, so the response is specific to the caller
    Authorization,
    /// Response sets a cookie, so it's specific to the caller
    SetCookie,
    /// Response varies on request headers that aren't part of the cache key
    Vary,
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

#[derive(Debug, Clone, Display, PartialEq, Eq, IntoStaticStr)]
pub enum CustomBypassReasonDummy {}
impl CustomBypassReason for CustomBypassReasonDummy {}

/// Status of the cache lookup operation
#[derive(Debug, Clone, Display, PartialEq, Eq, Default, IntoStaticStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum CacheStatus<R: CustomBypassReason = CustomBypassReasonDummy> {
    #[default]
    Disabled,
    Bypass(CacheBypassReason<R>),
    Hit(i64),
    Miss(i64),
}

impl<B: CustomBypassReason> CacheStatus<B> {
    /// Injects itself into a given response to be accessible by middleware
    pub fn with_response<T>(self, mut resp: Response<T>) -> Response<T> {
        resp.extensions_mut().insert(self);
        resp
    }
}

enum ResponseType<R: CustomBypassReason> {
    Fetched(Response<Bytes>, Duration),
    Streamed(Response, CacheBypassReason<R>),
}

/// Cache entry
#[derive(Clone)]
struct Entry {
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

/// No-op cache bypasser that never bypasses
#[derive(Debug, Clone)]
pub struct NoopBypasser;

impl Bypasser for NoopBypasser {
    type BypassReason = CustomBypassReasonDummy;

    fn bypass<T>(&self, _req: &Request<T>) -> Result<Option<Self::BypassReason>, CacheError> {
        Ok(None)
    }
}

/// Cache metrics
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
    /// Create new `Metrics`
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

/// Cache options
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

/// Splits a `Cache-Control` header value into directives on the commas that are
/// outside of quoted strings, respecting the escaped characters inside them.
/// Returns `None` if a quoted string isn't terminated.
fn split_directives(hdr: &str) -> Option<Vec<&str>> {
    let mut directives = vec![];
    let (mut start, mut quoted, mut escaped) = (0, false, false);

    // All the delimiters are ASCII, so splitting on their byte positions is safe
    for (i, c) in hdr.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }

        match c {
            b'\\' if quoted => escaped = true,
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                directives.push(&hdr[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    if quoted {
        return None;
    }

    directives.push(&hdr[start..]);
    Some(directives)
}

/// Tries to infer the caching TTL from the response headers.
///
/// This is a shared cache, so:
/// - `no-store`, `no-cache` & `private` forbid caching wherever they appear,
///   regardless of the other directives and their order.
/// - `s-maxage` takes precedence over `max-age`.
fn infer_ttl<T>(resp: &Response<T>) -> Option<CacheControl> {
    let (mut max_age, mut s_maxage) = (None, None);

    // There might be several Cache-Control headers, all of them count
    for hdr in resp.headers().get_all(CACHE_CONTROL) {
        // Do not cache if we can't read what we're asked for:
        // the header isn't readable or has an unterminated quoted string.
        let Some(directives) = hdr.to_str().ok().and_then(split_directives) else {
            return Some(CacheControl::NoCache);
        };

        // Iterate over the key-value pairs (or just keys)
        for directive in directives {
            let (k, v) = {
                let mut split = directive.splitn(2, '=').map(str::trim);
                (split.next().unwrap_or_default(), split.next())
            };

            if ["no-cache", "no-store", "private"]
                .iter()
                .any(|x| k.eq_ignore_ascii_case(x))
            {
                return Some(CacheControl::NoCache);
            }

            let secs = v.and_then(|x| {
                let x = x
                    .strip_prefix('"')
                    .and_then(|x| x.strip_suffix('"'))
                    .unwrap_or(x);
                x.parse::<u64>().ok()
            });
            if k.eq_ignore_ascii_case("s-maxage") {
                s_maxage = s_maxage.or(secs);
            } else if k.eq_ignore_ascii_case("max-age") {
                max_age = max_age.or(secs);
            }
        }
    }

    match s_maxage.or(max_age)? {
        0 => Some(CacheControl::NoCache),
        v => Some(CacheControl::MaxAge(Duration::from_secs(v))),
    }
}

/// Checks if the response can be shared between the requests with the same cache key
/// as far as its `Vary` header goes.
/// It can't if it varies on anything outside of `allowed`, i.e. on headers that
/// aren't part of the cache key (e.g. `Cookie` or `*`).
fn vary_allows_sharing(headers: &HeaderMap, allowed: &[HeaderName]) -> bool {
    headers.get_all(VARY).iter().all(|hdr| {
        hdr.to_str().is_ok_and(|hdr| {
            hdr.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .all(|x| allowed.iter().any(|y| x.eq_ignore_ascii_case(y.as_str())))
        })
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
    /// Create new `CacheBuilder`
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
    /// Create new `CacheBuilder` with a bypasser
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
    ///
    /// When enabled, `no-store`, `no-cache` & `private` prevent caching, while
    /// `s-maxage` or `max-age` override the default TTL.
    ///
    /// Regardless of this setting, requests with `Authorization` bypass the cache, and
    /// responses that have `Set-Cookie` or `Vary` on any header not covered by the cache key
    /// (see [`KeyExtractor::vary_headers`]) are never stored.
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
    pub fn build(self) -> Result<Cache<K, B>, CacheError> {
        Cache::new(self.opts, self.key_extractor, self.bypasser, &self.registry)
    }
}

/// HTTP Cache
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
    /// Create new `Cache`
    pub fn new(
        opts: Opts,
        key_extractor: K,
        bypasser: Option<B>,
        registry: &Registry,
    ) -> Result<Self, CacheError> {
        if opts.max_item_size as u64 >= opts.cache_size {
            return Err(CacheError::Other(
                "Cache item size should be less than whole cache size".into(),
            ));
        }

        if opts.ttl > opts.max_ttl {
            return Err(CacheError::Other("TTL should be <= max TTL".into()));
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

    /// Looks up the given entry
    pub fn get(&self, key: &K::Key, now: Instant, beta: f64) -> Option<(Response, i64)> {
        let val = self.store.get(key)?;

        // Run x-fetch if configured and simulate the cache miss if we need to refresh the entry
        if val.need_to_refresh(now, beta) {
            self.metrics.x_fetch.inc();
            return None;
        }

        let (mut parts, body) = val.response.clone().into_parts();
        let ttl_left = if now < val.expires {
            (val.expires - now).as_secs() as i64
        } else {
            -((now - val.expires).as_secs() as i64)
        };

        if ttl_left >= 0 {
            set_header(&mut parts.headers, &X_CACHE_TTL, ttl_left.into());
        }

        Some((Response::from_parts(parts, Body::from(body)), ttl_left))
    }

    /// Insert a new entry into the cache
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

    /// Process the HTTP request
    pub async fn process_request(
        &self,
        request: Request,
        next: Next,
    ) -> Result<Response, CacheError> {
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
    ) -> Result<(CacheStatus<B::BypassReason>, Response), CacheError> {
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

        // Requests with credentials get responses that are specific to the caller,
        // so they're neither served from the cache nor stored there.
        if request.headers().contains_key(AUTHORIZATION) {
            return Ok((
                CacheStatus::Bypass(CacheBypassReason::Authorization),
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

        if let Some((v, ttl_left)) = self.get(&key, now, self.opts.xfetch_beta) {
            return Ok((CacheStatus::Hit(ttl_left), v));
        }

        // Get synchronization lock to handle parallel requests
        let lock = self
            .locks
            .get_with_by_ref(&key, || Arc::new(Mutex::new(())));

        // Holds the guard (if we got one) so that it stays locked across the
        // backend call & cache insert below, actually serializing concurrent
        // requests for the same key instead of releasing it immediately.
        let mut guard = None;
        select! {
            // Only one parallel request should execute and populate the cache.
            // Other requests will wait for the lock to be released and get results from the cache.
            g = lock.lock() => {
                guard = Some(g);
            }

            // We proceed with the request as is if takes too long to get the lock
            _ = sleep(self.opts.lock_timeout) => {}
        }

        // Record prometheus metrics for the time spent waiting for the lock
        self.metrics
            .lock_await
            .with_label_values(&[if guard.is_some() { "yes" } else { "no" }])
            .observe(now.elapsed().as_secs_f64());

        // Check again the cache in case some other request filled it
        // while we were waiting for the lock
        if let Some((v, ttl_left)) = self.get(&key, now, 0.0) {
            return Ok((CacheStatus::Hit(ttl_left), v));
        }

        // Otherwise pass the request forward
        let now = Instant::now();
        let result = match self.pass_request(request, next).await? {
            // If the body was fetched - cache it
            ResponseType::Fetched(v, ttl) => {
                let delta = now.elapsed();
                self.insert(key, now + delta, ttl, delta, v.clone());

                let ttl = ttl.as_secs();
                let (mut parts, body) = v.into_parts();
                set_header(&mut parts.headers, &X_CACHE_TTL, ttl.into());
                let response = Response::from_parts(parts, Body::from(body));
                (CacheStatus::Miss(ttl as i64), response)
            }

            // Otherwise just pass it up
            ResponseType::Streamed(v, reason) => (CacheStatus::Bypass(reason), v),
        };

        // Release the lock only now that the cache has been populated (or the
        // request has been fully handled), so that other requests waiting on
        // it actually observe a filled cache instead of racing to the backend.
        drop(guard);

        Ok(result)
    }

    // Passes the request down the line and conditionally fetches the response body
    async fn pass_request(
        &self,
        request: Request,
        next: Next,
    ) -> Result<ResponseType<B::BypassReason>, CacheError> {
        // Execute the response & get the headers
        let response = next.run(request).await;

        // Do not cache non-2xx responses
        if !response.status().is_success() {
            return Ok(ResponseType::Streamed(
                response,
                CacheBypassReason::HTTPError,
            ));
        }

        // Do not cache responses that set cookies: they're specific to the caller
        // and replaying them would hand one client's cookie to another.
        if response.headers().contains_key(SET_COOKIE) {
            return Ok(ResponseType::Streamed(
                response,
                CacheBypassReason::SetCookie,
            ));
        }

        // Do not cache responses that vary on request headers which aren't in the cache key
        if !vary_allows_sharing(response.headers(), self.key_extractor.vary_headers()) {
            return Ok(ResponseType::Streamed(response, CacheBypassReason::Vary));
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

                // Use TTL from max-age while capping it to max_ttl
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
                HttpError::BodyTooBig => CacheError::FetchBodyTooBig,
                HttpError::BodyTimedOut => CacheError::FetchBodyTimeout,
                _ => CacheError::FetchBody(e.to_string()),
            })?;

        Ok(ResponseType::Fetched(
            Response::from_parts(parts, body),
            ttl,
        ))
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

#[cfg(test)]
impl<K: KeyExtractor + 'static, B: Bypasser + 'static> Cache<K, B> {
    pub fn housekeep(&self) {
        self.store.run_pending_tasks();
        self.locks.run_pending_tasks();
    }

    pub fn size(&self) -> u64 {
        self.store.weighted_size()
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.store.entry_count()
    }

    pub fn clear(&self) {
        self.store.invalidate_all();
        self.locks.invalidate_all();
        self.housekeep();
    }
}

/// Request headers that [`KeyExtractorUriRange`] includes in the key.
///
/// Canisters choose the content encoding based on `Accept-Encoding` (often without `Vary`),
/// and might reflect `Origin` in CORS headers, so the responses differ between their values.
/// CORS preflight headers are absent in regular requests, they're included so that
/// the responses with a common `Vary: Origin, Access-Control-Request-Method,
/// Access-Control-Request-Headers` can still be cached.
static KEY_HEADERS: [HeaderName; 5] = [
    RANGE,
    ACCEPT_ENCODING,
    ORIGIN,
    ACCESS_CONTROL_REQUEST_METHOD,
    ACCESS_CONTROL_REQUEST_HEADERS,
];

/// Feeds a length-prefixed field into the hash, so that the adjacent fields can't run into each other
fn hash_field(hash: &mut Sha1, field: &[u8]) {
    hash.update((field.len() as u64).to_le_bytes());
    hash.update(field);
}

/// Key extractor that is keyed by method, authority, path & query and the values of
/// `Range`, `Accept-Encoding`, `Origin` and CORS preflight request headers.
#[derive(Clone, Debug)]
pub struct KeyExtractorUriRange;

impl KeyExtractor for KeyExtractorUriRange {
    type Key = [u8; 20];

    fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, CacheError> {
        let authority = extract_authority(request)
            .ok_or_else(|| CacheError::ExtractKey("no authority found".into()))?
            .as_bytes();
        let paq = request
            .uri()
            .path_and_query()
            .ok_or_else(|| CacheError::ExtractKey("no path_and_query found".into()))?
            .as_str()
            .as_bytes();

        // Compute a composite hash
        let mut hash = Sha1::new();
        hash_field(&mut hash, request.method().as_str().as_bytes());
        hash_field(&mut hash, authority);
        hash_field(&mut hash, paq);

        // Each header is represented by the count of its values followed by the values,
        // so that the absent header & a header with an empty value differ.
        for name in &KEY_HEADERS {
            let values = request.headers().get_all(name);
            hash.update((values.iter().count() as u64).to_le_bytes());
            for v in values {
                hash_field(&mut hash, v.as_bytes());
            }
        }

        Ok(hash.finalize().into())
    }

    fn vary_headers(&self) -> &[HeaderName] {
        &KEY_HEADERS
    }
}

#[cfg(test)]
mod tests {
    use crate::{http::headers::full_header_map, hval};

    use super::*;

    use axum::{
        Router,
        body::to_bytes,
        extract::State,
        middleware::from_fn_with_state,
        response::IntoResponse,
        routing::{get, post},
    };
    use std::collections::HashSet;

    use http::{
        HeaderValue, Request, Response, StatusCode, Uri,
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_ENCODING, CONTENT_LENGTH, COOKIE},
    };
    use sha1::Digest;
    use tower::{Service, ServiceExt};

    #[derive(Clone, Debug)]
    pub struct KeyExtractorTest;

    impl KeyExtractor for KeyExtractorTest {
        type Key = [u8; 20];

        fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, CacheError> {
            let paq = request
                .uri()
                .path_and_query()
                .ok_or_else(|| CacheError::ExtractKey("no path_and_query found".into()))?
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
        } else if request.uri().path().contains("medium_response") {
            // Slower than an instant response but well within the lock timeout,
            // so concurrent requests actually have to wait on the lock rather
            // than falling through via the lock-wait timeout (as "slow_response"
            // does) or completing so fast that scheduling luck alone produces
            // a single miss (as "fast_response" does). This is the only case
            // that actually exercises the lock holding across the backend call.
            sleep(PROXY_LOCK_TIMEOUT / 4).await;
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

    async fn handler_cache_control_private(_request: Request<Body>) -> impl IntoResponse {
        [(CACHE_CONTROL, "max-age=60, private")]
    }

    /// Returns the credentials of the request so that the tests can tell whose response they got
    fn credentials(request: &Request<Body>) -> String {
        ["cookie", "authorization"]
            .iter()
            .filter_map(|x| request.headers().get(*x))
            .filter_map(|x| x.to_str().ok())
            .collect::<Vec<_>>()
            .join(",")
    }

    async fn handler_echo(request: Request<Body>) -> impl IntoResponse {
        credentials(&request)
    }

    /// Per-user response that is marked as such in every way possible
    async fn handler_per_user(request: Request<Body>) -> impl IntoResponse {
        let user = credentials(&request);

        (
            [
                (CACHE_CONTROL, "private, max-age=60".to_string()),
                (VARY, "Cookie".to_string()),
                (SET_COOKIE, format!("session={user}")),
            ],
            user,
        )
    }

    async fn handler_set_cookie(request: Request<Body>) -> impl IntoResponse {
        let user = credentials(&request);
        ([(SET_COOKIE, format!("session={user}"))], user)
    }

    async fn handler_vary_cookie(request: Request<Body>) -> impl IntoResponse {
        ([(VARY, "Accept-Encoding, Cookie")], credentials(&request))
    }

    async fn handler_vary_star(request: Request<Body>) -> impl IntoResponse {
        ([(VARY, "*")], credentials(&request))
    }

    async fn handler_vary_key_headers(request: Request<Body>) -> impl IntoResponse {
        ([(VARY, "Accept-Encoding, origin")], credentials(&request))
    }

    /// Chooses the content encoding the way asset canisters do: from `Accept-Encoding`, w/o `Vary`
    async fn handler_encoding(request: Request<Body>) -> Response<Body> {
        let accepts_br = request
            .headers()
            .get(ACCEPT_ENCODING)
            .and_then(|x| x.to_str().ok())
            .is_some_and(|x| x.split(',').any(|x| x.trim().eq_ignore_ascii_case("br")));

        if accepts_br {
            let mut response = Response::new(Body::from("br"));
            response.headers_mut().insert(CONTENT_ENCODING, hval!("br"));
            response
        } else {
            Response::new(Body::from("identity"))
        }
    }

    async fn handler_encoding_vary(request: Request<Body>) -> Response<Body> {
        let mut response = handler_encoding(request).await;
        response
            .headers_mut()
            .insert(VARY, hval!("Accept-Encoding"));
        response
    }

    /// Reflects the `Origin` in the CORS headers
    async fn handler_reflect_origin(request: Request<Body>) -> impl IntoResponse {
        let origin = request
            .headers()
            .get(ORIGIN)
            .cloned()
            .unwrap_or_else(|| hval!("null"));

        (
            [
                (ACCESS_CONTROL_ALLOW_ORIGIN, origin),
                (VARY, hval!("Origin")),
            ],
            "body",
        )
    }

    async fn handler_path(request: Request<Body>) -> String {
        request.uri().path().to_string()
    }

    /// Returns a response whose header map is full, with an `X-Cache-TTL` of its own
    async fn handler_full_headers(_request: Request<Body>) -> Response<Body> {
        let mut response = Response::new(Body::from("full"));
        *response.headers_mut() = full_header_map(&[
            // Otherwise axum adds Content-Length itself, which would panic on its own
            (CONTENT_LENGTH, hval!("4")),
            (X_CACHE_TTL, hval!("31337")),
        ]);
        response
    }

    /// Sends a GET request with an optional header, returns the cache status, response headers & body
    async fn dispatch_with_header(
        router: &mut Router,
        uri: &str,
        header: Option<(HeaderName, &'static str)>,
    ) -> (CacheStatus, HeaderMap, String) {
        let mut req = Request::get(uri).body(Body::from("")).unwrap();
        if let Some((k, v)) = header {
            req.headers_mut().insert(k, HeaderValue::from_static(v));
        }

        let result = router.call(req).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);

        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        let (parts, body) = result.into_parts();
        let body = to_bytes(body, usize::MAX).await.unwrap().to_vec();

        (
            cache_status,
            parts.headers,
            String::from_utf8_lossy(&body).to_string(),
        )
    }

    async fn middleware<K: KeyExtractor>(
        State(cache): State<Arc<Cache<K>>>,
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
        *req.uri_mut() = Uri::from_static("http://foo.bar.baz:80/foo/bar?abc=1");
        (*req.headers_mut()).insert(RANGE, hval!("1000-2000"));
        let key2 = x.extract(&req).unwrap();
        assert_ne!(key1, key2);

        // Range value can't make the request look like the one for another path
        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.baz/main.js");
        let key_path = x.extract(&req).unwrap();
        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.baz/");
        req.headers_mut().insert(RANGE, hval!("main.js"));
        assert_ne!(key_path, x.extract(&req).unwrap());

        // Computes the key of a request for the given URI with an optional Range header
        let key_range = |uri: &'static str, range: Option<&'static str>| {
            let mut req = Request::new("foo");
            *req.uri_mut() = Uri::from_static(uri);
            if let Some(v) = range {
                req.headers_mut().insert(RANGE, HeaderValue::from_static(v));
            }
            x.extract(&req).unwrap()
        };

        // A path prefix plus the rest of the path in Range doesn't collide with the full path
        assert_ne!(
            key_range("http://foo.bar.baz/app.js", None),
            key_range("http://foo.bar.baz/a", Some("pp.js")),
        );

        // The boundary between the path and Range can't be shifted when both carry Range
        assert_ne!(
            key_range("http://foo.bar.baz/app", Some(".js")),
            key_range("http://foo.bar.baz/a", Some("pp.js")),
        );
        assert_ne!(
            key_range("http://foo.bar.baz/a?b", Some("=1")),
            key_range("http://foo.bar.baz/a?b=1", Some("")),
        );

        // Different methods give different keys
        let mut req = Request::new("foo");
        *req.uri_mut() = Uri::from_static("http://foo.bar.baz:80/foo/bar?abc=1");
        *req.method_mut() = Method::HEAD;
        assert_ne!(key1, x.extract(&req).unwrap());

        // Computes the key of the baseline request with given headers added
        let key = |headers: &[(&HeaderName, &'static str)]| {
            let mut req = Request::new("foo");
            *req.uri_mut() = Uri::from_static("http://foo.bar.baz:80/foo/bar?abc=1");
            for &(k, v) in headers {
                req.headers_mut().append(k, HeaderValue::from_static(v));
            }
            x.extract(&req).unwrap()
        };
        assert_eq!(key(&[]), key1);

        // Headers outside of the key don't affect it
        assert_eq!(key(&[(&COOKIE, "foo")]), key1);

        let mut keys = HashSet::new();
        for name in &KEY_HEADERS {
            // Different values give different keys, same values give the same key
            assert_ne!(key(&[(name, "foo")]), key1, "{name}");
            assert_ne!(key(&[(name, "foo")]), key(&[(name, "bar")]), "{name}");
            assert_eq!(key(&[(name, "foo")]), key(&[(name, "foo")]), "{name}");

            // Absent header differs from the empty one
            assert_ne!(key(&[(name, "")]), key1, "{name}");

            // All the values of a header are considered
            assert_ne!(
                key(&[(name, "foo"), (name, "bar")]),
                key(&[(name, "foo")]),
                "{name}"
            );

            keys.insert(key(&[(name, "foo")]));
        }

        // The same value in different headers gives different keys
        assert_eq!(keys.len(), KEY_HEADERS.len());

        // Values can't move between the adjacent headers
        assert_ne!(
            key(&[(&ACCEPT_ENCODING, "foo"), (&ORIGIN, "")]),
            key(&[(&ACCEPT_ENCODING, ""), (&ORIGIN, "foo")]),
        );
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

        // Order doesn't matter, directives that forbid caching always win
        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("no-store, no-cache, max-age=1"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("max-age=1, no-store, no-cache"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        // Private responses must not be stored by a shared cache
        for v in [
            "private",
            "Private",
            "private, max-age=60",
            "max-age=60, private",
            "max-age=60,private",
            "public, max-age=60, PRIVATE",
            "private=\"set-cookie\", max-age=60",
        ] {
            req.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static(v));
            assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache), "{v}");
        }

        // All Cache-Control headers are considered, not only the first one
        req.headers_mut().insert(CACHE_CONTROL, hval!("max-age=60"));
        req.headers_mut().append(CACHE_CONTROL, hval!("private"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        // Unreadable header forbids caching
        req.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_bytes(b"max-age=60\xff").unwrap(),
        );
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        // s-maxage takes precedence over max-age in any order
        for v in ["s-maxage=5, max-age=60", "max-age=60, S-MaxAge=5"] {
            req.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static(v));
            assert_eq!(
                infer_ttl(&req),
                Some(CacheControl::MaxAge(Duration::from_secs(5))),
                "{v}"
            );
        }

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("s-maxage=0, max-age=60"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("s-maxage=foo, max-age=60"));
        assert_eq!(
            infer_ttl(&req),
            Some(CacheControl::MaxAge(Duration::from_secs(60)))
        );

        // Quoted values are accepted
        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("s-maxage=\"0\", max-age=60"));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("s-maxage=\"5\", max-age=60"));
        assert_eq!(
            infer_ttl(&req),
            Some(CacheControl::MaxAge(Duration::from_secs(5)))
        );

        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("max-age=\"60\""));
        assert_eq!(
            infer_ttl(&req),
            Some(CacheControl::MaxAge(Duration::from_secs(60)))
        );

        // Unterminated quoted string makes the header malformed, which forbids caching
        for v in [
            "max-age=\"60",
            "max-age=60\"",
            "max-age=\"",
            "max-age=60, ext=\"abc, private",
            "max-age=60, ext=\"abc\\\"",
        ] {
            req.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static(v));
            assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache), "{v}");
        }

        // Commas inside quoted strings don't separate directives
        req.headers_mut()
            .insert(CACHE_CONTROL, hval!("max-age=0, ext=\"x,s-maxage=600,y\""));
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        for v in [
            "max-age=60, ext=\"a,s-maxage=5\"",
            "max-age=60, ext=\"a, private, b\"",
            "ext=\"no-store\", max-age=60",
        ] {
            req.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static(v));
            assert_eq!(
                infer_ttl(&req),
                Some(CacheControl::MaxAge(Duration::from_secs(60))),
                "{v}"
            );
        }

        // Escaped quotes don't terminate the quoted string
        req.headers_mut().insert(
            CACHE_CONTROL,
            hval!("max-age=0, ext=\"a\\\",s-maxage=600,\\\"b\""),
        );
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

        // Qualified forms with a list of fields still forbid caching
        req.headers_mut().insert(
            CACHE_CONTROL,
            hval!("no-cache=\"Set-Cookie, Foo\", max-age=60"),
        );
        assert_eq!(infer_ttl(&req), Some(CacheControl::NoCache));

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
    async fn test_cache_full_headers() {
        // Default cache size, since the full header map alone weighs hundreds of KBs
        let cache = Arc::new(
            CacheBuilder::new(KeyExtractorTest)
                .max_item_size(MAX_ITEM_SIZE)
                .build()
                .unwrap(),
        );

        let mut app = Router::new()
            .route("/full", get(handler_full_headers))
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // There's no room for X-Cache-TTL, so the response is passed on without it
        // instead of panicking, and the upstream one isn't passed on in its place.
        let (cache_status, headers, body) = dispatch_with_header(&mut app, "/full", None).await;
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
        assert!(headers.get(X_CACHE_TTL).is_none());
        assert!(headers.contains_key("x-fill-0"));
        assert_eq!(body, "full");
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Same when it's served from the cache
        let (cache_status, headers, body) = dispatch_with_header(&mut app, "/full", None).await;
        assert!(matches!(cache_status, CacheStatus::Hit(_)));
        assert!(headers.get(X_CACHE_TTL).is_none());
        assert!(headers.contains_key("x-fill-0"));
        assert_eq!(body, "full");
    }

    #[test]
    fn test_cache_get_full_headers() {
        let cache = CacheBuilder::new(KeyExtractorTest).build().unwrap();

        let mut response = Response::new(Bytes::from_static(b"full"));
        *response.headers_mut() = full_header_map(&[(X_CACHE_TTL, hval!("31337"))]);

        let now = Instant::now();
        let ttl = Duration::from_secs(10);
        cache.insert([0; 20], now, ttl, Duration::ZERO, response);

        let (response, ttl_left) = cache.get(&[0; 20], now, 0.0).unwrap();
        assert_eq!(ttl_left, 10);
        assert!(response.headers().get(X_CACHE_TTL).is_none());
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Next request doesn't hit the cache, but is stored in the cache
        let req = Request::get("/2").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
        cache.housekeep();
        assert_eq!(cache.len(), 2);

        // Next request hits the cache
        let req = Request::get("/1").body(Body::from("")).unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert!(matches!(cache_status, CacheStatus::Hit(_)));
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
        assert!(matches!(cache_status, CacheStatus::Hit(_)));
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));

        // Before cache_size limit is reached all requests should be stored in cache.
        cache.clear();
        let req_count = 50;
        // First dispatch round, all requests miss cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert!(matches!(status, Some(CacheStatus::Miss(_))));
        }
        // Second dispatch round, all requests hit the cache.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert!(matches!(status, Some(CacheStatus::Hit(_))));
        }

        // Once cache_size limit is reached some requests should be evicted.
        cache.clear();
        let req_count = 500;
        // First dispatch round, all cache misses.
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            assert!(matches!(status, Some(CacheStatus::Miss(_))));
        }

        // Second dispatch round, some requests hit the cache, some don't
        let mut count_misses = 0;
        let mut count_hits = 0;
        for idx in 0..req_count {
            let status = dispatch_get_request(&mut app, format!("/{idx}")).await;
            if matches!(status, Some(CacheStatus::Miss(_))) {
                count_misses += 1;
            } else if matches!(status, Some(CacheStatus::Hit(_))) {
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
            .route("/cache_control_private", get(handler_cache_control_private))
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

        // Cache-Control private (even with max-age in front of it)
        let req = Request::get("/cache_control_private")
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 1);

        // Cache-Control no-store
        let req = Request::get("/cache_control_no_store")
            .body(Body::from("foobar"))
            .unwrap();
        let result = app.call(req).await.unwrap();
        let cache_status = result.extensions().get::<CacheStatus>().cloned().unwrap();
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
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
        assert!(matches!(cache_status, CacheStatus::Miss(_)));
        assert_eq!(ttl, 10);
        assert_eq!(result.status(), StatusCode::OK);
        cache.housekeep();
        assert_eq!(cache.len(), 4);
    }

    #[test]
    fn test_vary_allows_sharing() {
        let mut headers = HeaderMap::new();
        assert!(vary_allows_sharing(&headers, &KEY_HEADERS));
        assert!(vary_allows_sharing(&headers, &[]));

        // Headers that are in the key
        for v in [
            "",
            "Accept-Encoding",
            "accept-encoding, Origin",
            "Range",
            "Origin,Access-Control-Request-Method, Access-Control-Request-Headers, ",
        ] {
            headers.insert(VARY, HeaderValue::from_static(v));
            assert!(vary_allows_sharing(&headers, &KEY_HEADERS), "{v}");
        }

        // Anything else makes the response specific to the request
        for v in [
            "*",
            "Cookie",
            "cookie",
            "Authorization",
            "User-Agent",
            "Accept-Encoding, Cookie",
            "Accept-Encoding, *",
        ] {
            headers.insert(VARY, HeaderValue::from_static(v));
            assert!(!vary_allows_sharing(&headers, &KEY_HEADERS), "{v}");
        }

        // Headers are allowed only if they're in the key
        headers.insert(VARY, hval!("Accept-Encoding"));
        assert!(!vary_allows_sharing(&headers, &[]));
        assert!(!vary_allows_sharing(&headers, &[ORIGIN]));
        headers.insert(VARY, hval!(""));
        assert!(vary_allows_sharing(&headers, &[]));

        // All Vary headers are considered, not only the first one
        headers.insert(VARY, hval!("Accept-Encoding"));
        headers.append(VARY, hval!("Cookie"));
        assert!(!vary_allows_sharing(&headers, &KEY_HEADERS));

        // Unreadable header
        headers.insert(VARY, HeaderValue::from_bytes(b"Origin\xff").unwrap());
        assert!(!vary_allows_sharing(&headers, &KEY_HEADERS));
    }

    #[tokio::test]
    async fn test_cache_per_user_responses() {
        // These protections don't depend on whether we obey Cache-Control or not
        for obey_cache_control in [true, false] {
            let cache = Arc::new(
                CacheBuilder::new(KeyExtractorTest)
                    .obey_cache_control(obey_cache_control)
                    .build()
                    .unwrap(),
            );

            let mut app = Router::new()
                .route("/echo", get(handler_echo))
                .route("/per_user", get(handler_per_user))
                .route("/set_cookie", get(handler_set_cookie))
                .route("/vary_cookie", get(handler_vary_cookie))
                .route("/vary_star", get(handler_vary_star))
                .route("/vary_key_headers", get(handler_vary_key_headers))
                .layer(from_fn_with_state(Arc::clone(&cache), middleware));

            // Two users with different sessions request the same URL one after another,
            // each of them should get their own response & cookie.
            for user in ["alice", "bob"] {
                let (status, headers, body) =
                    dispatch_with_header(&mut app, "/per_user", Some((COOKIE, user))).await;
                assert_eq!(status, CacheStatus::Bypass(CacheBypassReason::SetCookie));
                assert_eq!(body, user);
                assert_eq!(headers.get(SET_COOKIE).unwrap(), &format!("session={user}"));
            }

            // Response with Set-Cookie is never stored
            for user in ["alice", "bob"] {
                let (status, headers, body) =
                    dispatch_with_header(&mut app, "/set_cookie", Some((COOKIE, user))).await;
                assert_eq!(status, CacheStatus::Bypass(CacheBypassReason::SetCookie));
                assert_eq!(body, user);
                assert_eq!(headers.get(SET_COOKIE).unwrap(), &format!("session={user}"));
            }

            // Response that varies on something that's not in the cache key is never stored
            for uri in ["/vary_cookie", "/vary_star"] {
                for user in ["alice", "bob"] {
                    let (status, _, body) =
                        dispatch_with_header(&mut app, uri, Some((COOKIE, user))).await;
                    assert_eq!(status, CacheStatus::Bypass(CacheBypassReason::Vary));
                    assert_eq!(body, user);
                }
            }

            cache.housekeep();
            assert_eq!(cache.len(), 0);

            // Request with Authorization is not stored
            let (status, _, body) =
                dispatch_with_header(&mut app, "/echo", Some((AUTHORIZATION, "Bearer alice")))
                    .await;
            assert_eq!(
                status,
                CacheStatus::Bypass(CacheBypassReason::Authorization)
            );
            assert_eq!(body, "Bearer alice");
            cache.housekeep();
            assert_eq!(cache.len(), 0);

            // Anonymous request doesn't get the response of an authorized one & gets cached
            let (status, _, body) = dispatch_with_header(&mut app, "/echo", None).await;
            assert!(matches!(status, CacheStatus::Miss(_)));
            assert_eq!(body, "");
            cache.housekeep();
            assert_eq!(cache.len(), 1);

            // Request with Authorization isn't served from the cache either
            let (status, _, body) =
                dispatch_with_header(&mut app, "/echo", Some((AUTHORIZATION, "Bearer bob"))).await;
            assert_eq!(
                status,
                CacheStatus::Bypass(CacheBypassReason::Authorization)
            );
            assert_eq!(body, "Bearer bob");

            // ... and it doesn't replace the cached anonymous response
            let (status, _, body) = dispatch_with_header(&mut app, "/echo", None).await;
            assert!(matches!(status, CacheStatus::Hit(_)));
            assert_eq!(body, "");

            // The test key extractor doesn't include any headers in the key,
            // so even the headers that the URI one includes prevent caching
            let (status, _, _) = dispatch_with_header(&mut app, "/vary_key_headers", None).await;
            assert_eq!(status, CacheStatus::Bypass(CacheBypassReason::Vary));
            cache.housekeep();
            assert_eq!(cache.len(), 1);
        }
    }

    #[tokio::test]
    async fn test_cache_varying_requests() {
        let cache = Arc::new(CacheBuilder::new(KeyExtractorUriRange).build().unwrap());

        let mut app = Router::new()
            .route("/encoding", get(handler_encoding))
            .route("/encoding_vary", get(handler_encoding_vary))
            .route("/origin", get(handler_reflect_origin))
            .route("/", get(handler_path))
            .route("/main.js", get(handler_path))
            .layer(from_fn_with_state(Arc::clone(&cache), middleware));

        // Each client gets an encoding that it accepts, whether the response declares Vary or not
        let encodings = [("gzip, deflate, br", "br"), ("gzip", "identity")];
        for uri in [
            "http://example.com/encoding",
            "http://example.com/encoding_vary",
        ] {
            for (accept, expected) in encodings {
                let (status, _, body) =
                    dispatch_with_header(&mut app, uri, Some((ACCEPT_ENCODING, accept))).await;
                assert!(matches!(status, CacheStatus::Miss(_)), "{uri} {accept}");
                assert_eq!(body, expected, "{uri} {accept}");
            }

            // Repeated requests are served from the cache, each with its own encoding
            for (accept, expected) in encodings {
                let (status, headers, body) =
                    dispatch_with_header(&mut app, uri, Some((ACCEPT_ENCODING, accept))).await;
                assert!(matches!(status, CacheStatus::Hit(_)), "{uri} {accept}");
                assert_eq!(body, expected, "{uri} {accept}");
                assert_eq!(
                    headers.get(CONTENT_ENCODING).and_then(|x| x.to_str().ok()),
                    (expected == "br").then_some("br"),
                    "{uri} {accept}"
                );
            }
        }

        // CORS headers that reflect the Origin aren't replayed to other origins
        let origins = ["https://a.example", "https://b.example"];
        for origin in origins {
            let (status, headers, _) = dispatch_with_header(
                &mut app,
                "http://example.com/origin",
                Some((ORIGIN, origin)),
            )
            .await;
            assert!(matches!(status, CacheStatus::Miss(_)), "{origin}");
            assert_eq!(headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), origin);
        }

        for origin in origins {
            let (status, headers, _) = dispatch_with_header(
                &mut app,
                "http://example.com/origin",
                Some((ORIGIN, origin)),
            )
            .await;
            assert!(matches!(status, CacheStatus::Hit(_)), "{origin}");
            assert_eq!(headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), origin);
        }

        // Range value can't make the response land under the key of another path
        let (status, _, body) =
            dispatch_with_header(&mut app, "http://example.com/", Some((RANGE, "main.js"))).await;
        assert!(matches!(status, CacheStatus::Miss(_)));
        assert_eq!(body, "/");

        let (status, _, body) =
            dispatch_with_header(&mut app, "http://example.com/main.js", None).await;
        assert!(matches!(status, CacheStatus::Miss(_)));
        assert_eq!(body, "/main.js");

        cache.housekeep();
        assert_eq!(cache.len(), 8);
    }

    #[tokio::test(start_paused = true)]
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
        // Expected cache misses/hits for fast/medium/slow responses, respectively.
        let expected_misses = [1, 1, req_count];
        let expected_hits = [req_count - 1, req_count - 1, 0];
        for (idx, uri) in ["/fast_response", "/medium_response", "/slow_response"]
            .iter()
            .enumerate()
        {
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
                        Some(CacheStatus::Hit(_)) => count_hits += 1,
                        Some(CacheStatus::Miss(_)) => count_misses += 1,
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

        assert!(refresh > 8);
    }
}
