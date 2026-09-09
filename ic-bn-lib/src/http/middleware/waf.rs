use std::{
    net::IpAddr,
    num::NonZeroU32,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use ahash::RandomState;
use anyhow::{Context as _, anyhow};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::{
    Router,
    extract::{Request as AxumRequest, State},
    response::{IntoResponse, Response as AxumResponse},
    routing::post,
};
use bytes::Bytes;
use clap::Args;
use futures::future::BoxFuture;
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    state::{InMemoryState, NotKeyed, keyed::DashMapStateStore},
};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
    header::{HOST, RETRY_AFTER},
};
use humantime::parse_duration;
use itertools::Itertools;
use regex::Regex;
use serde::Deserialize;
use serde_with::{DeserializeFromStr, DisplayFromStr, serde_as};
use tokio::{fs, select, time::interval};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};
use tracing::warn;
use url::Url;

use crate::{
    geoip::CountryCode,
    http::{Error, client::Client, middleware::RemoteAddr},
    tasks::Run,
};

/// WAF CLI
#[derive(Args)]
pub struct WafCli {
    /// Enables the WAF.
    /// Requires one of sources to be defined.
    #[clap(env, long, requires = "waf_input")]
    pub waf_enable: bool,

    /// Enables the WAF API endpoint.
    /// Conflicts with `waf_url` and `waf_file`.
    #[clap(env, long, group = "waf_input")]
    pub waf_api: bool,

    /// URL where to fetch WAF rules.
    /// Conflicts with `waf_api` and `waf_file`.
    #[clap(env, long, group = "waf_input")]
    pub waf_url: Option<Url>,

    /// File from which to load WAF rules.
    /// Conflicts with `waf_api` and `waf_url`.
    #[clap(env, long, group = "waf_input")]
    pub waf_file: Option<PathBuf>,

    /// Interval at which to fetch the rules from the file or URL.
    #[clap(env, long, value_parser = parse_duration, default_value = "10s")]
    pub waf_interval: Duration,
}

/// Matches HTTP status codes or ranges
#[derive(Debug, Clone, Copy, Eq, PartialEq, DeserializeFromStr)]
pub struct StatusRange {
    from: u16,
    to: Option<u16>,
}

impl StatusRange {
    /// Check status code against the range
    pub const fn evaluate(&self, v: StatusCode) -> bool {
        let code = v.as_u16();

        if let Some(to) = self.to {
            return code >= self.from && code <= to;
        }

        code == self.from
    }
}

impl FromStr for StatusRange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut it = s.split('-');
        let (from, to) = (it.next().unwrap(), it.next());
        let from: u16 = from
            .trim()
            .parse()
            .context("unable to parse status range start")?;

        if !(100..=599).contains(&from) {
            return Err(anyhow!("Status code can be between 100 and 599, not {from}").into());
        }

        let to = if let Some(v) = to {
            let v = v
                .trim()
                .parse()
                .context("unable to parse status range end")?;

            if !(100..=599).contains(&v) {
                return Err(anyhow!("Status code can be between 100 and 599, not {v}").into());
            }

            if v <= from {
                return Err(anyhow!(
                    "End of the range should be greater than start ({v} > {from})"
                )
                .into());
            }

            Some(v)
        } else {
            None
        };

        Ok(Self { from, to })
    }
}

/// Matches headers
#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderMatcher {
    #[serde_as(as = "DisplayFromStr")]
    pub name: HeaderName,
    #[serde_as(as = "DisplayFromStr")]
    #[serde(alias = "value")]
    pub regex: Regex,
}

impl PartialEq for HeaderMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.regex.as_str() == other.regex.as_str()
    }
}
impl Eq for HeaderMatcher {}

impl Ord for HeaderMatcher {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.as_str().cmp(other.name.as_str())
    }
}
impl PartialOrd for HeaderMatcher {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl HeaderMatcher {
    /// Check if the header name/value matches
    pub fn evaluate(&self, name: &HeaderName, value: &HeaderValue) -> bool {
        if name != self.name {
            return false;
        }

        let Ok(value) = value.to_str() else {
            return false;
        };

        self.regex.is_match(value)
    }

    /// Check if the header map matches
    pub fn evaluate_headermap(&self, map: &HeaderMap) -> bool {
        map.iter().any(|(name, value)| self.evaluate(name, value))
    }
}

/// Matches against HTTP requests
#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct RequestMatcher {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub host: Option<Regex>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub path: Option<Regex>,
    #[serde_as(as = "Option<Vec<DisplayFromStr>>")]
    pub methods: Option<Vec<Method>>,
    pub headers: Option<Vec<HeaderMatcher>>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub country_code: Option<Regex>,
}

impl PartialEq for RequestMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.methods == other.methods
        // Sort header matchers before comparison
            && self
                .headers
                .as_ref()
                .map(|x| x.clone().into_iter().sorted().collect::<Vec<_>>())
                == other
                    .headers
                    .as_ref()
                    .map(|x| x.clone().into_iter().sorted().collect::<Vec<_>>())
            && self.host.as_ref().map(|x| x.as_str()) == other.host.as_ref().map(|x| x.as_str())
            && self.path.as_ref().map(|x| x.as_str()) == other.path.as_ref().map(|x| x.as_str())
            && self.country_code.as_ref().map(|x| x.as_str()) == other.country_code.as_ref().map(|x| x.as_str())
    }
}
impl Eq for RequestMatcher {}

impl RequestMatcher {
    /// Check if the request matches
    pub fn evaluate<T>(&self, req: &Request<T>) -> bool {
        // Check if host matches
        if let Some(v) = &self.host {
            let host = match req.version() {
                // With <HTTP/2 the host portion of the URI is not populated,
                // so extract the Host header.
                Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => req
                    .headers()
                    .get(HOST)
                    .and_then(|x| x.to_str().ok())
                    .unwrap_or_default(),

                // With >=HTTP/2 it is the other way around - there's no Host header.
                _ => req.uri().host().unwrap_or_default(),
            };

            if !v.is_match(host) {
                return false;
            }
        }

        // Check if path matches
        if let Some(v) = &self.path
            && !v.is_match(
                req.uri()
                    .path_and_query()
                    .map(|x| x.as_str())
                    .unwrap_or_default(),
            )
        {
            return false;
        }

        // Check if country code matches
        if let Some(v) = &self.country_code {
            // If country code matching is requested,
            // but no CountryCode is in the request - then we fail the match
            let Some(country_code) = req.extensions().get::<CountryCode>() else {
                return false;
            };

            if !v.is_match(country_code) {
                return false;
            }
        }

        // Check if any methods match
        if let Some(v) = &self.methods
            && !v.iter().contains(req.method())
        {
            return false;
        }

        // Check that all of header rules match
        if let Some(v) = &self.headers
            && !v.iter().all(|rule| rule.evaluate_headermap(req.headers()))
        {
            return false;
        }

        // Empty rule matches anything
        true
    }
}

/// Matches against HTTP responses
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ResponseMatcher {
    pub headers: Option<Vec<HeaderMatcher>>,
    pub status: Option<Vec<StatusRange>>,
}

impl ResponseMatcher {
    /// Check if the response matches
    pub fn evaluate<T>(&self, req: &Response<T>) -> bool {
        // Check status codes
        if let Some(v) = &self.status
            && !v.iter().any(|x| x.evaluate(req.status()))
        {
            return false;
        }

        // Check that all of header rules match
        if let Some(v) = &self.headers
            && !v.iter().all(|rule| rule.evaluate_headermap(req.headers()))
        {
            return false;
        }

        // Empty rule matches anything
        true
    }
}

/// Decision on the rate limit
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RateLimitDecision {
    Pass,
    Throttle(Duration),
}

/// Type of the rate limiting applied
#[derive(Debug)]
pub enum RateLimitType {
    Global(Quota, RateLimiter<NotKeyed, InMemoryState, DefaultClock>),
    PerIp(
        Quota,
        RateLimiter<IpAddr, DashMapStateStore<IpAddr, RandomState>, DefaultClock>,
    ),
}

impl FromStr for RateLimitType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((typ, limit)) = s.split_once(':') else {
            return Err(anyhow!("expecting limit in 'type:rate' format").into());
        };

        let Some((rate, dur)) = limit.split_once("/") else {
            return Err(anyhow!("expecting rate in 'rate/duration' format").into());
        };

        let rate = rate.parse::<u32>().context("unable to parse rate as u32")?;
        let dur = parse_duration(dur).context("unable to parse duration")?;

        if rate == 0 {
            return Err(anyhow!("rate must be > 0").into());
        }

        if dur == Duration::ZERO {
            return Err(anyhow!("duration cannot be zero").into());
        }

        // We already checked that rate is > 0
        let replenish_period = dur / rate;
        if replenish_period.is_zero() {
            return Err(anyhow!("rate is too high for the given duration").into());
        }

        let quota = Quota::with_period(replenish_period)
            .unwrap()
            .allow_burst(NonZeroU32::new(rate).unwrap());

        Ok(match typ {
            "global" => Self::Global(quota, RateLimiter::direct(quota)),
            "per_ip" => Self::PerIp(
                quota,
                RateLimiter::dashmap_with_hasher(quota, RandomState::new()),
            ),
            _ => return Err(anyhow!("unknown rate limiter type {typ}").into()),
        })
    }
}

impl PartialEq for RateLimitType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Global(q1, _), Self::Global(q2, _)) => q1 == q2,
            (Self::PerIp(q1, _), Self::PerIp(q2, _)) => q1 == q2,
            _ => false,
        }
    }
}
impl Eq for RateLimitType {}

impl RateLimitType {
    /// Evaluate the request against the rate limit
    pub fn allowed<B>(&self, req: &Request<B>) -> RateLimitDecision {
        let (clock, r) = match self {
            Self::Global(_, v) => (v.clock(), v.check()),
            Self::PerIp(_, v) => {
                // Allow if we fail to extract IP.
                // It shouldn't happen ever under normal workload
                // and it's probably better to allow the request in this case.
                let Some(ip) = req.extensions().get::<RemoteAddr>() else {
                    return RateLimitDecision::Pass;
                };

                (v.clock(), v.check_key(ip))
            }
        };

        if let Err(e) = r {
            let dur = e.wait_time_from(clock.now());
            return RateLimitDecision::Throttle(dur);
        }

        RateLimitDecision::Pass
    }
}

/// Action that applies to the requests
#[derive(Debug, PartialEq, Eq)]
pub enum RequestAction {
    Pass,
    Block(StatusCode),
    RateLimit(RateLimitType),
}

impl FromStr for RequestAction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "pass" {
            return Ok(Self::Pass);
        }

        let mut it = s.split(':');
        let (pfx, sfx) = (it.next().unwrap(), it.next());
        if pfx == "block" {
            let code = if let Some(code) = sfx {
                StatusCode::from_str(code).context("unable to parse status code")?
            } else {
                StatusCode::FORBIDDEN
            };

            return Ok(Self::Block(code));
        }

        if pfx == "limit" {
            let Some((_, v)) = s.split_once(':') else {
                return Err(anyhow!("expecting limit definition after ':'").into());
            };

            return Ok(Self::RateLimit(RateLimitType::from_str(v)?));
        }

        Err(anyhow!("unsupported action format").into())
    }
}

/// Action that applies to the responses
#[derive(Debug, PartialEq, Eq)]
pub enum ResponseAction {
    Pass,
    Block(StatusCode),
}

impl FromStr for ResponseAction {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "pass" {
            return Ok(Self::Pass);
        }

        let mut it = s.split(':');
        let (pfx, sfx) = (it.next().unwrap(), it.next());
        if pfx == "block" {
            let code = if let Some(code) = sfx {
                StatusCode::from_str(code).context("unable to parse status code")?
            } else {
                StatusCode::FORBIDDEN
            };

            return Ok(Self::Block(code));
        }

        Err(anyhow!("unsupported action format").into())
    }
}

/// Outcome of the rule evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pass,
    Block(StatusCode),
    Throttle(Duration),
}

impl IntoResponse for Decision {
    fn into_response(self) -> AxumResponse {
        match self {
            Self::Pass => StatusCode::OK.into_response(),
            Self::Block(v) => (v, "Blocked for policy reasons").into_response(),
            Self::Throttle(v) => (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    RETRY_AFTER,
                    HeaderValue::from_str(&(v.as_secs() + 1).to_string()).unwrap(),
                )],
                "Request was rate-limited, consult Retry-After header for a number of seconds after which it can be retried",
            )
                .into_response(),
        }
    }
}

/// Request rule
#[serde_as]
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct RequestRule {
    #[serde(alias = "match")]
    pub matcher: RequestMatcher,
    #[serde_as(as = "DisplayFromStr")]
    pub action: RequestAction,
}

impl RequestRule {
    pub fn evaluate<B>(&self, req: &Request<B>) -> Option<Decision> {
        if !self.matcher.evaluate(req) {
            return None;
        }

        Some(match &self.action {
            RequestAction::Pass => Decision::Pass,
            RequestAction::Block(v) => Decision::Block(*v),
            RequestAction::RateLimit(v) => match v.allowed(req) {
                RateLimitDecision::Pass => Decision::Pass,
                RateLimitDecision::Throttle(v) => Decision::Throttle(v),
            },
        })
    }
}

/// Response rule
#[serde_as]
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct ResponseRule {
    #[serde(alias = "match_req")]
    pub matcher_req: Option<RequestMatcher>,
    #[serde(alias = "match_resp")]
    pub matcher: ResponseMatcher,
    #[serde_as(as = "DisplayFromStr")]
    pub action: ResponseAction,
}

impl ResponseRule {
    pub fn evaluate<B1, B2>(&self, req: &Request<B1>, resp: &Response<B2>) -> Option<Decision> {
        if let Some(v) = &self.matcher_req
            && !v.evaluate(req)
        {
            return None;
        }

        if !self.matcher.evaluate(resp) {
            return None;
        }

        Some(match &self.action {
            ResponseAction::Pass => Decision::Pass,
            ResponseAction::Block(v) => Decision::Block(*v),
        })
    }
}

/// Ruleset
#[derive(Debug, PartialEq, Eq, Deserialize, Default)]
pub struct Ruleset {
    pub requests: Option<Vec<RequestRule>>,
    pub responses: Option<Vec<ResponseRule>>,
}

impl Ruleset {
    fn is_empty(&self) -> bool {
        (self.requests.is_none() || self.requests.as_ref().map(|x| x.is_empty()) == Some(true))
            && (self.responses.is_none()
                || self.responses.as_ref().map(|x| x.is_empty()) == Some(true))
    }

    /// Evaluate given request against ruleset
    fn evaluate_request<B>(&self, req: &Request<B>) -> Decision {
        let Some(v) = &self.requests else {
            return Decision::Pass;
        };

        v.iter()
            .find_map(|x| x.evaluate(req))
            .unwrap_or(Decision::Pass)
    }

    /// Evaluate given request parts & response against ruleset
    fn evaluate_response<B1, B2>(&self, req: &Request<B1>, resp: &Response<B2>) -> Decision {
        let Some(v) = &self.responses else {
            return Decision::Pass;
        };

        v.iter()
            .find_map(|x| x.evaluate(req, resp))
            .unwrap_or(Decision::Pass)
    }
}

/// Web Application Firewall
#[derive(Debug, Clone)]
pub struct Waf<S> {
    ruleset: Arc<ArcSwap<Ruleset>>,
    inner: S,
}

/// Implement Tower Service for Waf
impl<S> Service<AxumRequest> for Waf<S>
where
    S: Service<AxumRequest, Response = AxumResponse> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: AxumRequest) -> Self::Future {
        let ruleset = self.ruleset.load_full();
        // Fast-path
        if ruleset.is_empty() {
            let fut = self.inner.call(request);
            return Box::pin(fut);
        }

        // Evaluate the request
        let decision = ruleset.evaluate_request(&request);
        if decision != Decision::Pass {
            return Box::pin(async move { Ok(decision.into_response()) });
        }

        // Clone the parts for later evaluation
        let (parts, body) = request.into_parts();
        let parts_clone = parts.clone();
        let request = AxumRequest::from_parts(parts, body);

        let future = self.inner.call(request);
        Box::pin(async move {
            let response: AxumResponse = future.await?;

            // Evaluate the response
            let req = Request::from_parts(parts_clone, ());
            let decision = ruleset.evaluate_response(&req, &response);
            if decision != Decision::Pass {
                return Ok(decision.into_response());
            }

            Ok(response)
        })
    }
}

fn parse_ruleset(data: &[u8]) -> Result<Ruleset, Error> {
    let ruleset: Ruleset = serde_json::from_slice(data)
        .context("unable to parse ruleset as JSON")
        .or_else(|_| serde_yaml_ng::from_slice(data))
        .context("unable to parse ruleset as YAML")?;

    Ok(ruleset)
}

/// Trait to fetch ruleset
#[async_trait]
trait FetchesRuleset: Send + Sync {
    async fn fetch_rules(&self) -> Result<Ruleset, Error>;
}

/// Fetches ruleset from the file
struct RulesetFetcherFile {
    path: PathBuf,
}

#[async_trait]
impl FetchesRuleset for RulesetFetcherFile {
    async fn fetch_rules(&self) -> Result<Ruleset, Error> {
        let data = fs::read(&self.path)
            .await
            .context("unable to read ruleset from file")?;

        parse_ruleset(&data)
    }
}

/// Fetches ruleset from the URL
struct RulesetFetcherUrl {
    http_client: Arc<dyn Client>,
    url: Url,
}

#[async_trait]
impl FetchesRuleset for RulesetFetcherUrl {
    async fn fetch_rules(&self) -> Result<Ruleset, Error> {
        let req = reqwest::Request::new(Method::GET, self.url.clone());
        let resp = self
            .http_client
            .execute(req)
            .await
            .context("unable to execute request")?;
        let data = resp.bytes().await.context("unable to get response body")?;

        parse_ruleset(&data)
    }
}

/// Waf layer usable as an Axum middleware
#[derive(Clone, derive_new::new)]
pub struct WafLayer {
    ruleset: Arc<ArcSwap<Ruleset>>,
    fetcher: Option<Arc<dyn FetchesRuleset>>,
    interval: Duration,
}

impl<S> Layer<S> for WafLayer {
    type Service = Waf<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Waf {
            ruleset: self.ruleset.clone(),
            inner,
        }
    }
}

/// API handler to update the ruleset.
/// Supports JSON and YAML.
async fn api_handler(State(state): State<WafLayer>, body: Bytes) -> AxumResponse {
    let ruleset = match parse_ruleset(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Unable to parse ruleset: {e:#}"),
            )
                .into_response();
        }
    };

    warn!("WAF: Ruleset updated over API");
    if state.set_ruleset(ruleset) {
        "Ruleset updated\n"
    } else {
        "Ruleset is the same, not updated\n"
    }
    .into_response()
}

/// Create an API router for nesting
pub fn create_router<S: Send + Sync + Clone + 'static>(layer: WafLayer) -> Router<S> {
    Router::new().route("/update", post(api_handler).with_state(layer))
}

impl WafLayer {
    /// Create a new layer from provided CLI and optional HTTP client
    pub fn new_from_cli(cli: &WafCli, http_client: Option<Arc<dyn Client>>) -> Result<Self, Error> {
        let fetcher = if let Some(v) = &cli.waf_url {
            let Some(http_client) = http_client else {
                return Err(anyhow!("URL source requires HTTP client").into());
            };

            Some(Arc::new(RulesetFetcherUrl {
                http_client,
                url: v.clone(),
            }) as Arc<dyn FetchesRuleset>)
        } else {
            cli.waf_file.as_ref().map(|v| {
                Arc::new(RulesetFetcherFile { path: v.clone() }) as Arc<dyn FetchesRuleset>
            })
        };

        Ok(Self {
            ruleset: Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            fetcher,
            interval: cli.waf_interval,
        })
    }

    /// Updates the ruleset, but only if the new ruleset is different.
    pub fn set_ruleset(&self, new: Ruleset) -> bool {
        let new = Arc::new(new);

        // Check if the new ruleset is different
        if new == self.ruleset.load_full() {
            return false;
        }

        self.ruleset.store(new);
        true
    }

    async fn update_ruleset(&self) {
        let Some(fetcher) = &self.fetcher else {
            return;
        };

        let ruleset = match fetcher.fetch_rules().await {
            Ok(v) => v,
            Err(e) => {
                warn!("WAF: unable to fetch ruleset: {e:#}");
                return;
            }
        };

        if self.set_ruleset(ruleset) {
            warn!("WAF: Ruleset was updated");
        }
    }
}

#[async_trait]
impl Run for WafLayer {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        let mut interval = interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            select! {
                () = token.cancelled() => return Ok(()),
                _ = interval.tick() => self.update_ruleset().await,
            }
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::trivial_regex)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Router, body::Body};
    use serde_json::json;

    use crate::{
        hname,
        http::client::{Client, MockClient},
        hval, regex,
    };

    use super::*;

    #[test]
    fn test_status_range() {
        assert_eq!(
            StatusRange::from_str("100 -   200").unwrap(),
            StatusRange {
                from: 100,
                to: Some(200)
            }
        );

        assert_eq!(
            StatusRange::from_str("100").unwrap(),
            StatusRange {
                from: 100,
                to: None
            }
        );

        assert!(StatusRange::from_str("").is_err());
        assert!(StatusRange::from_str("+").is_err());
        assert!(StatusRange::from_str("-").is_err());
        assert!(StatusRange::from_str("99").is_err());
        assert!(StatusRange::from_str("99-600").is_err());
        assert!(StatusRange::from_str("99-").is_err());
        assert!(StatusRange::from_str("-500").is_err());
        assert!(StatusRange::from_str("101-600").is_err());
        assert!(StatusRange::from_str("199-100").is_err());
        // `to` segment present but not a number
        assert!(StatusRange::from_str("100-abc").is_err());
        // Equal boundaries should be rejected, not just `to < from`
        assert!(StatusRange::from_str("300-300").is_err());

        let range = StatusRange::from_str("200-499").unwrap();

        assert!(range.evaluate(StatusCode::OK));
        assert!(range.evaluate(StatusCode::ACCEPTED));
        assert!(range.evaluate(StatusCode::PERMANENT_REDIRECT));
        assert!(range.evaluate(StatusCode::NOT_FOUND));
        assert!(!range.evaluate(StatusCode::CONTINUE));
        assert!(!range.evaluate(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!range.evaluate(StatusCode::SERVICE_UNAVAILABLE));

        let range = StatusRange::from_str("200").unwrap();
        assert!(range.evaluate(StatusCode::OK));
        assert!(!range.evaluate(StatusCode::ACCEPTED));
    }

    #[test]
    fn test_parse_ruleset_formats() {
        // Valid JSON should parse directly, without needing the YAML fallback
        let json = json!({ "requests": [] }).to_string();
        assert!(parse_ruleset(json.as_bytes()).is_ok());

        // Valid YAML is picked up by the fallback
        assert!(parse_ruleset(b"requests: []\n").is_ok());

        // Invalid as both JSON and YAML representations of a Ruleset
        assert!(parse_ruleset(b"{not valid as either format").is_err());
    }

    #[test]
    fn test_request_matcher_deserialize() {
        let rule = json!({
            "methods": ["GET", "OPTIONS"],
            "headers": [
                {
                    "name": "foo",
                    "regex": "^bar.*$"
                },
                {
                    "name": "dead",
                    "regex": "^beef.*$"
                }
            ],
            "host": "^lala",
            "path": "^/foo",
            "country_code": "^(CH|DE)$",
        })
        .to_string();

        let rule: RequestMatcher = serde_json::from_str(&rule).unwrap();
        assert_eq!(
            rule,
            RequestMatcher {
                methods: Some(vec![Method::GET, Method::OPTIONS]),
                headers: Some(vec![
                    HeaderMatcher {
                        name: hname!("foo"),
                        regex: regex!("^bar.*$"),
                    },
                    HeaderMatcher {
                        name: hname!("dead"),
                        regex: regex!("^beef.*$"),
                    }
                ]),
                host: Some(regex!("^lala")),
                path: Some(regex!("^/foo")),
                country_code: Some(regex!("^(CH|DE)$")),
            }
        );
    }

    #[test]
    fn test_request_matcher_empty() {
        // A matcher with every field unset matches any request
        let rule = RequestMatcher {
            host: None,
            path: None,
            methods: None,
            headers: None,
            country_code: None,
        };

        let req = Request::builder()
            .method(Method::TRACE)
            .uri("https://anything.example/whatever")
            .body("")
            .unwrap();
        assert!(rule.evaluate(&req));
    }

    #[test]
    fn test_request_matcher_host() {
        let rule = RequestMatcher {
            host: Some(regex!("^lala")),
            path: None,
            methods: None,
            headers: None,
            country_code: None,
        };

        // HTTP/2+: host comes from the URI authority
        let req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://lala/foo")
            .body("")
            .unwrap();
        assert!(rule.evaluate(&req));

        let req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://other/foo")
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));

        // HTTP/1.x: host comes from the `Host` header, not the URI
        for http_ver in [Version::HTTP_09, Version::HTTP_10, Version::HTTP_11] {
            let req = Request::builder()
                .version(http_ver)
                .header("host", "lala")
                .uri("https://other/foo")
                .body("")
                .unwrap();
            assert!(rule.evaluate(&req));

            // No Host header -> resolves to an empty string, fails to match
            let req = Request::builder()
                .version(http_ver)
                .uri("https://lala/foo")
                .body("")
                .unwrap();
            assert!(!rule.evaluate(&req));
        }
    }

    #[test]
    fn test_request_matcher_path() {
        let rule = RequestMatcher {
            host: None,
            path: Some(regex!("^/foo")),
            methods: None,
            headers: None,
            country_code: None,
        };

        let req = Request::builder().uri("https://lala/foo").body("").unwrap();
        assert!(rule.evaluate(&req));

        let req = Request::builder()
            .uri("https://lala/foo/bar")
            .body("")
            .unwrap();
        assert!(rule.evaluate(&req));

        let req = Request::builder().uri("https://lala/bar").body("").unwrap();
        assert!(!rule.evaluate(&req));
    }

    #[test]
    fn test_request_matcher_methods() {
        let rule = RequestMatcher {
            host: None,
            path: None,
            methods: Some(vec![Method::GET, Method::OPTIONS]),
            headers: None,
            country_code: None,
        };

        for m in [Method::GET, Method::OPTIONS] {
            let req = Request::builder().method(m).body("").unwrap();
            assert!(rule.evaluate(&req));
        }

        for m in [Method::POST, Method::DELETE] {
            let req = Request::builder().method(m).body("").unwrap();
            assert!(!rule.evaluate(&req));
        }
    }

    #[test]
    fn test_request_matcher_headers() {
        let rule = RequestMatcher {
            host: None,
            path: None,
            methods: None,
            headers: Some(vec![
                HeaderMatcher {
                    name: hname!("foo"),
                    regex: regex!("^bar.*$"),
                },
                HeaderMatcher {
                    name: hname!("dead"),
                    regex: regex!("^beef.*$"),
                },
            ]),
            country_code: None,
        };

        // All header rules match
        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .body("")
            .unwrap();
        assert!(rule.evaluate(&req));

        // One header value fails its regex
        let req = Request::builder()
            .header("foo", "nope")
            .header("dead", "beefbeef")
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));

        // One required header is missing entirely
        let req = Request::builder()
            .header("foo", "barfuss")
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));
    }

    #[test]
    fn test_request_matcher_country_code() {
        let rule = RequestMatcher {
            host: None,
            path: None,
            methods: Some(vec![Method::GET]),
            headers: Some(vec![HeaderMatcher {
                name: hname!("foo"),
                regex: regex!("^bar$"),
            }]),
            country_code: Some(regex!("^(CH|DE)$")),
        };

        let build = |cc: &str, method: Method, header: &str| {
            Request::builder()
                .method(method)
                .header("foo", header)
                .extension(CountryCode(cc.try_into().unwrap()))
                .body("")
                .unwrap()
        };

        // Every field matches
        assert!(rule.evaluate(&build("CH", Method::GET, "bar")));

        assert!(!rule.evaluate(&build("CH", Method::POST, "bar")));
        assert!(!rule.evaluate(&build("CH", Method::GET, "nope")));

        // Extension present but doesn't match the regex, even though
        // methods/headers would otherwise pass
        assert!(!rule.evaluate(&build("US", Method::GET, "bar")));

        // No CountryCode extension at all
        let req = Request::builder()
            .method(Method::GET)
            .header("foo", "bar")
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));
    }

    #[test]
    fn test_request_matcher_full_match() {
        let rule = RequestMatcher {
            host: Some(regex!("^lala")),
            path: Some(regex!("^/foo")),
            methods: Some(vec![Method::GET, Method::OPTIONS]),
            headers: Some(vec![
                HeaderMatcher {
                    name: hname!("foo"),
                    regex: regex!("^bar.*$"),
                },
                HeaderMatcher {
                    name: hname!("dead"),
                    regex: regex!("^beef.*$"),
                },
            ]),
            country_code: Some(regex!("^(CH|DE)$")),
        };

        let build = |method: Method, uri: &str| {
            Request::builder()
                .version(Version::HTTP_2)
                .method(method)
                .uri(uri)
                .header("foo", "barfuss")
                .header("dead", "beefbeef")
                .extension(CountryCode("CH".try_into().unwrap()))
                .body("")
                .unwrap()
        };

        assert!(rule.evaluate(&build(Method::GET, "https://lala/foo")));
        assert!(rule.evaluate(&build(Method::OPTIONS, "https://lala/foo")));

        // Each field, perturbed individually, should fail the match
        assert!(!rule.evaluate(&build(Method::POST, "https://lala/foo")));
        assert!(!rule.evaluate(&build(Method::GET, "https://other/foo")));
        assert!(!rule.evaluate(&build(Method::GET, "https://lala/bar")));

        let req = Request::builder()
            .version(Version::HTTP_2)
            .method(Method::GET)
            .uri("https://lala/foo")
            .header("fox", "barfuss")
            .header("dead", "beefbeef")
            .extension(CountryCode("CH".try_into().unwrap()))
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));

        let mut req = build(Method::GET, "https://lala/foo");
        req.extensions_mut()
            .insert(CountryCode("US".try_into().unwrap()));
        assert!(!rule.evaluate(&req));
    }

    #[test]
    fn test_header_matcher() {
        let m = HeaderMatcher {
            name: hname!("foo"),
            regex: regex!("^bar"),
        };

        // Matching name and value
        assert!(m.evaluate(&hname!("foo"), &hval!("barfuss")));

        // Name mismatch -- the value alone would satisfy the regex
        assert!(!m.evaluate(&hname!("baz"), &hval!("bar")));

        // Value fails to_str() (invalid UTF-8), even with a permissive regex
        let permissive = HeaderMatcher {
            name: hname!("foo"),
            regex: regex!(".*"),
        };
        let bad_value = HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();
        assert!(!permissive.evaluate(&hname!("foo"), &bad_value));

        // evaluate_headermap finds a match anywhere in the map
        let mut map = HeaderMap::new();
        map.insert(hname!("other"), hval!("irrelevant"));
        map.insert(hname!("foo"), hval!("barfuss"));
        assert!(m.evaluate_headermap(&map));

        map.remove(hname!("foo"));
        assert!(!m.evaluate_headermap(&map));
    }

    #[test]
    fn test_header_matcher_ord() {
        let mut v = [
            HeaderMatcher {
                name: hname!("zzz"),
                regex: regex!(".*"),
            },
            HeaderMatcher {
                name: hname!("aaa"),
                regex: regex!(".*"),
            },
            HeaderMatcher {
                name: hname!("mmm"),
                regex: regex!(".*"),
            },
        ];
        v.sort();
        let names: Vec<_> = v.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, vec!["aaa", "mmm", "zzz"]);

        // RequestMatcher equality sorts headers before comparing, so
        // differing input order shouldn't affect equality.
        let a = RequestMatcher {
            host: None,
            path: None,
            methods: None,
            headers: Some(vec![
                HeaderMatcher {
                    name: hname!("foo"),
                    regex: regex!("^bar.*$"),
                },
                HeaderMatcher {
                    name: hname!("dead"),
                    regex: regex!("^beef.*$"),
                },
            ]),
            country_code: None,
        };
        let b = RequestMatcher {
            host: None,
            path: None,
            methods: None,
            headers: Some(vec![
                HeaderMatcher {
                    name: hname!("dead"),
                    regex: regex!("^beef.*$"),
                },
                HeaderMatcher {
                    name: hname!("foo"),
                    regex: regex!("^bar.*$"),
                },
            ]),
            country_code: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_response() {
        let rule = json!({
            "status": ["100-200", "307", "400-500"],
            "headers": [
                {
                    "name": "foo",
                    "regex": "^bar.*$"
                },
                {
                    "name": "dead",
                    "regex": "^beef.*$"
                }
            ],
        })
        .to_string();

        let rule: ResponseMatcher = serde_json::from_str(&rule).unwrap();
        assert_eq!(
            rule,
            ResponseMatcher {
                status: Some(vec![
                    StatusRange::from_str("100-200").unwrap(),
                    StatusRange::from_str("307").unwrap(),
                    StatusRange::from_str("400-500").unwrap()
                ]),
                headers: Some(vec![
                    HeaderMatcher {
                        name: hname!("foo"),
                        regex: regex!("^bar.*$"),
                    },
                    HeaderMatcher {
                        name: hname!("dead"),
                        regex: regex!("^beef.*$"),
                    }
                ]),
            }
        );

        // Test full matches
        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::OK)
            .body("")
            .unwrap();
        assert!(rule.evaluate(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::CONTINUE)
            .body("")
            .unwrap();
        assert!(rule.evaluate(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::TEMPORARY_REDIRECT)
            .body("")
            .unwrap();
        assert!(rule.evaluate(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::NOT_FOUND)
            .body("")
            .unwrap();
        assert!(rule.evaluate(&resp));

        // Test partial matches (no match)
        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::PERMANENT_REDIRECT)
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "zbeefbeef")
            .status(StatusCode::OK)
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&resp));
    }

    #[test]
    fn test_response_matcher_empty() {
        // A matcher with every field unset matches any response
        let rule = ResponseMatcher {
            status: None,
            headers: None,
        };

        let resp = Response::builder().status(200).body("").unwrap();
        assert!(rule.evaluate(&resp));

        let resp = Response::builder()
            .status(500)
            .header("x", "y")
            .body("")
            .unwrap();
        assert!(rule.evaluate(&resp));
    }

    #[test]
    fn test_response_matcher_headers_only() {
        // status: None means the status check is skipped entirely
        let rule = ResponseMatcher {
            status: None,
            headers: Some(vec![HeaderMatcher {
                name: hname!("foo"),
                regex: regex!("^bar.*$"),
            }]),
        };

        for status in [StatusCode::OK, StatusCode::INTERNAL_SERVER_ERROR] {
            let resp = Response::builder()
                .status(status)
                .header("foo", "barfuss")
                .body("")
                .unwrap();
            assert!(rule.evaluate(&resp));

            let resp = Response::builder()
                .status(status)
                .header("foo", "nope")
                .body("")
                .unwrap();
            assert!(!rule.evaluate(&resp));
        }
    }

    #[test]
    fn test_request_action() {
        assert_eq!(
            RequestAction::from_str("pass").unwrap(),
            RequestAction::Pass
        );

        assert_eq!(
            RequestAction::from_str("block").unwrap(),
            RequestAction::Block(StatusCode::FORBIDDEN)
        );

        assert_eq!(
            RequestAction::from_str("block:451").unwrap(),
            RequestAction::Block(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
        );

        assert!(RequestAction::from_str("block:0").is_err());
        assert!(RequestAction::from_str("block:foo").is_err());
        assert!(RequestAction::from_str("foo").is_err());

        assert_eq!(
            RequestAction::from_str("limit:global:10/1m").unwrap(),
            RequestAction::RateLimit(RateLimitType::Global(
                Quota::with_period(Duration::from_secs(6))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(10).unwrap()),
                RateLimiter::direct(Quota::with_period(Duration::from_secs(6)).unwrap())
            ))
        );

        assert_eq!(
            RequestAction::from_str("limit:per_ip:10/1m").unwrap(),
            RequestAction::RateLimit(RateLimitType::PerIp(
                Quota::with_period(Duration::from_secs(6))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(10).unwrap()),
                RateLimiter::dashmap_with_hasher(
                    Quota::with_period(Duration::from_secs(6)).unwrap(),
                    RandomState::new()
                )
            ))
        );

        assert!(RequestAction::from_str("limit").is_err());
        assert!(RequestAction::from_str("limit:").is_err());
        // Propagates errors from RateLimitType::from_str -- see
        // test_rate_limit_type_from_str for its detailed error branches.
        assert!(RequestAction::from_str("limit:foo").is_err());
    }

    #[test]
    fn test_response_action() {
        assert_eq!(
            ResponseAction::from_str("pass").unwrap(),
            ResponseAction::Pass
        );

        assert_eq!(
            ResponseAction::from_str("block").unwrap(),
            ResponseAction::Block(StatusCode::FORBIDDEN)
        );

        assert_eq!(
            ResponseAction::from_str("block:451").unwrap(),
            ResponseAction::Block(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
        );

        assert!(ResponseAction::from_str("block:0").is_err());
        assert!(ResponseAction::from_str("block:foo").is_err());
        assert!(ResponseAction::from_str("foo").is_err());
    }

    #[test]
    fn test_rate_limit_type_from_str() {
        assert!(RateLimitType::from_str("global:10/1m").is_ok());
        assert!(RateLimitType::from_str("per_ip:10/1m").is_ok());

        // Missing ':' for the 'type:rate' format
        assert!(RateLimitType::from_str("10/1m").is_err());
        // Missing '/' for the 'rate/duration' format
        assert!(RateLimitType::from_str("global:10").is_err());
        // Rate fails to parse as u32
        assert!(RateLimitType::from_str("global:foo/1m").is_err());
        assert!(RateLimitType::from_str("global:99999999999/1m").is_err());
        // Duration fails to parse
        assert!(RateLimitType::from_str("global:10/foo").is_err());
        // Rate must be > 0
        assert!(RateLimitType::from_str("global:0/1s").is_err());
        assert!(RateLimitType::from_str("per_ip:0/1s").is_err());
        // Duration cannot be zero
        assert!(RateLimitType::from_str("global:10/0s").is_err());
        assert!(RateLimitType::from_str("per_ip:10/0s").is_err());
        // Unknown limiter type
        assert!(RateLimitType::from_str("bogus:10/1m").is_err());

        // Rate high enough that `dur / rate` truncates to zero should be a
        // parse error, not a panic (dur/rate used to be passed unchecked
        // into `Quota::with_period(..).unwrap()`, which panics on a zero
        // duration).
        assert!(RateLimitType::from_str("global:2000000000/1s").is_err());
        assert!(RateLimitType::from_str("per_ip:2000000000/1s").is_err());
    }

    #[test]
    fn test_rate_limit_type_eq() {
        let a = RateLimitType::from_str("global:10/1m").unwrap();
        let b = RateLimitType::from_str("global:10/1m").unwrap();
        let c = RateLimitType::from_str("global:20/1m").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);

        let d = RateLimitType::from_str("per_ip:10/1m").unwrap();
        let e = RateLimitType::from_str("per_ip:10/1m").unwrap();
        let f = RateLimitType::from_str("per_ip:20/1m").unwrap();
        assert_eq!(d, e);
        assert_ne!(d, f);

        // Different variants are never equal, regardless of quota
        assert_ne!(a, d);
    }

    #[test]
    fn test_rate_limit_type_allowed_global() {
        let rl = RateLimitType::from_str("global:2/1h").unwrap();
        let req = Request::builder().body(()).unwrap();

        assert_eq!(rl.allowed(&req), RateLimitDecision::Pass);
        assert_eq!(rl.allowed(&req), RateLimitDecision::Pass);
        assert!(matches!(rl.allowed(&req), RateLimitDecision::Throttle(_)));
    }

    #[test]
    fn test_rate_limit_type_allowed_per_ip() {
        let rl = RateLimitType::from_str("per_ip:1/1h").unwrap();

        // No RemoteAddr extension at all -> defensive Pass, regardless of
        // how many requests come through.
        let req_no_addr = Request::builder().body(()).unwrap();
        for _ in 0..10 {
            assert_eq!(rl.allowed(&req_no_addr), RateLimitDecision::Pass);
        }

        // Per-IP quota: first request for an IP passes, the next throttles
        let mut req_a = Request::builder().body(()).unwrap();
        req_a
            .extensions_mut()
            .insert(RemoteAddr(IpAddr::from_str("1.2.3.4").unwrap()));
        assert_eq!(rl.allowed(&req_a), RateLimitDecision::Pass);
        assert!(matches!(rl.allowed(&req_a), RateLimitDecision::Throttle(_)));

        // A different IP has an independent quota
        let mut req_b = Request::builder().body(()).unwrap();
        req_b
            .extensions_mut()
            .insert(RemoteAddr(IpAddr::from_str("5.6.7.8").unwrap()));
        assert_eq!(rl.allowed(&req_b), RateLimitDecision::Pass);
    }

    #[test]
    fn test_ruleset_is_empty() {
        let ruleset: Ruleset = serde_json::from_str(
            &json!({
                "requests": [
                { "match": { "methods": ["GET"] }, "action": "block:403" }
                ]
            })
            .to_string(),
        )
        .unwrap();
        assert!(!ruleset.is_empty());

        let ruleset: Ruleset = serde_json::from_str(
            &json!({
                "responses": [
                { "match_resp": { "status": ["500"] }, "action": "block:403" }
                ]
            })
            .to_string(),
        )
        .unwrap();
        assert!(!ruleset.is_empty());

        // Both fields present but empty
        let ruleset: Ruleset =
            serde_json::from_str(&json!({"requests": [], "responses": []}).to_string()).unwrap();
        assert!(ruleset.is_empty());

        // Both fields entirely absent
        let ruleset: Ruleset = serde_json::from_str(&json!({}).to_string()).unwrap();
        assert!(ruleset.is_empty());

        // One field present-but-empty, the other absent entirely: a
        // combination independent of the two cases above -- a
        // requests/responses field-swap bug in is_empty() would still pass
        // those but fail these.
        let ruleset: Ruleset = serde_json::from_str(&json!({"requests": []}).to_string()).unwrap();
        assert!(ruleset.is_empty());

        let ruleset: Ruleset = serde_json::from_str(&json!({"responses": []}).to_string()).unwrap();
        assert!(ruleset.is_empty());
    }

    #[test]
    fn test_ruleset_evaluate_request() {
        let probe = Request::builder().method(Method::GET).body("").unwrap();

        // Neither field set, or a present-but-empty requests field: both
        // fall through to Decision::Pass from within evaluate_request
        // itself, not merely via the Waf service's separate is_empty()
        // fast path.
        let empty = Ruleset {
            requests: None,
            responses: None,
        };
        assert_eq!(empty.evaluate_request(&probe), Decision::Pass);

        let empty_vec = Ruleset {
            requests: Some(vec![]),
            responses: None,
        };
        assert_eq!(empty_vec.evaluate_request(&probe), Decision::Pass);

        // An earlier rule with an explicit `pass` action stops the scan
        // before a later, also-matching, blocking rule is considered.
        let ruleset: Ruleset = serde_json::from_str(
            &json!({
                "requests": [
                { "match": { "methods": ["GET"] }, "action": "pass" },
                { "match": { "methods": ["GET"] }, "action": "block:403" }
                ]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(ruleset.evaluate_request(&probe), Decision::Pass);

        // First-match-wins between two overlapping blocking rules
        let ruleset: Ruleset = serde_json::from_str(
            &json!({
                "requests": [
                { "match": { "methods": ["GET"] }, "action": "block:451" },
                { "match": { "methods": ["GET"] }, "action": "block:403" }
                ]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            ruleset.evaluate_request(&probe),
            Decision::Block(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
        );

        let ruleset = json!({
            "requests": [
            {
                "match": {
                    "methods": ["GET", "POST"],
                    "host": "^foo",
                    "path": "^/bar"
                },
                "action": "limit:global:10/1h",
            },
            {
                "match": {
                    "methods": ["DELETE"],
                },
                "action": "block:403",
            }]
        })
        .to_string();
        let ruleset: Ruleset = serde_json::from_str(&ruleset).unwrap();

        // Should always pass (matches no rule)
        for _ in 0..1000 {
            let req = Request::builder().method(Method::OPTIONS).body("").unwrap();
            assert_eq!(ruleset.evaluate_request(&req), Decision::Pass);
        }

        // Should always block
        for _ in 0..1000 {
            let req = Request::builder().method(Method::DELETE).body("").unwrap();
            assert_eq!(
                ruleset.evaluate_request(&req),
                Decision::Block(StatusCode::FORBIDDEN)
            );
        }

        // 10 should go through, the rest throttled
        for _ in 0..10 {
            let req = Request::builder()
                .method(Method::GET)
                .version(Version::HTTP_2)
                .uri("https://foo/bar")
                .body("")
                .unwrap();
            assert_eq!(ruleset.evaluate_request(&req), Decision::Pass);
        }

        let req = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_2)
            .uri("https://foo/bar")
            .body("")
            .unwrap();

        let r = ruleset.evaluate_request(&req);
        match r {
            Decision::Throttle(v) => {
                assert!(v >= Duration::from_secs(359) && v <= Duration::from_secs(360))
            }
            _ => unreachable!(),
        }

        for _ in 0..1000 {
            let req = Request::builder()
                .method(Method::GET)
                .version(Version::HTTP_2)
                .uri("https://foo/bar")
                .body("")
                .unwrap();
            assert!(matches!(
                ruleset.evaluate_request(&req),
                Decision::Throttle(_)
            ));
        }
    }

    #[test]
    fn test_ruleset_evaluate_response() {
        let probe_req = Request::builder().method(Method::POST).body(()).unwrap();
        let probe_resp = Response::builder().status(200).body("").unwrap();

        // Neither field set, or a present-but-empty responses field: both
        // fall through to Decision::Pass from within evaluate_response
        // itself.
        let empty = Ruleset {
            requests: None,
            responses: None,
        };
        assert_eq!(
            empty.evaluate_response(&probe_req, &probe_resp),
            Decision::Pass
        );

        let empty_vec = Ruleset {
            requests: None,
            responses: Some(vec![]),
        };
        assert_eq!(
            empty_vec.evaluate_response(&probe_req, &probe_resp),
            Decision::Pass
        );

        // An earlier rule with an explicit `pass` action stops the scan
        // before a later, also-matching, blocking rule is considered.
        let ruleset: Ruleset = serde_json::from_str(
            &json!({
                "responses": [
                { "match_resp": { "status": ["200"] }, "action": "pass" },
                { "match_resp": { "status": ["200"] }, "action": "block:403" }
                ]
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            ruleset.evaluate_response(&probe_req, &probe_resp),
            Decision::Pass
        );

        let ruleset = json!({
            "responses": [
            {
                "match_req": {
                    "methods": ["OPTIONS"],
                },
                "match_resp": {
                    "status": ["100-200", "400-499", "599"],
                },
                "action": "block:499",
            },
            {
                "match_resp": {
                    "status": ["100-200", "400-499", "599"],
                },
                "action": "block:451",
            },
            {
                "match_resp": {
                    "status": ["500"],
                    "headers": [{
                        "name": "foo",
                        "value": "bar.*",
                    }]
                },
                "action": "block:401",
            }]
        })
        .to_string();
        let ruleset: Ruleset = serde_json::from_str(&ruleset).unwrap();

        let req = Request::builder().method(Method::POST).body(()).unwrap();

        let resp = Response::builder()
            .status(StatusCode::PERMANENT_REDIRECT)
            .body("")
            .unwrap();

        // Should always pass
        for _ in 0..1000 {
            assert_eq!(ruleset.evaluate_response(&req, &resp), Decision::Pass);
        }

        // Should always block with 451
        for _ in 0..1000 {
            let resp = Response::builder().status(StatusCode::OK).body("").unwrap();
            assert_eq!(
                ruleset.evaluate_response(&req, &resp),
                Decision::Block(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
            );
        }

        // Should always block with 499 -- first-match-wins: this request
        // also matches rule 2 (451), but rule 1 (OPTIONS-only) comes first.
        let req = Request::builder().method(Method::OPTIONS).body(()).unwrap();

        for _ in 0..1000 {
            let resp = Response::builder().status(StatusCode::OK).body("").unwrap();
            assert_eq!(
                ruleset.evaluate_response(&req, &resp),
                Decision::Block(StatusCode::from_u16(499).unwrap())
            );
        }

        // Should always block with 401
        let resp = Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("foo", "bardead")
            .body("")
            .unwrap();

        for _ in 0..1000 {
            assert_eq!(
                ruleset.evaluate_response(&req, &resp),
                Decision::Block(StatusCode::UNAUTHORIZED)
            );
        }
    }

    #[tokio::test]
    async fn test_waflayer() {
        use axum::routing::get;

        let ruleset = Ruleset::default();
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(ruleset))),
            None,
            Duration::ZERO,
        );

        let ruleset = r#"
        requests:
        - action: block:451
          match:
            methods:
            - OPTIONS
            - GET
            headers:
            - name: foo
              regex: ^bar.*$
        "#;

        assert!(layer.set_ruleset(parse_ruleset(ruleset.as_bytes()).unwrap()));
        assert!(!layer.set_ruleset(parse_ruleset(ruleset.as_bytes()).unwrap()));

        let mut router = Router::new()
            .route("/", get(|| async { "foo" }).options(|| async { "bar" }))
            .layer(layer);

        // Should block
        let req = Request::builder()
            .method(Method::OPTIONS)
            .header("foo", "barfuss")
            .body(Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);

        let req = Request::builder()
            .method(Method::GET)
            .header("foo", "barfuss")
            .body(Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);

        // Should pass
        let req = Request::builder()
            .method(Method::OPTIONS)
            .body(Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_waf_fast_path_empty_ruleset() {
        use axum::routing::get;

        // With an empty ruleset, the Waf service should take its fast path
        // and call straight through to the inner handler.
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            None,
            Duration::ZERO,
        );
        let mut router = Router::new()
            .route("/", get(|| async { (StatusCode::IM_A_TEAPOT, "hi") }))
            .layer(layer);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn test_waf_blocks_via_response_rule() {
        use axum::routing::get;

        // A response-side rule must call through to the inner handler
        // first, then evaluate (and can override) its actual response.
        let ruleset = parse_ruleset(
            b"responses:\n- match_resp:\n    status: [\"404\"]\n  action: block:451\n",
        )
        .unwrap();
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(ruleset))),
            None,
            Duration::ZERO,
        );

        let mut router = Router::new()
            .route("/", get(|| async { StatusCode::NOT_FOUND }))
            .layer(layer);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
    }

    #[test]
    fn test_waflayer_new_from_cli() {
        // Neither url nor file -> no fetcher
        let cli = WafCli {
            waf_enable: false,
            waf_api: false,
            waf_url: None,
            waf_file: None,
            waf_interval: Duration::from_secs(1),
        };
        let layer = WafLayer::new_from_cli(&cli, None).unwrap();
        assert!(layer.fetcher.is_none());

        // File source -> file fetcher, no HTTP client needed
        let cli = WafCli {
            waf_enable: false,
            waf_api: false,
            waf_url: None,
            waf_file: Some(PathBuf::from("/tmp/does-not-need-to-exist.yaml")),
            waf_interval: Duration::from_secs(1),
        };
        let layer = WafLayer::new_from_cli(&cli, None).unwrap();
        assert!(layer.fetcher.is_some());

        // URL source without an HTTP client -> error
        let cli = WafCli {
            waf_enable: false,
            waf_api: false,
            waf_url: Some(Url::parse("http://example.com/waf").unwrap()),
            waf_file: None,
            waf_interval: Duration::from_secs(1),
        };
        assert!(WafLayer::new_from_cli(&cli, None).is_err());

        // URL source with an HTTP client -> URL fetcher
        let client: Arc<dyn Client> = Arc::new(MockClient::new());
        let layer = WafLayer::new_from_cli(&cli, Some(client)).unwrap();
        assert!(layer.fetcher.is_some());
    }

    struct OkFetcher(&'static [u8]);

    #[async_trait]
    impl FetchesRuleset for OkFetcher {
        async fn fetch_rules(&self) -> Result<Ruleset, Error> {
            parse_ruleset(self.0)
        }
    }

    struct ErrFetcher;

    #[async_trait]
    impl FetchesRuleset for ErrFetcher {
        async fn fetch_rules(&self) -> Result<Ruleset, Error> {
            Err(anyhow!("boom").into())
        }
    }

    struct CountingFetcher(Arc<AtomicUsize>);

    #[async_trait]
    impl FetchesRuleset for CountingFetcher {
        async fn fetch_rules(&self) -> Result<Ruleset, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(anyhow!("no-op").into())
        }
    }

    #[tokio::test]
    async fn test_waflayer_update_ruleset() {
        // No fetcher configured -> no-op
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            None,
            Duration::ZERO,
        );
        layer.update_ruleset().await;
        assert_eq!(layer.ruleset.load_full(), Arc::new(Ruleset::default()));

        // Fetch error -> no-op, ruleset unchanged
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            Some(Arc::new(ErrFetcher) as Arc<dyn FetchesRuleset>),
            Duration::ZERO,
        );
        layer.update_ruleset().await;
        assert_eq!(layer.ruleset.load_full(), Arc::new(Ruleset::default()));

        // Fetch success -> ruleset applied
        let yaml: &'static [u8] = b"requests:\n- action: block:403\n  match: {}\n";
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            Some(Arc::new(OkFetcher(yaml)) as Arc<dyn FetchesRuleset>),
            Duration::ZERO,
        );
        layer.update_ruleset().await;
        assert_ne!(layer.ruleset.load_full(), Arc::new(Ruleset::default()));
    }

    #[tokio::test]
    async fn test_waflayer_run_ticks_and_cancels() {
        let counter = Arc::new(AtomicUsize::new(0));
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            Some(Arc::new(CountingFetcher(counter.clone())) as Arc<dyn FetchesRuleset>),
            Duration::from_millis(5),
        );

        let token = CancellationToken::new();
        let task = tokio::spawn({
            let token = token.clone();
            async move { layer.run(token).await }
        });

        // Wait until the background loop has ticked at least once
        let mut ticked = false;
        for _ in 0..200 {
            if counter.load(Ordering::SeqCst) > 0 {
                ticked = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(ticked, "run() never invoked the fetcher");

        token.cancel();
        let res = tokio::time::timeout(Duration::from_secs(1), task).await;
        assert!(
            res.is_ok(),
            "run() did not terminate promptly after cancellation"
        );
    }

    #[tokio::test]
    async fn test_ruleset_fetcher_file() {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"requests:\n- action: block:403\n  match: {}\n")
            .unwrap();

        let fetcher = RulesetFetcherFile {
            path: file.path().to_path_buf(),
        };
        let ruleset = fetcher.fetch_rules().await.unwrap();
        assert!(!ruleset.is_empty());

        let fetcher = RulesetFetcherFile {
            path: PathBuf::from("/nonexistent/path/does-not-exist.yaml"),
        };
        assert!(fetcher.fetch_rules().await.is_err());
    }

    #[tokio::test]
    async fn test_ruleset_fetcher_url() {
        let mut mock = MockClient::new();
        mock.expect_execute().returning(|_req| {
            let resp: reqwest::Response =
                Response::new("requests:\n- action: block:403\n  match: {}\n".to_string()).into();
            Ok(resp)
        });

        let fetcher = RulesetFetcherUrl {
            http_client: Arc::new(mock),
            url: Url::parse("http://example.com/waf.yaml").unwrap(),
        };
        let ruleset = fetcher.fetch_rules().await.unwrap();
        assert!(!ruleset.is_empty());
    }

    #[tokio::test]
    async fn test_api_handler() {
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            None,
            Duration::ZERO,
        );

        // Invalid body -> 400
        let resp = api_handler(
            State(layer.clone()),
            Bytes::from_static(b"{not valid at all"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Valid body -> ruleset updated
        let yaml = b"requests:\n- action: block:403\n  match: {}\n";
        let resp = api_handler(State(layer.clone()), Bytes::from_static(yaml)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"Ruleset updated\n");

        // Same body again -> reports no change
        let resp = api_handler(State(layer.clone()), Bytes::from_static(yaml)).await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"Ruleset is the same, not updated\n");
    }

    #[tokio::test]
    async fn test_create_router() {
        let layer = WafLayer::new(
            Arc::new(ArcSwap::new(Arc::new(Ruleset::default()))),
            None,
            Duration::ZERO,
        );
        let mut router: Router = create_router(layer);

        let yaml = b"requests:\n- action: block:403\n  match: {}\n";
        let req = Request::builder()
            .method(Method::POST)
            .uri("/update")
            .body(Body::from(yaml.to_vec()))
            .unwrap();
        let resp = router.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
