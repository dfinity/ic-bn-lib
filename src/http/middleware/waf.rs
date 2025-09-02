use std::{net::IpAddr, num::NonZeroU32, str::FromStr, time::Duration};

use ahash::RandomState;
use anyhow::{Context, anyhow};
use axum::response::{IntoResponse, Response};
use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock},
    state::{InMemoryState, NotKeyed, keyed::DashMapStateStore},
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header::RETRY_AFTER};
use humantime::parse_duration;
use itertools::Itertools;
use regex::Regex;
use serde::Deserialize;
use serde_with::{DeserializeFromStr, DisplayFromStr, serde_as};

use crate::http::{Error, middleware::extract_ip_from_request};

/// Matches HTTP status codes or ranges
#[derive(Debug, Clone, Copy, Eq, PartialEq, DeserializeFromStr)]
pub struct StatusRange {
    from: u16,
    to: Option<u16>,
}

impl StatusRange {
    pub const fn evaluate(&self, v: StatusCode) -> bool {
        let code = v.as_u16();

        if let Some(to) = self.to {
            return code >= self.from && code <= to;
        }

        code == self.from
    }
}

impl FromStr for StatusRange {
    type Err = crate::http::Error;

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

impl HeaderMatcher {
    pub fn evaluate(&self, name: &HeaderName, value: &HeaderValue) -> bool {
        if name != self.name {
            return false;
        }

        let Ok(value) = value.to_str() else {
            return false;
        };

        self.regex.is_match(value)
    }

    pub fn evaluate_headermap(&self, map: &HeaderMap) -> bool {
        map.iter().any(|(name, value)| self.evaluate(name, value))
    }
}

/// Matches against HTTP requests
#[serde_as]
#[derive(Debug, Clone, Deserialize)]
pub struct RequestMatcher {
    #[serde_as(as = "Option<Vec<DisplayFromStr>>")]
    pub methods: Option<Vec<Method>>,
    pub headers: Option<Vec<HeaderMatcher>>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub url: Option<Regex>,
}

impl PartialEq for RequestMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.methods == other.methods
            && self.headers == other.headers
            && self.url.as_ref().map(|x| x.as_str()) == other.url.as_ref().map(|x| x.as_str())
    }
}
impl Eq for RequestMatcher {}

impl RequestMatcher {
    pub fn evaluate<T>(&self, req: &Request<T>) -> bool {
        // Check if URL matches
        if let Some(v) = &self.url {
            if !v.is_match(&req.uri().to_string()) {
                return false;
            }
        }

        // Check if any methods match
        if let Some(v) = &self.methods {
            if !v.iter().contains(req.method()) {
                return false;
            }
        }

        // Check that all of header rules match
        if let Some(v) = &self.headers {
            if !v.iter().all(|rule| rule.evaluate_headermap(req.headers())) {
                return false;
            }
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
    pub fn evaluate<T>(&self, req: &Response<T>) -> bool {
        // Check status codes
        if let Some(v) = &self.status {
            if !v.iter().any(|x| x.evaluate(req.status())) {
                return false;
            }
        }

        // Check that all of header rules match
        if let Some(v) = &self.headers {
            if !v.iter().all(|rule| rule.evaluate_headermap(req.headers())) {
                return false;
            }
        }

        // Empty rule matches anything
        true
    }
}

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
                let Some(ip) = extract_ip_from_request(req) else {
                    return RateLimitDecision::Pass;
                };

                (v.clock(), v.check_key(&ip))
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
    fn into_response(self) -> Response {
        match self {
            Self::Pass => StatusCode::OK.into_response(),
            Self::Block(v) => (v, "Blocked for policy reasons").into_response(),
            Self::Throttle(v) => (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    RETRY_AFTER,
                    HeaderValue::from_str(&v.as_secs().to_string()).unwrap(),
                )],
                "Rate limited",
            )
                .into_response(),
        }
    }
}

/// Request rule
#[serde_as]
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct RequestRule {
    #[serde(alias = "rule")]
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
    #[serde(alias = "rule")]
    pub matcher: ResponseMatcher,
    #[serde_as(as = "DisplayFromStr")]
    pub action: ResponseAction,
}

impl ResponseRule {
    pub fn evaluate<B>(&self, resp: &Response<B>) -> Option<Decision> {
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
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct Ruleset {
    pub requests: Option<Vec<RequestRule>>,
    pub responses: Option<Vec<ResponseRule>>,
}

impl Ruleset {
    /// Evaluate given request against ruleset
    pub fn evaluate_request<B>(&self, req: &Request<B>) -> Decision {
        let Some(v) = &self.requests else {
            return Decision::Pass;
        };

        v.iter()
            .find_map(|x| x.evaluate(req))
            .unwrap_or(Decision::Pass)
    }

    /// Evaluate given response against ruleset
    pub fn evaluate_response<B>(&self, resp: &Response<B>) -> Decision {
        let Some(v) = &self.responses else {
            return Decision::Pass;
        };

        v.iter()
            .find_map(|x| x.evaluate(resp))
            .unwrap_or(Decision::Pass)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

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
    fn test_request() {
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
            "url": "^https",
        })
        .to_string();

        let rule: RequestMatcher = serde_json::from_str(&rule).unwrap();
        assert_eq!(
            rule,
            RequestMatcher {
                methods: Some(vec![Method::GET, Method::OPTIONS]),
                headers: Some(vec![
                    HeaderMatcher {
                        name: HeaderName::from_static("foo"),
                        regex: Regex::from_str("^bar.*$").unwrap(),
                    },
                    HeaderMatcher {
                        name: HeaderName::from_static("dead"),
                        regex: Regex::from_str("^beef.*$").unwrap(),
                    }
                ]),
                url: Some(Regex::from_str("^https").unwrap(),)
            }
        );

        // Test full matches
        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::GET)
            .uri("https://lala")
            .body("")
            .unwrap();
        assert!(rule.evaluate(&req));

        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::OPTIONS)
            .uri("https://lala")
            .body("")
            .unwrap();
        assert!(rule.evaluate(&req));

        // Test partial matches (no match)
        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::POST)
            .uri("https://lala")
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));

        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::GET)
            .uri("http://lala")
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));

        let req = Request::builder()
            .header("fox", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::GET)
            .uri("https://lala")
            .body("")
            .unwrap();
        assert!(!rule.evaluate(&req));
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
                        name: HeaderName::from_static("foo"),
                        regex: Regex::from_str("^bar.*$").unwrap(),
                    },
                    HeaderMatcher {
                        name: HeaderName::from_static("dead"),
                        regex: Regex::from_str("^beef.*$").unwrap(),
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
        assert!(RequestAction::from_str("limit:foo").is_err());
        assert!(RequestAction::from_str("limit:0/1s").is_err());
        assert!(RequestAction::from_str("limit:1/0s").is_err());
        assert!(RequestAction::from_str("limit:1/foo").is_err());
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
    fn test_ruleset() {
        let ruleset = json!({
            "requests": [{
                "rule": {
                    "methods": ["GET", "POST"],
                    "url": "^https.*",
                },
                "action": "limit:global:10/1h",
            }, {
                "rule": {
                    "methods": ["DELETE"],
                },
                "action": "block:403",
            }],

            "responses": [{
                "rule": {
                    "status": ["100-200", "400-499", "599"],
                },
                "action": "block:451",
            }, {
                "rule": {
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

        // Test requests

        // Should always pass
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
                .uri("https://foobar")
                .body("")
                .unwrap();
            assert_eq!(ruleset.evaluate_request(&req), Decision::Pass);
        }

        for _ in 0..1000 {
            let req = Request::builder()
                .method(Method::GET)
                .uri("https://foobar")
                .body("")
                .unwrap();
            assert!(matches!(
                ruleset.evaluate_request(&req),
                Decision::Throttle(_)
            ));
        }

        // Test responses

        // Should always pass
        for _ in 0..1000 {
            let resp = Response::builder()
                .status(StatusCode::PERMANENT_REDIRECT)
                .body("")
                .unwrap();
            assert_eq!(ruleset.evaluate_response(&resp), Decision::Pass);
        }

        // Should always block with 451
        for _ in 0..1000 {
            let resp = Response::builder().status(StatusCode::OK).body("").unwrap();
            assert_eq!(
                ruleset.evaluate_response(&resp),
                Decision::Block(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS)
            );
        }

        // Should always block with 401
        for _ in 0..1000 {
            let resp = Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("foo", "bardead")
                .body("")
                .unwrap();
            assert_eq!(
                ruleset.evaluate_response(&resp),
                Decision::Block(StatusCode::UNAUTHORIZED)
            );
        }
    }
}
