use std::str::FromStr;

use anyhow::{Context, anyhow};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use itertools::Itertools;
use regex::Regex;
use serde::Deserialize;
use serde_with::{DeserializeFromStr, DisplayFromStr, serde_as};

/// Matches HTTP status codes or ranges
#[derive(Debug, Clone, Copy, Eq, PartialEq, DeserializeFromStr)]
pub struct StatusRange {
    from: u16,
    to: Option<u16>,
}

impl StatusRange {
    pub const fn check(&self, v: StatusCode) -> bool {
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
    pub regex: Regex,
}

impl PartialEq for HeaderMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.regex.as_str() == other.regex.as_str()
    }
}
impl Eq for HeaderMatcher {}

impl HeaderMatcher {
    pub fn check(&self, name: &HeaderName, value: &HeaderValue) -> bool {
        if name != self.name {
            return false;
        }

        let Ok(value) = value.to_str() else {
            return false;
        };

        self.regex.is_match(value)
    }

    pub fn check_headermap(&self, map: &HeaderMap) -> bool {
        map.iter().any(|(name, value)| self.check(name, value))
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
    pub fn check<T>(&self, req: &Request<T>) -> bool {
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
            if !v.iter().all(|rule| rule.check_headermap(req.headers())) {
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
    pub fn check<T>(&self, req: &Response<T>) -> bool {
        // Check status codes
        if let Some(v) = &self.status {
            if !v.iter().any(|x| x.check(req.status())) {
                return false;
            }
        }

        // Check that all of header rules match
        if let Some(v) = &self.headers {
            if !v.iter().all(|rule| rule.check_headermap(req.headers())) {
                return false;
            }
        }

        // Empty rule matches anything
        true
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

        assert!(range.check(StatusCode::OK));
        assert!(range.check(StatusCode::ACCEPTED));
        assert!(range.check(StatusCode::PERMANENT_REDIRECT));
        assert!(range.check(StatusCode::NOT_FOUND));
        assert!(!range.check(StatusCode::CONTINUE));
        assert!(!range.check(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!range.check(StatusCode::SERVICE_UNAVAILABLE));

        let range = StatusRange::from_str("200").unwrap();
        assert!(range.check(StatusCode::OK));
        assert!(!range.check(StatusCode::ACCEPTED));
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
        assert!(rule.check(&req));

        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::OPTIONS)
            .uri("https://lala")
            .body("")
            .unwrap();
        assert!(rule.check(&req));

        // Test partial matches (no match)
        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::POST)
            .uri("https://lala")
            .body("")
            .unwrap();
        assert!(!rule.check(&req));

        let req = Request::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::GET)
            .uri("http://lala")
            .body("")
            .unwrap();
        assert!(!rule.check(&req));

        let req = Request::builder()
            .header("fox", "barfuss")
            .header("dead", "beefbeef")
            .method(Method::GET)
            .uri("https://lala")
            .body("")
            .unwrap();
        assert!(!rule.check(&req));
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
        assert!(rule.check(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::CONTINUE)
            .body("")
            .unwrap();
        assert!(rule.check(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::TEMPORARY_REDIRECT)
            .body("")
            .unwrap();
        assert!(rule.check(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::NOT_FOUND)
            .body("")
            .unwrap();
        assert!(rule.check(&resp));

        // Test partial matches (no match)
        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "beefbeef")
            .status(StatusCode::PERMANENT_REDIRECT)
            .body("")
            .unwrap();
        assert!(!rule.check(&resp));

        let resp = Response::builder()
            .header("foo", "barfuss")
            .header("dead", "zbeefbeef")
            .status(StatusCode::OK)
            .body("")
            .unwrap();
        assert!(!rule.check(&resp));
    }
}
