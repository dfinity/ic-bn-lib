use std::str::FromStr;

use anyhow::{Context, anyhow};
use http::{HeaderName, HeaderValue, Method, Request, StatusCode};
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

/// Matches Header names & values
#[serde_as]
#[derive(Deserialize)]
pub struct HeaderRule {
    #[serde_as(as = "DisplayFromStr")]
    pub name: HeaderName,
    #[serde_as(as = "DisplayFromStr")]
    pub regex: Regex,
}

impl HeaderRule {
    pub fn check(&self, name: &HeaderName, value: &HeaderValue) -> bool {
        if name != self.name {
            return false;
        }

        let Ok(value) = value.to_str() else {
            return false;
        };

        self.regex.is_match(value)
    }
}

/// Rule to match against HTTP requests
#[serde_as]
#[derive(Deserialize)]
pub struct RequestRule {
    #[serde_as(as = "Option<Vec<DisplayFromStr>>")]
    pub methods: Option<Vec<Method>>,
    pub headers: Option<Vec<HeaderRule>>,
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub url: Option<Regex>,
}

impl RequestRule {
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
            if !v.iter().all(|rule| {
                req.headers()
                    .iter()
                    .any(|(name, value)| rule.check(name, value))
            }) {
                return false;
            }
        }

        true
    }
}

/// Rule to match against HTTP responses
#[serde_as]
#[derive(Deserialize)]
pub struct ResponseRule {
    pub headers: Option<Vec<HeaderRule>>,
    pub status: Option<Vec<StatusRange>>,
}

#[cfg(test)]
mod test {
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
}
