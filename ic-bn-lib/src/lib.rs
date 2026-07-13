// Needed for certain macros
#![recursion_limit = "256"]
#![warn(clippy::nursery)]
#![warn(tail_expr_drop_order)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::collapsible_if)]

#[cfg(feature = "custom-domains")]
pub mod custom_domains;
pub mod dns;
pub mod health;
pub mod http;
#[cfg(feature = "lb")]
pub mod lb;
pub mod network;
#[cfg(feature = "pubsub")]
pub mod pubsub;
#[cfg(all(target_os = "linux", feature = "sev-snp"))]
pub mod sev_snp;
#[cfg(feature = "smtp")]
pub mod smtp;
pub mod tasks;
pub mod tests;
pub mod tls;
#[cfg(feature = "vector")]
pub mod vector;
use std::{fs::File, net::IpAddr, path::Path};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use candid::Principal;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, IntoStaticStr};
use tokio::io::AsyncWriteExt;

pub use hickory_proto;
pub use hickory_resolver;
pub use hyper;
pub use hyper_util;
pub use ic_agent;
#[cfg(feature = "smtp")]
pub use mail_auth;
pub use prometheus;
#[cfg(feature = "acme")]
pub use rcgen;
pub use reqwest;
pub use rustls;
#[cfg(feature = "acme-alpn")]
pub use rustls_acme;
pub use uuid;

/// Converts a string representation to an `EmailAddress`. Panics when an error occurs.
#[macro_export]
macro_rules! email {
    ($email:expr) => {{ $crate::smtp::address::EmailAddress::from_text($email).unwrap() }};
}

/// Converts a string representation to a `candid::Principal`. Panics when an error occurs.
#[macro_export]
macro_rules! principal {
    ($id:expr) => {{ candid::Principal::from_text($id).unwrap() }};
}

/// tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe
pub const MAINNET_ROOT_SUBNET_ID: Principal = Principal::from_slice(&[
    207, 242, 128, 227, 45, 127, 92, 205, 34, 70, 136, 47, 148, 175, 178, 15, 84, 202, 97, 162, 23,
    101, 231, 18, 212, 61, 39, 137, 2,
]);

/// Generic error
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

/// Error to be used with `retry_async` macro
/// which indicates whether it should be retried or not.
#[derive(thiserror::Error, Debug)]
pub enum RetryError {
    #[error("Permanent error: {0:?}")]
    Permanent(anyhow::Error),
    #[error("Transient error: {0:?}")]
    Transient(anyhow::Error),
}

/// Type of IC API request
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    IntoStaticStr,
    EnumString,
    Serialize,
    Deserialize,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    #[default]
    Unknown,
    Status,
    QueryV2,
    QueryV3,
    QuerySubnetV3,
    CallV2,
    CallV3,
    CallV4,
    CallSubnetV4,
    ReadStateV2,
    ReadStateV3,
    ReadStateSubnetV2,
    ReadStateSubnetV3,
}

impl RequestType {
    pub const fn is_query(&self) -> bool {
        matches!(self, Self::QueryV2 | Self::QueryV3 | Self::QuerySubnetV3)
    }

    pub const fn is_call(&self) -> bool {
        matches!(
            self,
            Self::CallV2 | Self::CallV3 | Self::CallV4 | Self::CallSubnetV4
        )
    }

    pub const fn is_read_state(&self) -> bool {
        matches!(
            self,
            Self::ReadStateV2
                | Self::ReadStateV3
                | Self::ReadStateSubnetV2
                | Self::ReadStateSubnetV3
        )
    }
}

/// Parses size string as a binary (1k = 1024 etc) in u64
pub fn parse_size(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().with_binary().parse_size(s)
}

/// Parses size string as a binary (1k = 1024 etc) in usize
pub fn parse_size_usize(s: &str) -> Result<usize, parse_size::Error> {
    parse_size(s).map(|x| x as usize)
}

/// Parses size string as a decimal (1k = 1000 etc) in u64
pub fn parse_size_decimal(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().parse_size(s)
}

/// Parses size string as a decimal (1k = 1000 etc) in usize
pub fn parse_size_decimal_usize(s: &str) -> Result<usize, parse_size::Error> {
    parse_size_decimal(s).map(|x| x as usize)
}

/// Downloads the given url to given path.
/// Destination folder must exist.
pub fn download_url_to(url: &str, path: &Path) -> Result<u64, Error> {
    let mut r = reqwest::blocking::get(url).context("unable to perform HTTP request")?;
    if !r.status().is_success() {
        return Err(anyhow!("incorrect HTTP code: {}", r.status()).into());
    }

    let mut file = File::create(path).context("could not create file")?;
    Ok(r.copy_to(&mut file)
        .context("unable to write body to file")?)
}

/// Downloads the given url and returns it as Bytes
pub fn download_url(url: &str) -> Result<Bytes, Error> {
    let r = reqwest::blocking::get(url).context("unable to perform HTTP request")?;
    if !r.status().is_success() {
        return Err(anyhow!("incorrect HTTP code: {}", r.status()).into());
    }

    Ok(r.bytes().context("unable to fetch file")?)
}

/// Downloads the given url to given path.
/// Destination folder must exist.
pub async fn download_url_to_async(url: &str, path: &Path) -> Result<(), Error> {
    let r = reqwest::get(url)
        .await
        .context("unable to perform HTTP request")?;
    if !r.status().is_success() {
        return Err(anyhow!("incorrect HTTP code: {}", r.status()).into());
    }

    let mut file = tokio::fs::File::create(path)
        .await
        .context("could not create file")?;

    let mut stream = r.bytes_stream();
    while let Some(v) = stream.next().await {
        file.write(&v.context("unable to read chunk")?)
            .await
            .context("unable to write chunk")?;
    }

    Ok(())
}

/// Downloads the given url and returns it as Bytes
pub async fn download_url_async(url: &str) -> Result<Bytes, Error> {
    let r = reqwest::get(url)
        .await
        .context("unable to perform HTTP request")?;

    if !r.status().is_success() {
        return Err(anyhow!("incorrect HTTP code: {}", r.status()).into());
    }

    Ok(r.bytes().await.context("unable to fetch file")?)
}

/// Retrying async closures/functions holding mutable references is a pain in Rust.
/// So, for now, we'll have to use a macro to work that around.
#[macro_export]
macro_rules! retry_async {
    ($f:expr, $timeout:expr, $delay:expr) => {{
        use rand::{Rng, SeedableRng};
        // SmallRng is Send which we require
        let mut rng = rand::rngs::SmallRng::from_entropy();

        let start = std::time::Instant::now();
        let mut delay = $delay;

        let result = loop {
            // Bound this attempt by the *remaining* budget, not the original
            // `$timeout` - otherwise a dependency that consistently takes
            // just under `$timeout` before failing can make the loop's total
            // wall-clock time run to several multiples of `$timeout`.
            let attempt_timeout = $timeout.saturating_sub(start.elapsed());
            if attempt_timeout == std::time::Duration::ZERO {
                break Err(anyhow::anyhow!("Timed out"));
            }

            // Run the function wrapping it into Tokio timeout future so
            // its execution time doesn't exceed our configured limit
            let Ok(res) = tokio::time::timeout(attempt_timeout, $f).await else {
                break Err(anyhow::anyhow!("Timed out"));
            };

            let err = match res {
                Ok(v) => break Ok(v),
                Err($crate::RetryError::Permanent(e)) => break Err(e),
                Err($crate::RetryError::Transient(e)) => e,
            };

            let left = $timeout.saturating_sub(start.elapsed());
            if left == std::time::Duration::ZERO {
                break Err(err);
            }

            delay = left.min(delay * 2);
            // Generate a random jitter in 0.0..0.1 range
            let jitter: f64 = (rng.r#gen::<f64>() / 10.0);
            let d64 = delay.as_secs_f64();
            delay = Duration::from_secs_f64(d64.mul_add(0.95, d64 * jitter));
            tokio::time::sleep(delay).await;
        };

        result
    }};

    ($f:expr, $timeout:expr) => {
        retry_async!($f, $timeout, Duration::from_millis(500))
    };

    ($f:expr) => {
        retry_async!($f, Duration::from_secs(60), Duration::from_millis(500))
    };
}

/// Returns family of an IP address
pub trait IpFamily {
    fn family(&self) -> &'static str;
}

impl IpFamily for IpAddr {
    fn family(&self) -> &'static str {
        if self.is_ipv4() { "v4" } else { "v6" }
    }
}

/// Converts bool to yes/no static str
pub trait BoolYesNo {
    fn yesno(&self) -> &'static str;
}

impl BoolYesNo for bool {
    fn yesno(&self) -> &'static str {
        if *self { "yes" } else { "no" }
    }
}

pub trait SerializeOption<T> {
    /// Serializes `Option<T>` as either inner value or provided default
    fn serialize_or<'t, O>(&'t self, otherwise: O) -> SerializeOr<'t, T, O>;
}

pub struct SerializeOr<'t, T, O> {
    option: &'t Option<T>,
    otherwise: O,
}

impl<'t, T: Serialize, O: Serialize> Serialize for SerializeOr<'t, T, O> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.option {
            Some(v) => v.serialize(serializer),
            None => self.otherwise.serialize(serializer),
        }
    }
}

impl<T> SerializeOption<T> for Option<T> {
    fn serialize_or<'t, O>(&'t self, otherwise: O) -> SerializeOr<'t, T, O> {
        SerializeOr {
            option: self,
            otherwise,
        }
    }
}

#[macro_export]
macro_rules! dyn_event {
    ($lvl:ident, $($arg:tt)+) => {
        match $lvl {
            ::tracing::Level::TRACE => ::tracing::trace!($($arg)+),
            ::tracing::Level::DEBUG => ::tracing::debug!($($arg)+),
            ::tracing::Level::INFO => ::tracing::info!($($arg)+),
            ::tracing::Level::WARN => ::tracing::warn!($($arg)+),
            ::tracing::Level::ERROR => ::tracing::error!($($arg)+),
        }
    };
}

pub trait TruncatesString {
    /// Truncates the given string to around n *bytes*,
    /// on the closest UTF-8 code point boundary.
    fn truncate_bytes(&self, n: usize) -> &str;
}

impl TruncatesString for &str {
    fn truncate_bytes(&self, n: usize) -> &str {
        truncate(self, n)
    }
}

/// Truncates the given string to around n *bytes*,
/// on the closest UTF-8 code point boundary.
pub fn truncate(s: &str, n: usize) -> &str {
    let n = s.len().min(n);
    let m = (0..=n)
        .rfind(|m| s.is_char_boundary(*m))
        .unwrap_or_default();
    &s[..m]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("foobarbaz", 4), "foob");
        assert_eq!(truncate("tättähäärä härkä", 12), "tättähää");
        assert_eq!(truncate("", 99), "");
        assert_eq!(truncate("🏁", 2), "");
        assert_eq!(truncate("foobarbaz", 99), "foobarbaz");

        assert_eq!("tättähäärä härkä".truncate_bytes(12), "tättähää");
    }

    #[tokio::test]
    async fn test_retry_async_bounds_total_time_to_timeout() {
        use std::time::Duration;

        let timeout = Duration::from_millis(300);
        let base_delay = Duration::from_millis(20);
        let attempt_duration = Duration::from_millis(200);

        let start = std::time::Instant::now();
        let result: Result<(), anyhow::Error> = retry_async! {
            async {
                tokio::time::sleep(attempt_duration).await;
                Err::<(), _>(RetryError::Transient(anyhow::anyhow!("always fails")))
            },
            timeout,
            base_delay
        };
        let elapsed = start.elapsed();

        assert!(result.is_err());
        // Each attempt (200ms) comfortably fits within the overall timeout
        // (300ms) on its own, so a per-attempt timeout that isn't shrunk to
        // the remaining budget lets a second full attempt run past the
        // deadline (previously observed ~440ms total here instead of
        // staying close to the configured 300ms).
        assert!(
            elapsed < timeout + Duration::from_millis(100),
            "retry_async! ran for {elapsed:?}, expected to stay close to the {timeout:?} budget"
        );
    }
}
