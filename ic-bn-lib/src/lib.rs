// Needed for certain macros
#![recursion_limit = "256"]
#![warn(clippy::nursery)]
#![warn(tail_expr_drop_order)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::field_reassign_with_default)]

#[cfg(feature = "custom-domains")]
pub mod custom_domains;
pub mod http;
pub mod pubsub;
pub mod tasks;
pub mod tests;
pub mod tls;
pub mod utils;
#[cfg(feature = "vector")]
pub mod vector;

use std::{fs::File, path::Path};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use futures::StreamExt;
use ic_bn_lib_common::Error;
use tokio::io::AsyncWriteExt;

pub use hyper;
pub use hyper_util;
pub use ic_agent;
pub use ic_bn_lib_common;
pub use prometheus;
pub use reqwest;
pub use rustls;
pub use uuid;

/// Error to be used with `retry_async` macro
/// which indicates whether it should be retried or not.
#[derive(thiserror::Error, Debug)]
pub enum RetryError {
    #[error("Permanent error: {0:?}")]
    Permanent(anyhow::Error),
    #[error("Transient error: {0:?}")]
    Transient(anyhow::Error),
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
            // Run the function wrapping it into Tokio timeout future so
            // its execution time doesn't exceed our configured limit
            let Ok(res) = tokio::time::timeout($timeout, $f).await else {
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
