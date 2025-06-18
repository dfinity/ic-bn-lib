// Needed for certain macros
#![recursion_limit = "256"]
#![warn(clippy::nursery)]
#![warn(tail_expr_drop_order)]

pub mod http;
pub mod pubsub;
pub mod tasks;
pub mod tests;
pub mod tls;
pub mod types;
#[cfg(feature = "vector")]
pub mod vector;

use std::{fs::File, path::Path};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use futures::StreamExt;
pub use prometheus;
use tokio::io::AsyncWriteExt;

/// Generic error
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
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
    parse_size(s).map(|x| x as usize)
}

#[macro_export]
macro_rules! principal {
    ($id:expr) => {{ candid::Principal::from_text($id).unwrap() }};
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
