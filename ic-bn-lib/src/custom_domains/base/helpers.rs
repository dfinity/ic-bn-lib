use std::{
    fmt::{Debug, Display},
    future::Future,
    time::{Duration, Instant},
};

use anyhow::Result;
use tokio::time::sleep;
use tracing::{debug, error, info, trace, warn, Level};

/// Error returned when a retry operation times out.
#[derive(Debug)]
pub struct RetryTimeoutError<E> {
    /// Number of attempts made before timing out
    pub attempts: usize,
    /// The last error encountered
    pub last_error: E,
}

/// Retries an async operation with exponential backoff until timeout.
///
/// # Arguments
/// * `operation` - Optional name for logging purposes
/// * `log_level` - Log level for retry messages (defaults to INFO)
/// * `timeout` - Maximum duration to keep retrying
/// * `backoff` - Duration to wait between attempts
/// * `f` - Async function to retry
///
/// # Returns
/// * `Ok((attempts, result))` on success
/// * `Err(RetryTimeoutError)` on timeout
pub async fn retry_async<F, Fut, R, E>(
    operation: Option<&str>,
    log_level: Option<Level>,
    timeout: Duration,
    backoff: Duration,
    f: F,
) -> Result<(usize, R), RetryTimeoutError<E>>
where
    Fut: Future<Output = Result<R, E>>,
    F: Fn() -> Fut,
    E: std::fmt::Debug,
{
    let log_level = log_level.unwrap_or(Level::INFO);
    let start_time = Instant::now();
    let mut attempt = 1;

    if let Some(op) = operation {
        trace_msg(
            log_level,
            format!("Retrying operation \"{op}\" for up to {timeout:?} with {backoff:?} backoff"),
        );
    }

    loop {
        match f().await {
            Ok(v) => {
                if let Some(op_name) = operation {
                    trace_msg(
                        log_level,
                        format!(
                            "Operation \"{op_name}\" succeeded after {:?} on attempt {attempt}",
                            start_time.elapsed()
                        ),
                    );
                }
                return Ok((attempt, v));
            }
            Err(err) => {
                if start_time.elapsed() > timeout {
                    return Err(RetryTimeoutError {
                        attempts: attempt,
                        last_error: err,
                    });
                }

                if let Some(op_name) = operation {
                    trace_msg(
                        log_level,
                        format!(
                            "Operation \"{op_name}\" failed on attempt {attempt}. Error: {err:?}",
                        ),
                    );
                }

                sleep(backoff).await;
                attempt += 1;
            }
        }
    }
}

/// Logs a message at the specified tracing level.
pub fn trace_msg<M: Display>(level: Level, message: M) {
    match level {
        Level::ERROR => error!(message = %message),
        Level::WARN => warn!(message = %message),
        Level::INFO => info!(message = %message),
        Level::DEBUG => debug!(message = %message),
        Level::TRACE => trace!(message = %message),
    }
}

/// Formats an error with its full chain of causes.
///
/// Useful for detailed error reporting that includes nested error context.
pub fn format_error_chain(err: &anyhow::Error) -> String {
    let mut s = format!("{err}");
    for cause in err.chain().skip(1) {
        s.push_str(&format!("\nCaused by: {cause}"));
    }
    s
}
