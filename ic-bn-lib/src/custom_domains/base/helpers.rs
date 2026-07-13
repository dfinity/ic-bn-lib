use std::{
    fmt::{Debug, Display},
    future::Future,
    time::{Duration, Instant},
};

use anyhow::Result;
use tokio::time::sleep;
use tracing::{Level, debug, error, info, trace, warn};

/// Error returned when a retry operation times out.
#[derive(Debug)]
pub struct RetryTimeoutError<E> {
    /// Number of attempts made before timing out
    pub attempts: usize,
    /// The last error encountered
    pub last_error: E,
}

/// Retries an async operation with an interval until timeout.
///
/// # Arguments
/// * `operation` - Optional name for logging purposes
/// * `log_level` - Log level for retry messages (defaults to INFO)
/// * `timeout` - Maximum duration to keep retrying
/// * `interval` - Duration to wait between attempts
/// * `f` - Async function to retry
///
/// # Returns
/// * `Ok((attempts, result))` on success
/// * `Err(RetryTimeoutError)` on timeout
pub async fn retry_async<F, Fut, R, E>(
    operation: Option<&str>,
    log_level: Option<Level>,
    timeout: Duration,
    interval: Duration,
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
            format!("Retrying operation \"{op}\" for up to {timeout:?} with {interval:?} interval"),
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

                sleep(interval).await;
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

#[cfg(test)]
mod test {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use anyhow::anyhow;

    use super::*;

    #[test]
    fn test_format_error_chain_single_error() {
        let err = anyhow!("root cause");
        assert_eq!(format_error_chain(&err), "root cause");
    }

    #[test]
    fn test_format_error_chain_with_context() {
        let err = anyhow!("root cause").context("middle").context("top");
        assert_eq!(
            format_error_chain(&err),
            "top\nCaused by: middle\nCaused by: root cause"
        );
    }

    #[tokio::test]
    async fn test_retry_async_succeeds_immediately() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();

        let result = retry_async(
            None,
            None,
            Duration::from_secs(1),
            Duration::from_millis(10),
            move || {
                let a = a.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, anyhow::Error>(42)
                }
            },
        )
        .await;

        let (attempt_no, value) = result.unwrap();
        assert_eq!(attempt_no, 1);
        assert_eq!(value, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_async_succeeds_after_failures() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();

        let result = retry_async(
            Some("flaky_op"),
            None,
            Duration::from_secs(5),
            Duration::from_millis(5),
            move || {
                let a = a.clone();
                async move {
                    let n = a.fetch_add(1, Ordering::SeqCst) + 1;
                    if n < 3 {
                        Err(anyhow!("not yet"))
                    } else {
                        Ok(n)
                    }
                }
            },
        )
        .await;

        let (attempt_no, value) = result.unwrap();
        assert_eq!(attempt_no, 3);
        assert_eq!(value, 3);
    }

    #[tokio::test]
    async fn test_retry_async_times_out_on_persistent_failure() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();

        let result = retry_async(
            None,
            None,
            Duration::from_millis(60),
            Duration::from_millis(10),
            move || {
                let a = a.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>(anyhow!("always fails"))
                }
            },
        )
        .await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.attempts >= 1);
        assert!(attempts.load(Ordering::SeqCst) >= 1);
    }
}
