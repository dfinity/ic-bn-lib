use std::time::Duration;

use humantime::parse_duration;
use url::Url;

use crate::parse_size_decimal_usize;

/// Vector CLI
#[derive(clap::Args, Clone)]
pub struct VectorCli {
    /// Setting this enables logging of HTTP requests to Vector using native protocol
    #[clap(env, long)]
    pub log_vector_url: Option<Url>,

    /// Vector username
    #[clap(env, long)]
    pub log_vector_user: Option<String>,

    /// Vector password
    #[clap(env, long)]
    pub log_vector_pass: Option<String>,

    /// Vector batch size in number of events.
    /// When it's exceeded then the batch is closed & queued for sending.
    #[clap(env, long, default_value = "100k", value_parser = parse_size_decimal_usize)]
    pub log_vector_batch: usize,

    /// Number of batches to store in the queue for the Flushers to consume.
    #[clap(env, long, default_value = "64")]
    pub log_vector_batch_queue: usize,

    /// Vector batch flush interval
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub log_vector_interval: Duration,

    /// Vector buffer size (in number of events) to account for ingest problems.
    /// If the buffer is full then new events will be dropped.
    #[clap(env, long, default_value = "500k", value_parser = parse_size_decimal_usize)]
    pub log_vector_buffer: usize,

    /// Number of batch flusher tasks to spawn.
    /// If there's a big event volume - increasing this number might help.
    /// Each task is flushing a single batch which contains time-ordered events.
    #[clap(env, long, default_value = "32")]
    pub log_vector_flushers: usize,

    /// Vector HTTP request timeout for a batch flush.
    /// With each retry it will be linearly increased until it reaches 10x.
    /// E.g. for 30s the timeouts will be 30s/1m/1m30s/.../5m
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub log_vector_timeout: Duration,

    /// Vector HTTP request retry interval
    /// With each retry it will be linearly increased until it reaches 5x.
    /// E.g. for 2s the retry intervals will be 2s/4s/6s/8s/10s/10s/10s...
    #[clap(env, long, default_value = "2s", value_parser = parse_duration)]
    pub log_vector_retry_interval: Duration,

    /// Retry count when flushing a batch.
    /// It is taken into account only when shutting down.
    #[clap(env, long, default_value = "5")]
    pub log_vector_retry_count: usize,

    /// ZSTD compression level to use when sending data
    #[clap(env, long, default_value = "3")]
    pub log_vector_zstd_level: usize,
}

#[cfg(test)]
mod test {
    use clap::{CommandFactory, Parser};

    use super::*;
    use crate::vector::VectorOptions;

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        vector: VectorCli,
    }

    /// Parses the given arguments, prepending a dummy argv[0].
    fn parse(args: &[&str]) -> VectorCli {
        let mut argv = vec![""];
        argv.extend_from_slice(args);
        Cli::parse_from(argv).vector
    }

    fn try_parse(args: &[&str]) -> Result<VectorCli, clap::Error> {
        let mut argv = vec![""];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).map(|x| x.vector)
    }

    #[test]
    fn test_cli_definition_is_sane() {
        // Catches duplicate/conflicting long names, bad default values etc.
        Cli::command().debug_assert();
    }

    #[test]
    fn test_defaults() {
        let c = parse(&[]);

        assert_eq!(c.log_vector_url, None);
        assert_eq!(c.log_vector_user, None);
        assert_eq!(c.log_vector_pass, None);
        // Sizes are decimal: 100k is 100000, not 102400.
        assert_eq!(c.log_vector_batch, 100_000);
        assert_eq!(c.log_vector_batch_queue, 64);
        assert_eq!(c.log_vector_interval, Duration::from_secs(5));
        assert_eq!(c.log_vector_buffer, 500_000);
        assert_eq!(c.log_vector_flushers, 32);
        assert_eq!(c.log_vector_timeout, Duration::from_secs(30));
        assert_eq!(c.log_vector_retry_interval, Duration::from_secs(2));
        assert_eq!(c.log_vector_retry_count, 5);
        assert_eq!(c.log_vector_zstd_level, 3);
    }

    #[test]
    fn test_all_args_explicit() {
        let c = parse(&[
            "--log-vector-url",
            "https://127.0.0.1:8443/vector",
            "--log-vector-user",
            "user1",
            "--log-vector-pass",
            "pass1",
            "--log-vector-batch",
            "1k",
            "--log-vector-batch-queue",
            "7",
            "--log-vector-interval",
            "1m 30s",
            "--log-vector-buffer",
            "2M",
            "--log-vector-flushers",
            "3",
            "--log-vector-timeout",
            "90s",
            "--log-vector-retry-interval",
            "250ms",
            "--log-vector-retry-count",
            "0",
            "--log-vector-zstd-level",
            "19",
        ]);

        assert_eq!(
            c.log_vector_url,
            Some(Url::parse("https://127.0.0.1:8443/vector").unwrap())
        );
        assert_eq!(c.log_vector_user.as_deref(), Some("user1"));
        assert_eq!(c.log_vector_pass.as_deref(), Some("pass1"));
        assert_eq!(c.log_vector_batch, 1000);
        assert_eq!(c.log_vector_batch_queue, 7);
        assert_eq!(c.log_vector_interval, Duration::from_secs(90));
        assert_eq!(c.log_vector_buffer, 2_000_000);
        assert_eq!(c.log_vector_flushers, 3);
        assert_eq!(c.log_vector_timeout, Duration::from_secs(90));
        assert_eq!(c.log_vector_retry_interval, Duration::from_millis(250));
        assert_eq!(c.log_vector_retry_count, 0);
        assert_eq!(c.log_vector_zstd_level, 19);
    }

    #[test]
    fn test_size_parser() {
        // Decimal prefixes
        assert_eq!(parse(&["--log-vector-batch", "0"]).log_vector_batch, 0);
        assert_eq!(parse(&["--log-vector-batch", "1"]).log_vector_batch, 1);
        assert_eq!(parse(&["--log-vector-batch", "1B"]).log_vector_batch, 1);
        assert_eq!(parse(&["--log-vector-batch", "1k"]).log_vector_batch, 1000);
        assert_eq!(parse(&["--log-vector-batch", "1K"]).log_vector_batch, 1000);
        assert_eq!(
            parse(&["--log-vector-batch", "1.5M"]).log_vector_batch,
            1_500_000
        );
        assert_eq!(
            parse(&["--log-vector-buffer", "3G"]).log_vector_buffer,
            3_000_000_000
        );
        // An explicit binary prefix still means 1024 even in decimal mode
        assert_eq!(parse(&["--log-vector-batch", "1Ki"]).log_vector_batch, 1024);
        assert_eq!(
            parse(&["--log-vector-batch", "1MiB"]).log_vector_batch,
            1024 * 1024
        );

        // Garbage is rejected
        for v in ["", " ", "abc", "1z", "-1", "1,000", "0x10"] {
            assert!(
                try_parse(&["--log-vector-batch", v]).is_err(),
                "size {v:?} should not parse"
            );
        }
    }

    #[test]
    fn test_duration_parser() {
        assert_eq!(
            parse(&["--log-vector-interval", "0"]).log_vector_interval,
            Duration::ZERO
        );
        assert_eq!(
            parse(&["--log-vector-interval", "1ms"]).log_vector_interval,
            Duration::from_millis(1)
        );
        assert_eq!(
            parse(&["--log-vector-timeout", "1h 30m"]).log_vector_timeout,
            Duration::from_secs(5400)
        );
        assert_eq!(
            parse(&["--log-vector-retry-interval", "2m"]).log_vector_retry_interval,
            Duration::from_secs(120)
        );

        // A bare number has no unit, and units must be known
        for v in ["", "5", "1gigasecond", "foo", "-1s"] {
            assert!(
                try_parse(&["--log-vector-interval", v]).is_err(),
                "duration {v:?} should not parse"
            );
        }
    }

    #[test]
    fn test_invalid_args() {
        // Not an absolute URL
        assert!(try_parse(&["--log-vector-url", "foobar"]).is_err());
        assert!(try_parse(&["--log-vector-url", ""]).is_err());
        // Relative URLs have no base
        assert!(try_parse(&["--log-vector-url", "/foo"]).is_err());
        // Not a usize
        assert!(try_parse(&["--log-vector-zstd-level=-1"]).is_err());
        assert!(try_parse(&["--log-vector-retry-count", "foo"]).is_err());
        // Options require values
        assert!(try_parse(&["--log-vector-batch"]).is_err());
        // Unknown option
        assert!(try_parse(&["--log-vector-nonexistent", "1"]).is_err());
    }

    #[test]
    fn test_vector_options_from_cli() {
        // URL is mandatory
        assert!(VectorOptions::try_from(&parse(&[])).is_err());

        // Distinct values everywhere so that a mixed-up field mapping is caught
        let cli = parse(&[
            "--log-vector-url",
            "https://127.0.0.1:1234/foo",
            "--log-vector-user",
            "u",
            "--log-vector-pass",
            "p",
            "--log-vector-batch",
            "11",
            "--log-vector-batch-queue",
            "12",
            "--log-vector-interval",
            "13s",
            "--log-vector-buffer",
            "14",
            "--log-vector-flushers",
            "15",
            "--log-vector-timeout",
            "16s",
            "--log-vector-retry-interval",
            "17s",
            "--log-vector-retry-count",
            "18",
            "--log-vector-zstd-level",
            "19",
        ]);

        let opts = VectorOptions::try_from(&cli).unwrap();
        assert_eq!(opts.url, Url::parse("https://127.0.0.1:1234/foo").unwrap());
        assert_eq!(opts.user.as_deref(), Some("u"));
        assert_eq!(opts.pass.as_deref(), Some("p"));
        assert_eq!(opts.batch_size, 11);
        assert_eq!(opts.batch_queue, 12);
        assert_eq!(opts.batch_flush_interval, Duration::from_secs(13));
        assert_eq!(opts.buffer, 14);
        assert_eq!(opts.flushers, 15);
        assert_eq!(opts.flush_timeout, Duration::from_secs(16));
        assert_eq!(opts.retry_interval, Duration::from_secs(17));
        assert_eq!(opts.retry_count, 18);
        assert_eq!(opts.zstd_level, 19);
    }
}
