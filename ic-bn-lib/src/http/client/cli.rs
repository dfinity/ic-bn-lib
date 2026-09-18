use std::time::Duration;

use clap::Args;
use humantime::parse_duration;

use crate::http::client::{ClientOptions, HttpVersion};

/// HTTP Client CLI
#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct HttpClientCli {
    /// Timeout for HTTP connection phase
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub http_client_timeout_connect: Duration,

    /// Timeout for a single read request
    #[clap(env, long, default_value = "15s", value_parser = parse_duration)]
    pub http_client_timeout_read: Duration,

    /// Timeout for the whole HTTP call: this includes connecting, sending request,
    /// receiving response etc.
    #[clap(env, long, default_value = "60s", value_parser = parse_duration)]
    pub http_client_timeout: Duration,

    /// How long to keep idle HTTP connections open.
    /// Default is 90s.
    #[clap(env, long, value_parser = parse_duration)]
    pub http_client_pool_idle_timeout: Option<Duration>,

    /// How many idle connections maximum to keep per-host.
    /// Default is unlimited.
    #[clap(env, long)]
    pub http_client_pool_idle_max: Option<usize>,

    /// TCP Keepalive delay.
    /// It's the time between when the connection became idle and when the keepalive packet is sent.
    /// If not specified - keepalives are disabled.
    #[clap(env, long, value_parser = parse_duration)]
    pub http_client_tcp_keepalive_delay: Option<Duration>,

    /// TCP Keepalive interval.
    /// If the acknowledgement for the 1st keepalive wasn't received - retry after this time.
    /// If not specified - use system default.
    #[clap(env, long, value_parser = parse_duration)]
    pub http_client_tcp_keepalive_interval: Option<Duration>,

    /// TCP Keepalive retries.
    /// If this many keepalives in a row weren't acknowledged - close the connection.
    /// If not specified - use system default.
    #[clap(env, long)]
    pub http_client_tcp_keepalive_retries: Option<u32>,

    /// HTTP2 Keepalive interval.
    /// If not specified - the keepalives are not sent.
    #[clap(env, long, value_parser = parse_duration)]
    pub http_client_http2_keepalive: Option<Duration>,

    /// HTTP2 Keepalive timeout
    #[clap(env, long, value_parser = parse_duration)]
    pub http_client_http2_keepalive_timeout: Option<Duration>,

    /// Whether to send HTTP2 Keepalives while connection is idle (no active streams)
    #[clap(env, long)]
    pub http_client_http2_keepalive_idle: bool,

    /// Which HTTP versions to use.
    /// Can be "http1", "http2" or "all". Defaults to "all".
    #[clap(env, long, default_value = "all")]
    pub http_client_http_version: HttpVersion,

    /// If the target hostname resolves to both IPv6 and IPv4,
    /// we first try the preferred family and, if the connection isn't established
    /// in this time, we in parallel try the other family.
    /// See RFC6555.
    #[clap(env, long, value_parser = parse_duration, default_value = "500ms")]
    pub http_client_happy_eyeballs_timeout: Duration,

    /// Fixed name to use when checking TLS certificates, instead of the host name.
    #[clap(env, long)]
    pub http_client_tls_fixed_name: Option<String>,
}

impl From<&HttpClientCli> for ClientOptions {
    fn from(c: &HttpClientCli) -> Self {
        Self {
            timeout_connect: c.http_client_timeout_connect,
            timeout_read: c.http_client_timeout_read,
            timeout: c.http_client_timeout,
            pool_idle_timeout: c.http_client_pool_idle_timeout,
            pool_idle_max: c.http_client_pool_idle_max,
            tcp_keepalive_delay: c.http_client_tcp_keepalive_delay,
            tcp_keepalive_interval: c.http_client_tcp_keepalive_interval,
            tcp_keepalive_retries: c.http_client_tcp_keepalive_retries,
            http2_keepalive: c.http_client_http2_keepalive,
            http2_keepalive_timeout: c.http_client_http2_keepalive_timeout,
            http2_keepalive_idle: c.http_client_http2_keepalive_idle,
            happy_eyeballs_timeout: c.http_client_happy_eyeballs_timeout,
            http_version: c.http_client_http_version,
            user_agent: "ic-bn-lib".into(),
            tls_config: None,
            tls_fixed_name: c.http_client_tls_fixed_name.clone(),
            dns_overrides: vec![],
        }
    }
}

#[cfg(test)]
mod test {
    use clap::Parser;

    use super::*;

    /// `HttpClientCli` is an `Args` group, so it needs a `Parser` host to be parsed standalone.
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        http_client: HttpClientCli,
    }

    fn parse(args: &[&str]) -> Result<HttpClientCli, clap::Error> {
        let mut argv = vec!["test"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).map(|x| x.http_client)
    }

    #[test]
    fn test_defaults() {
        let c = parse(&[]).unwrap();

        assert_eq!(c.http_client_timeout_connect, Duration::from_secs(5));
        assert_eq!(c.http_client_timeout_read, Duration::from_secs(15));
        assert_eq!(c.http_client_timeout, Duration::from_secs(60));
        assert_eq!(
            c.http_client_happy_eyeballs_timeout,
            Duration::from_millis(500)
        );
        assert_eq!(c.http_client_http_version, HttpVersion::All);

        // Everything optional stays unset and the bool flag stays off
        assert_eq!(c.http_client_pool_idle_timeout, None);
        assert_eq!(c.http_client_pool_idle_max, None);
        assert_eq!(c.http_client_tcp_keepalive_delay, None);
        assert_eq!(c.http_client_tcp_keepalive_interval, None);
        assert_eq!(c.http_client_tcp_keepalive_retries, None);
        assert_eq!(c.http_client_http2_keepalive, None);
        assert_eq!(c.http_client_http2_keepalive_timeout, None);
        assert!(!c.http_client_http2_keepalive_idle);
        assert_eq!(c.http_client_tls_fixed_name, None);
    }

    /// Every field gets a distinct value so a mis-wired `--flag` or a swapped field
    /// in `From<&HttpClientCli>` shows up.
    fn full_args() -> Vec<&'static str> {
        vec![
            "--http-client-timeout-connect=1s",
            "--http-client-timeout-read=2s",
            "--http-client-timeout=3s",
            "--http-client-pool-idle-timeout=4s",
            "--http-client-pool-idle-max=11",
            "--http-client-tcp-keepalive-delay=5s",
            "--http-client-tcp-keepalive-interval=6s",
            "--http-client-tcp-keepalive-retries=12",
            "--http-client-http2-keepalive=7s",
            "--http-client-http2-keepalive-timeout=8s",
            "--http-client-http2-keepalive-idle",
            "--http-client-http-version=http2",
            "--http-client-happy-eyeballs-timeout=9s",
            "--http-client-tls-fixed-name=foo.bar",
        ]
    }

    #[test]
    fn test_explicit_values() {
        let c = parse(&full_args()).unwrap();

        assert_eq!(c.http_client_timeout_connect, Duration::from_secs(1));
        assert_eq!(c.http_client_timeout_read, Duration::from_secs(2));
        assert_eq!(c.http_client_timeout, Duration::from_secs(3));
        assert_eq!(
            c.http_client_pool_idle_timeout,
            Some(Duration::from_secs(4))
        );
        assert_eq!(c.http_client_pool_idle_max, Some(11));
        assert_eq!(
            c.http_client_tcp_keepalive_delay,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            c.http_client_tcp_keepalive_interval,
            Some(Duration::from_secs(6))
        );
        assert_eq!(c.http_client_tcp_keepalive_retries, Some(12));
        assert_eq!(c.http_client_http2_keepalive, Some(Duration::from_secs(7)));
        assert_eq!(
            c.http_client_http2_keepalive_timeout,
            Some(Duration::from_secs(8))
        );
        assert!(c.http_client_http2_keepalive_idle);
        assert_eq!(c.http_client_http_version, HttpVersion::Http2);
        assert_eq!(c.http_client_happy_eyeballs_timeout, Duration::from_secs(9));
        assert_eq!(c.http_client_tls_fixed_name.as_deref(), Some("foo.bar"));
    }

    #[test]
    fn test_humantime_parser_accepts_compound_and_subsecond() {
        let c = parse(&[
            "--http-client-timeout=1m30s",
            "--http-client-timeout-connect=250ms",
            "--http-client-happy-eyeballs-timeout=1h",
        ])
        .unwrap();

        assert_eq!(c.http_client_timeout, Duration::from_secs(90));
        assert_eq!(c.http_client_timeout_connect, Duration::from_millis(250));
        assert_eq!(
            c.http_client_happy_eyeballs_timeout,
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_invalid_values_are_rejected() {
        // Bare numbers have no unit, so humantime rejects them
        assert!(parse(&["--http-client-timeout=60"]).is_err());
        assert!(parse(&["--http-client-timeout=notaduration"]).is_err());
        assert!(parse(&["--http-client-timeout="]).is_err());
        // Negative durations aren't representable
        assert!(parse(&["--http-client-timeout=-5s"]).is_err());
        // Optional duration fields use the same parser
        assert!(parse(&["--http-client-pool-idle-timeout=bogus"]).is_err());
        assert!(parse(&["--http-client-happy-eyeballs-timeout=1 potato"]).is_err());

        // HttpVersion only accepts the snake_case strum spellings
        assert!(parse(&["--http-client-http-version=http3"]).is_err());
        assert!(parse(&["--http-client-http-version=Http1"]).is_err());

        // Numeric fields
        assert!(parse(&["--http-client-pool-idle-max=-1"]).is_err());
        assert!(parse(&["--http-client-pool-idle-max=lots"]).is_err());
        assert!(parse(&["--http-client-tcp-keepalive-retries=1.5"]).is_err());

        // Unknown flags
        assert!(parse(&["--http-client-nope=1"]).is_err());
        // The bool flag takes no value
        assert!(parse(&["--http-client-http2-keepalive-idle=yes"]).is_err());
    }

    #[test]
    fn test_client_options_conversion() {
        let c = parse(&full_args()).unwrap();
        let o = ClientOptions::from(&c);

        assert_eq!(o.timeout_connect, Duration::from_secs(1));
        assert_eq!(o.timeout_read, Duration::from_secs(2));
        assert_eq!(o.timeout, Duration::from_secs(3));
        assert_eq!(o.pool_idle_timeout, Some(Duration::from_secs(4)));
        assert_eq!(o.pool_idle_max, Some(11));
        assert_eq!(o.tcp_keepalive_delay, Some(Duration::from_secs(5)));
        assert_eq!(o.tcp_keepalive_interval, Some(Duration::from_secs(6)));
        assert_eq!(o.tcp_keepalive_retries, Some(12));
        assert_eq!(o.http2_keepalive, Some(Duration::from_secs(7)));
        assert_eq!(o.http2_keepalive_timeout, Some(Duration::from_secs(8)));
        assert!(o.http2_keepalive_idle);
        assert_eq!(o.happy_eyeballs_timeout, Duration::from_secs(9));
        assert_eq!(o.http_version, HttpVersion::Http2);
        assert_eq!(o.tls_fixed_name.as_deref(), Some("foo.bar"));

        // Not derived from the CLI
        assert_eq!(o.user_agent, "ic-bn-lib");
        assert!(o.tls_config.is_none());
        assert!(o.dns_overrides.is_empty());
    }

    /// The conversion must not silently fall back to `ClientOptions::default()`
    /// for the fields the CLI leaves unset.
    #[test]
    fn test_client_options_conversion_defaults() {
        let o = ClientOptions::from(&parse(&[]).unwrap());
        let d = ClientOptions::default();

        // CLI defaults deliberately differ from `ClientOptions::default()`
        assert_eq!(o.timeout_connect, Duration::from_secs(5));
        assert_ne!(o.timeout_connect, d.timeout_connect);
        assert_eq!(o.timeout_read, Duration::from_secs(15));
        assert_ne!(o.timeout_read, d.timeout_read);
        assert_eq!(o.timeout, Duration::from_secs(60));
        assert_ne!(o.timeout, d.timeout);
        assert_ne!(o.user_agent, d.user_agent);

        assert_eq!(o.pool_idle_timeout, None);
        assert_eq!(o.pool_idle_max, None);
        assert!(!o.http2_keepalive_idle);
        assert_eq!(o.http_version, HttpVersion::All);
        assert_eq!(o.tls_fixed_name, None);
    }
}
