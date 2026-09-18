use std::time::Duration;

use humantime::parse_duration;

use crate::{
    http::server::{ProxyProtocolMode, ServerOptions},
    parse_size,
    tls::TlsOptions,
};

/// HTTP Server CLI
#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
pub struct HttpServerCli {
    /// Backlog of incoming connections to set on the listening socket
    #[clap(env, long, default_value = "2048")]
    pub http_server_backlog: u32,

    /// Maximum number of HTTP requests to serve over a single connection.
    /// After this number is reached the connection is gracefully closed.
    #[clap(env, long)]
    pub http_server_max_requests_per_conn: Option<u64>,

    /// Timeout for network read calls.
    /// If the read call takes longer than that - the connection is closed.
    /// This effectively closes idle HTTP/1.1 connections.
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub http_server_read_timeout: Duration,

    /// Timeout for network write calls.
    /// If the write call takes longer than that - the connection is closed.
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub http_server_write_timeout: Duration,

    /// Idle timeout for connections.
    /// If no requests are executed during this period - the connections is closed.
    /// Mostly needed for HTTP/2 where the read timeout sometimes cannot kick in
    /// due to PING frames and other non-request activity.
    #[clap(env, long, value_parser = parse_duration)]
    pub http_server_idle_timeout: Option<Duration>,

    /// TLS handshake timeout
    #[clap(env, long, default_value = "15s", value_parser = parse_duration)]
    pub http_server_tls_handshake_timeout: Duration,

    /// For how long to wait for the client to send headers.
    /// Applies only to HTTP1 connections.
    /// Should be set lower than the global `http_server_read_timeout`.
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub http_server_http1_header_read_timeout: Duration,

    /// For how long to wait for the client to send full request body.
    #[clap(env, long, default_value = "60s", value_parser = parse_duration)]
    pub http_server_body_read_timeout: Duration,

    /// Maximum number of HTTP2 streams that the client is allowed to create inside a single connection
    #[clap(env, long, default_value = "128")]
    pub http_server_http2_max_streams: u32,

    /// Keepalive interval for HTTP2 connections
    #[clap(env, long, value_parser = parse_duration)]
    pub http_server_http2_keepalive_interval: Option<Duration>,

    /// Keepalive timeout for HTTP2 connections
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub http_server_http2_keepalive_timeout: Duration,

    /// TCP Keepalive delay.
    /// It's the time between when the connection became idle and when the keepalive packet is sent.
    /// If not specified - keepalives are disabled.
    #[clap(env, long, value_parser = parse_duration)]
    pub http_server_tcp_keepalive_delay: Option<Duration>,

    /// TCP Keepalive interval.
    /// If the acknowledgement for the 1st keepalive wasn't received - retry after this time.
    /// If not specified - use system default.
    #[clap(env, long, value_parser = parse_duration)]
    pub http_server_tcp_keepalive_interval: Option<Duration>,

    /// TCP Keepalive retries.
    /// If this many keepalives in a row weren't acknowledged - close the connection.
    /// If not specified - use system default.
    #[clap(env, long)]
    pub http_server_tcp_keepalive_retries: Option<u32>,

    /// TCP MSS option.
    /// Limits the TCP segment size, can be used to work around PMTU issues.
    #[clap(env, long)]
    pub http_server_tcp_mss: Option<u32>,

    /// Maximum size of cache to store TLS sessions in memory
    #[clap(env, long, default_value = "256MB", value_parser = parse_size)]
    pub http_server_tls_session_cache_size: u64,

    /// Maximum time that a TLS session key can stay in cache without being requested (Time-to-Idle)
    #[clap(env, long, default_value = "18h", value_parser = parse_duration)]
    pub http_server_tls_session_cache_tti: Duration,

    /// Lifetime of a TLS1.3 ticket, due to key rotation the actual lifetime will be twice than this
    #[clap(env, long, default_value = "9h", value_parser = parse_duration)]
    pub http_server_tls_ticket_lifetime: Duration,

    /// How long to wait for the existing connections to finish before shutting down.
    /// Also applies to the recycling of connections with `http_server_max_requests_per_conn` option.
    #[clap(env, long, default_value = "60s", value_parser = parse_duration)]
    pub http_server_grace_period: Duration,

    /// Whether to expect connections with Proxy Protocol v2.
    /// If the connection contains the Proxy Protocol v2 header - then we will use the client's IP
    /// from it instead of TCP endpoint.
    /// Can be "off", "enabled" or "forced".
    /// If "enabled" - we'll support connections with or without Proxy Protocol.
    /// If "forced" then connections without a Proxy Protocol header will not be accepted.
    #[clap(env, long, default_value = "off")]
    pub http_server_proxy_protocol_mode: ProxyProtocolMode,
}

impl From<&HttpServerCli> for ServerOptions {
    fn from(c: &HttpServerCli) -> Self {
        Self {
            backlog: c.http_server_backlog,
            read_timeout: Some(c.http_server_read_timeout),
            write_timeout: Some(c.http_server_write_timeout),
            idle_timeout: c.http_server_idle_timeout,
            tls_handshake_timeout: c.http_server_tls_handshake_timeout,
            tcp_keepalive_delay: c.http_server_tcp_keepalive_delay,
            tcp_keepalive_interval: c.http_server_tcp_keepalive_interval,
            tcp_keepalive_retries: c.http_server_tcp_keepalive_retries,
            tcp_mss: c.http_server_tcp_mss,
            http1_header_read_timeout: c.http_server_http1_header_read_timeout,
            http2_keepalive_interval: c.http_server_http2_keepalive_interval,
            http2_keepalive_timeout: c.http_server_http2_keepalive_timeout,
            http2_max_streams: c.http_server_http2_max_streams,
            grace_period: c.http_server_grace_period,
            max_requests_per_conn: c.http_server_max_requests_per_conn,
            proxy_protocol_mode: c.http_server_proxy_protocol_mode,
        }
    }
}

impl From<&HttpServerCli> for TlsOptions {
    fn from(c: &HttpServerCli) -> Self {
        Self {
            additional_alpn: vec![],
            sessions_count: c.http_server_tls_session_cache_size,
            sessions_tti: c.http_server_tls_session_cache_tti,
            ticket_lifetime: c.http_server_tls_ticket_lifetime,
            tls_versions: vec![],
        }
    }
}

#[cfg(test)]
mod test {
    use clap::Parser;

    use super::*;

    /// Wrapper needed to be able to use `try_parse_from` on `clap::Args`
    #[derive(Parser)]
    struct Cli {
        #[clap(flatten)]
        srv: HttpServerCli,
    }

    fn parse(args: &[&str]) -> HttpServerCli {
        let mut v = vec!["test"];
        v.extend_from_slice(args);
        Cli::try_parse_from(v).unwrap().srv
    }

    fn try_parse(args: &[&str]) -> Result<HttpServerCli, clap::Error> {
        let mut v = vec!["test"];
        v.extend_from_slice(args);
        Cli::try_parse_from(v).map(|x| x.srv)
    }

    const ALL_ARGS: &[&str] = &[
        "--http-server-backlog=4096",
        "--http-server-max-requests-per-conn=1000",
        "--http-server-read-timeout=1m",
        "--http-server-write-timeout=2m",
        "--http-server-idle-timeout=3m",
        "--http-server-tls-handshake-timeout=4s",
        "--http-server-http1-header-read-timeout=5s",
        "--http-server-body-read-timeout=6s",
        "--http-server-http2-max-streams=256",
        "--http-server-http2-keepalive-interval=7s",
        "--http-server-http2-keepalive-timeout=8s",
        "--http-server-tcp-keepalive-delay=9s",
        "--http-server-tcp-keepalive-interval=10s",
        "--http-server-tcp-keepalive-retries=11",
        "--http-server-tcp-mss=1400",
        "--http-server-tls-session-cache-size=1MB",
        "--http-server-tls-session-cache-tti=12h",
        "--http-server-tls-ticket-lifetime=13h",
        "--http-server-grace-period=14s",
        "--http-server-proxy-protocol-mode=forced",
    ];

    #[test]
    fn test_cli_defaults() {
        let c = parse(&[]);

        assert_eq!(c.http_server_backlog, 2048);
        assert_eq!(c.http_server_max_requests_per_conn, None);
        assert_eq!(c.http_server_read_timeout, Duration::from_secs(30));
        assert_eq!(c.http_server_write_timeout, Duration::from_secs(30));
        assert_eq!(c.http_server_idle_timeout, None);
        assert_eq!(c.http_server_tls_handshake_timeout, Duration::from_secs(15));
        assert_eq!(
            c.http_server_http1_header_read_timeout,
            Duration::from_secs(10)
        );
        assert_eq!(c.http_server_body_read_timeout, Duration::from_secs(60));
        assert_eq!(c.http_server_http2_max_streams, 128);
        assert_eq!(c.http_server_http2_keepalive_interval, None);
        assert_eq!(
            c.http_server_http2_keepalive_timeout,
            Duration::from_secs(10)
        );
        assert_eq!(c.http_server_tcp_keepalive_delay, None);
        assert_eq!(c.http_server_tcp_keepalive_interval, None);
        assert_eq!(c.http_server_tcp_keepalive_retries, None);
        assert_eq!(c.http_server_tcp_mss, None);
        // `parse_size` is binary, so MB == MiB
        assert_eq!(c.http_server_tls_session_cache_size, 256 * 1024 * 1024);
        assert_eq!(
            c.http_server_tls_session_cache_tti,
            Duration::from_secs(18 * 3600)
        );
        assert_eq!(
            c.http_server_tls_ticket_lifetime,
            Duration::from_secs(9 * 3600)
        );
        assert_eq!(c.http_server_grace_period, Duration::from_secs(60));
        assert_eq!(c.http_server_proxy_protocol_mode, ProxyProtocolMode::Off);
    }

    #[test]
    fn test_cli_explicit_values() {
        let c = parse(ALL_ARGS);

        assert_eq!(c.http_server_backlog, 4096);
        assert_eq!(c.http_server_max_requests_per_conn, Some(1000));
        assert_eq!(c.http_server_read_timeout, Duration::from_secs(60));
        assert_eq!(c.http_server_write_timeout, Duration::from_secs(120));
        assert_eq!(c.http_server_idle_timeout, Some(Duration::from_secs(180)));
        assert_eq!(c.http_server_tls_handshake_timeout, Duration::from_secs(4));
        assert_eq!(
            c.http_server_http1_header_read_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(c.http_server_body_read_timeout, Duration::from_secs(6));
        assert_eq!(c.http_server_http2_max_streams, 256);
        assert_eq!(
            c.http_server_http2_keepalive_interval,
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            c.http_server_http2_keepalive_timeout,
            Duration::from_secs(8)
        );
        assert_eq!(
            c.http_server_tcp_keepalive_delay,
            Some(Duration::from_secs(9))
        );
        assert_eq!(
            c.http_server_tcp_keepalive_interval,
            Some(Duration::from_secs(10))
        );
        assert_eq!(c.http_server_tcp_keepalive_retries, Some(11));
        assert_eq!(c.http_server_tcp_mss, Some(1400));
        assert_eq!(c.http_server_tls_session_cache_size, 1024 * 1024);
        assert_eq!(
            c.http_server_tls_session_cache_tti,
            Duration::from_secs(12 * 3600)
        );
        assert_eq!(
            c.http_server_tls_ticket_lifetime,
            Duration::from_secs(13 * 3600)
        );
        assert_eq!(c.http_server_grace_period, Duration::from_secs(14));
        assert_eq!(c.http_server_proxy_protocol_mode, ProxyProtocolMode::Forced);
    }

    #[test]
    fn test_cli_humantime_compound_duration() {
        let c = parse(&["--http-server-read-timeout=1h30m10s"]);
        assert_eq!(c.http_server_read_timeout, Duration::from_secs(5410));

        // Sub-second precision must survive
        let c = parse(&["--http-server-grace-period=1500ms"]);
        assert_eq!(c.http_server_grace_period, Duration::from_millis(1500));
    }

    #[test]
    fn test_cli_proxy_protocol_modes() {
        assert_eq!(
            parse(&["--http-server-proxy-protocol-mode=off"]).http_server_proxy_protocol_mode,
            ProxyProtocolMode::Off
        );
        assert_eq!(
            parse(&["--http-server-proxy-protocol-mode=enabled"]).http_server_proxy_protocol_mode,
            ProxyProtocolMode::Enabled
        );
        assert_eq!(
            parse(&["--http-server-proxy-protocol-mode=forced"]).http_server_proxy_protocol_mode,
            ProxyProtocolMode::Forced
        );

        // Not snake_case / unknown values must be rejected
        assert!(try_parse(&["--http-server-proxy-protocol-mode=Enabled"]).is_err());
        assert!(try_parse(&["--http-server-proxy-protocol-mode=bogus"]).is_err());
        assert!(try_parse(&["--http-server-proxy-protocol-mode="]).is_err());
    }

    #[test]
    fn test_cli_invalid_durations() {
        assert!(try_parse(&["--http-server-read-timeout=abc"]).is_err());
        // No unit -> humantime refuses it
        assert!(try_parse(&["--http-server-write-timeout=30"]).is_err());
        assert!(try_parse(&["--http-server-idle-timeout=-5s"]).is_err());
        assert!(try_parse(&["--http-server-grace-period="]).is_err());
    }

    #[test]
    fn test_cli_invalid_sizes() {
        assert!(try_parse(&["--http-server-tls-session-cache-size=abc"]).is_err());
        assert!(try_parse(&["--http-server-tls-session-cache-size=1QB"]).is_err());
        assert!(try_parse(&["--http-server-tls-session-cache-size=-1"]).is_err());
        // Bare numbers are bytes
        assert_eq!(
            parse(&["--http-server-tls-session-cache-size=1234"])
                .http_server_tls_session_cache_size,
            1234
        );
    }

    #[test]
    fn test_cli_invalid_numbers() {
        assert!(try_parse(&["--http-server-backlog=-1"]).is_err());
        // u32 overflow
        assert!(try_parse(&["--http-server-backlog=4294967296"]).is_err());
        assert!(try_parse(&["--http-server-http2-max-streams=foo"]).is_err());
        assert!(try_parse(&["--http-server-max-requests-per-conn=-1"]).is_err());
        assert!(try_parse(&["--http-server-unknown-option=1"]).is_err());
    }

    /// Catches clap definition problems (duplicate ids, bad default values that
    /// don't round-trip through the value parser, etc.)
    #[test]
    fn test_cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_size_units_are_binary() {
        let size = |s: &str| {
            parse(&[&format!("--http-server-tls-session-cache-size={s}")])
                .http_server_tls_session_cache_size
        };

        assert_eq!(size("0"), 0);
        assert_eq!(size("1KB"), 1024);
        assert_eq!(size("512KB"), 512 * 1024);
        assert_eq!(size("2GB"), 2 * 1024 * 1024 * 1024);
        // Decimal semantics would give 1_000_000 here
        assert_eq!(size("1MB"), 1_048_576);
    }

    #[test]
    fn test_cli_numeric_boundaries() {
        assert_eq!(parse(&["--http-server-backlog=0"]).http_server_backlog, 0);
        assert_eq!(
            parse(&["--http-server-backlog=4294967295"]).http_server_backlog,
            u32::MAX
        );
        assert_eq!(
            parse(&["--http-server-http2-max-streams=0"]).http_server_http2_max_streams,
            0
        );
        assert_eq!(
            parse(&["--http-server-max-requests-per-conn=0"]).http_server_max_requests_per_conn,
            Some(0)
        );
        assert_eq!(
            parse(&["--http-server-max-requests-per-conn=18446744073709551615"])
                .http_server_max_requests_per_conn,
            Some(u64::MAX)
        );
        // One past u64
        assert!(try_parse(&["--http-server-max-requests-per-conn=18446744073709551616"]).is_err());
    }

    /// Zero durations are accepted by humantime and must be carried over verbatim
    /// rather than being turned into `None`.
    #[test]
    fn test_cli_zero_durations() {
        let c = parse(&[
            "--http-server-read-timeout=0s",
            "--http-server-grace-period=0s",
            "--http-server-idle-timeout=0s",
        ]);
        assert_eq!(c.http_server_read_timeout, Duration::ZERO);
        assert_eq!(c.http_server_grace_period, Duration::ZERO);
        assert_eq!(c.http_server_idle_timeout, Some(Duration::ZERO));

        let o = ServerOptions::from(&c);
        assert_eq!(o.read_timeout, Some(Duration::ZERO));
        assert_eq!(o.grace_period, Duration::ZERO);
        assert_eq!(o.idle_timeout, Some(Duration::ZERO));
    }

    #[test]
    fn test_cli_clone_and_debug() {
        let c = parse(ALL_ARGS);
        assert_eq!(c.clone(), c);
        // The Debug output is used in startup logs - make sure the fields are in it
        let d = format!("{c:?}");
        assert!(d.contains("http_server_backlog: 4096"), "{d}");
        assert!(d.contains("Forced"), "{d}");
    }

    #[test]
    fn test_cli_eq() {
        assert_eq!(parse(&[]), parse(&["--http-server-read-timeout=30s"]));
        assert_ne!(parse(&[]), parse(&["--http-server-read-timeout=31s"]));
        assert_eq!(parse(ALL_ARGS), parse(ALL_ARGS));
    }

    #[test]
    fn test_server_options_from_cli() {
        let c = parse(ALL_ARGS);
        let o = ServerOptions::from(&c);

        assert_eq!(o.backlog, 4096);
        // Non-optional CLI timeouts are wrapped into `Some`
        assert_eq!(o.read_timeout, Some(Duration::from_secs(60)));
        assert_eq!(o.write_timeout, Some(Duration::from_secs(120)));
        assert_eq!(o.idle_timeout, Some(Duration::from_secs(180)));
        assert_eq!(o.tls_handshake_timeout, Duration::from_secs(4));
        assert_eq!(o.tcp_keepalive_delay, Some(Duration::from_secs(9)));
        assert_eq!(o.tcp_keepalive_interval, Some(Duration::from_secs(10)));
        assert_eq!(o.tcp_keepalive_retries, Some(11));
        assert_eq!(o.tcp_mss, Some(1400));
        assert_eq!(o.http1_header_read_timeout, Duration::from_secs(5));
        assert_eq!(o.http2_keepalive_interval, Some(Duration::from_secs(7)));
        assert_eq!(o.http2_keepalive_timeout, Duration::from_secs(8));
        assert_eq!(o.http2_max_streams, 256);
        assert_eq!(o.grace_period, Duration::from_secs(14));
        assert_eq!(o.max_requests_per_conn, Some(1000));
        assert_eq!(o.proxy_protocol_mode, ProxyProtocolMode::Forced);
    }

    #[test]
    fn test_server_options_from_cli_defaults_keep_optionals_none() {
        let o = ServerOptions::from(&parse(&[]));

        assert_eq!(o.idle_timeout, None);
        assert_eq!(o.max_requests_per_conn, None);
        assert_eq!(o.tcp_keepalive_delay, None);
        assert_eq!(o.tcp_keepalive_interval, None);
        assert_eq!(o.tcp_keepalive_retries, None);
        assert_eq!(o.tcp_mss, None);
        assert_eq!(o.http2_keepalive_interval, None);
        // ...while the mandatory ones are always set
        assert_eq!(o.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(o.write_timeout, Some(Duration::from_secs(30)));
        assert_eq!(o.proxy_protocol_mode, ProxyProtocolMode::Off);
    }

    #[test]
    fn test_tls_options_from_cli() {
        let c = parse(ALL_ARGS);
        let o = TlsOptions::from(&c);

        assert_eq!(o.sessions_count, 1024 * 1024);
        assert_eq!(o.sessions_tti, Duration::from_secs(12 * 3600));
        assert_eq!(o.ticket_lifetime, Duration::from_secs(13 * 3600));
        // These are not driven by the CLI and are left empty
        assert!(o.additional_alpn.is_empty());
        assert!(o.tls_versions.is_empty());

        // The CLI conversion must not inherit `TlsOptions::default()`
        let d = TlsOptions::default();
        assert_ne!(o.sessions_count, d.sessions_count);
        assert_ne!(o.sessions_tti, d.sessions_tti);
        assert_ne!(o.ticket_lifetime, d.ticket_lifetime);
    }
}
