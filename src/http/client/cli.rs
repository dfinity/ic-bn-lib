use std::time::Duration;

use clap::Args;
use humantime::parse_duration;

use crate::http::client::HttpVersion;

#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct HttpClient {
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

impl From<&HttpClient> for super::Options {
    fn from(c: &HttpClient) -> Self {
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

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        server: HttpClient,
    }

    #[test]
    fn test_cli() {
        let args: Vec<&str> = vec![];
        Cli::parse_from(args);
    }
}
