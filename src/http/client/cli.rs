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

    /// How long to keep idle HTTP connections open
    #[clap(env, long, default_value = "120s", value_parser = parse_duration)]
    pub http_client_pool_idle: Duration,

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
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub http_client_http2_keepalive_timeout: Duration,

    /// Which HTTP versions to use.
    /// Can be "http1", "http2" or "all". Defaults to "all".
    #[clap(env, long, default_value = "all")]
    pub http_client_http_version: HttpVersion,

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
            pool_idle_timeout: Some(c.http_client_pool_idle),
            pool_idle_max: None,
            tcp_keepalive_delay: c.http_client_tcp_keepalive_delay,
            tcp_keepalive_interval: c.http_client_tcp_keepalive_interval,
            tcp_keepalive_retries: c.http_client_tcp_keepalive_retries,
            http2_keepalive: c.http_client_http2_keepalive,
            http2_keepalive_timeout: c.http_client_http2_keepalive_timeout,
            http2_keepalive_idle: true,
            http_version: c.http_client_http_version,
            user_agent: "".into(),
            tls_config: None,
            tls_fixed_name: c.http_client_tls_fixed_name.clone(),
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
