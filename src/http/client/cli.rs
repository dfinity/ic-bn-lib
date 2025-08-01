use std::time::Duration;

use clap::Args;
use humantime::parse_duration;

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

    /// TCP Keepalive interval
    #[clap(env, long, default_value = "15s", value_parser = parse_duration)]
    pub http_client_tcp_keepalive: Duration,

    /// HTTP2 Keepalive interval
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub http_client_http2_keepalive: Duration,

    /// HTTP2 Keepalive timeout
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub http_client_http2_keepalive_timeout: Duration,

    /// HTTP2 Only. Disables HTTP/1.1
    #[clap(env, long)]
    pub http_client_http2_only: bool,

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
            tcp_keepalive: Some(c.http_client_tcp_keepalive),
            http2_keepalive: Some(c.http_client_http2_keepalive),
            http2_keepalive_timeout: c.http_client_http2_keepalive_timeout,
            http2_keepalive_idle: false,
            http2_only: c.http_client_http2_only,
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
