use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::anyhow;
use clap::Args;
use derive_new::new;
use humantime::parse_duration;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use rustls::{CipherSuite, ProtocolVersion, ServerConnection};
use socket2::TcpKeepalive;
use strum::{Display, EnumString, IntoStaticStr};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::{parse_size, traits::http::CustomBypassReason, types::tls::TlsOptions};

pub const ALPN_H1: &[u8] = b"http/1.1";
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_ACME: &[u8] = b"acme-tls/1";

/// HTTP error
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HTTP body reading timed out")]
    BodyTimedOut,
    #[error("HTTP body is too big")]
    BodyTooBig,
    #[error("HTTP body reading failed: {0}")]
    BodyReadingFailed(String),
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("No Proxy Protocol v2 detected")]
    NoProxyProtocolDetected,
    #[error("DNS resolving failed: {0}")]
    DnsError(String),
    #[error("Generic HTTP failure: {0}")]
    HttpError(#[from] http::Error),
    #[error("{0}")]
    HyperClientError(#[from] hyper_util::client::legacy::Error),
    #[error("{0}")]
    HyperError(#[from] hyper::Error),
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

/// HTTP Cache error
#[derive(thiserror::Error, Debug)]
pub enum CacheError {
    #[error("unable to extract key from request: {0}")]
    ExtractKey(String),
    #[error("unable to execute bypasser: {0}")]
    ExecuteBypasser(String),
    #[error("timed out while fetching body")]
    FetchBodyTimeout,
    #[error("body is too big")]
    FetchBodyTooBig,
    #[error("unable to fetch request body: {0}")]
    FetchBody(String),
    #[error("unable to parse content-length header")]
    ParseContentLength,
    #[error("{0}")]
    Other(String),
}

/// Status of Proxy Protocol in the Server
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ProxyProtocolMode {
    Off,
    Enabled,
    Forced,
}

/// HTTP server options
#[derive(Clone, Copy)]
pub struct ServerOptions {
    pub backlog: u32,
    pub tls_handshake_timeout: Duration,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
    pub tcp_keepalive_delay: Option<Duration>,
    pub tcp_keepalive_interval: Option<Duration>,
    pub tcp_keepalive_retries: Option<u32>,
    pub tcp_mss: Option<u32>,
    pub http1_header_read_timeout: Duration,
    pub http2_max_streams: u32,
    pub http2_keepalive_interval: Option<Duration>,
    pub http2_keepalive_timeout: Duration,
    pub grace_period: Duration,
    pub max_requests_per_conn: Option<u64>,
    pub proxy_protocol_mode: ProxyProtocolMode,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            backlog: 2048,
            tls_handshake_timeout: Duration::from_secs(15),
            read_timeout: Some(Duration::from_secs(60)),
            write_timeout: Some(Duration::from_secs(60)),
            idle_timeout: None,
            tcp_keepalive_delay: None,
            tcp_keepalive_interval: None,
            tcp_keepalive_retries: None,
            tcp_mss: None,
            http1_header_read_timeout: Duration::from_secs(10),
            http2_max_streams: 128,
            http2_keepalive_interval: None,
            http2_keepalive_timeout: Duration::from_secs(10),
            grace_period: Duration::from_secs(60),
            max_requests_per_conn: None,
            proxy_protocol_mode: ProxyProtocolMode::Off,
        }
    }
}

impl From<&ServerOptions> for TcpKeepalive {
    fn from(v: &ServerOptions) -> Self {
        let mut ka = Self::new();

        if let Some(v) = v.tcp_keepalive_delay {
            ka = ka.with_time(v);
        }
        if let Some(v) = v.tcp_keepalive_interval {
            ka = ka.with_interval(v);
        }
        if let Some(v) = v.tcp_keepalive_retries {
            ka = ka.with_retries(v);
        }

        ka
    }
}

/// TLS-related information about the connection
#[derive(Clone, Debug)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub protocol: ProtocolVersion,
    pub cipher: CipherSuite,
    pub handshake_dur: Duration,
}

impl TryFrom<&ServerConnection> for TlsInfo {
    type Error = Error;

    fn try_from(c: &ServerConnection) -> Result<Self, Self::Error> {
        Ok(Self {
            handshake_dur: Duration::ZERO,
            sni: c.server_name().map(|x| x.to_string()),
            alpn: c
                .alpn_protocol()
                .map(|x| String::from_utf8_lossy(x).to_string()),
            protocol: c
                .protocol_version()
                .ok_or_else(|| anyhow!("No TLS protocol found"))?,
            cipher: c
                .negotiated_cipher_suite()
                .map(|x| x.suite())
                .ok_or_else(|| anyhow!("No TLS ciphersuite found"))?,
        })
    }
}

/// Connection information
#[derive(Debug)]
pub struct ConnInfo {
    pub id: Uuid,
    pub accepted_at: Instant,
    pub local_addr: Addr,
    pub remote_addr: Addr,
    pub traffic: Arc<Stats>,
    pub req_count: AtomicU64,
    pub close: CancellationToken,
}

impl Default for ConnInfo {
    fn default() -> Self {
        Self {
            id: Uuid::now_v7(),
            accepted_at: Instant::now(),
            local_addr: Addr::default(),
            remote_addr: Addr::default(),
            traffic: Arc::new(Stats::new()),
            req_count: AtomicU64::new(0),
            close: CancellationToken::new(),
        }
    }
}

impl ConnInfo {
    pub fn req_count(&self) -> u64 {
        self.req_count.load(Ordering::SeqCst)
    }

    pub fn close(&self) {
        self.close.cancel();
    }
}

/// Options for a `Listener`
pub struct ListenerOpts {
    pub backlog: u32,
    pub mss: Option<u32>,
    pub keepalive: TcpKeepalive,
}

impl Default for ListenerOpts {
    fn default() -> Self {
        Self {
            backlog: 1024,
            mss: None,
            keepalive: TcpKeepalive::new(),
        }
    }
}

/// Connection endpoint address
#[derive(Debug, Clone)]
pub enum Addr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Default for Addr {
    fn default() -> Self {
        Self::Tcp(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            666,
        )))
    }
}

impl Addr {
    pub const fn family(&self) -> &'static str {
        match self {
            Self::Tcp(v) => {
                if v.ip().to_canonical().is_ipv4() {
                    "v4"
                } else {
                    "v6"
                }
            }
            Self::Unix(_) => "unix",
        }
    }

    pub const fn ip(&self) -> IpAddr {
        match self {
            Self::Tcp(v) => v.ip().to_canonical(),
            Self::Unix(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Tcp(v) => v.ip().to_canonical().to_string(),
                Self::Unix(v) => v.to_string_lossy().to_string(),
            }
        )
    }
}

/// Atomic counters for `AsyncCounter`
#[derive(new, Debug)]
pub struct Stats {
    #[new(default)]
    pub sent: AtomicU64,
    #[new(default)]
    pub rcvd: AtomicU64,
}

impl Stats {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::SeqCst)
    }

    pub fn rcvd(&self) -> u64 {
        self.rcvd.load(Ordering::SeqCst)
    }
}

/// HTTP server metrics
#[derive(Clone)]
pub struct Metrics {
    pub conns: IntCounterVec,
    pub conns_open: IntGaugeVec,
    pub requests: IntCounterVec,
    pub requests_inflight: IntGaugeVec,
    pub bytes_sent: IntCounterVec,
    pub bytes_rcvd: IntCounterVec,
    pub conn_duration: HistogramVec,
    pub requests_per_conn: HistogramVec,
    pub conn_tls_handshake_duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const HANDSHAKE_DURATION_BUCKETS: &[f64] =
            &[0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6];
        const CONN_DURATION_BUCKETS: &[f64] = &[1.0, 8.0, 32.0, 64.0, 256.0, 512.0, 1024.0];
        const CONN_REQUESTS: &[f64] = &[1.0, 4.0, 8.0, 16.0, 32.0, 64.0, 256.0];

        const LABELS: &[&str] = &[
            "addr",
            "family",
            "tls_version",
            "tls_cipher",
            "forced_close",
            "recycled",
        ];

        Self {
            conns: register_int_counter_vec_with_registry!(
                format!("conn_total"),
                format!("Counts the number of connections"),
                LABELS,
                registry
            )
            .unwrap(),

            conns_open: register_int_gauge_vec_with_registry!(
                format!("conn_open"),
                format!("Number of currently open connections"),
                &LABELS[0..4],
                registry
            )
            .unwrap(),

            requests: register_int_counter_vec_with_registry!(
                format!("conn_requests_total"),
                format!("Counts the number of requests"),
                LABELS,
                registry
            )
            .unwrap(),

            requests_inflight: register_int_gauge_vec_with_registry!(
                format!("conn_requests_inflight"),
                format!("Counts the number of requests that are currently executed"),
                &LABELS[0..4],
                registry
            )
            .unwrap(),

            bytes_sent: register_int_counter_vec_with_registry!(
                format!("conn_bytes_sent_total"),
                format!("Counts number of bytes sent"),
                LABELS,
                registry
            )
            .unwrap(),

            bytes_rcvd: register_int_counter_vec_with_registry!(
                format!("conn_bytes_rcvd_total"),
                format!("Counts number of bytes received"),
                LABELS,
                registry
            )
            .unwrap(),

            conn_duration: register_histogram_vec_with_registry!(
                format!("conn_duration_sec"),
                format!("Records the duration of connection in seconds"),
                LABELS,
                CONN_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),

            requests_per_conn: register_histogram_vec_with_registry!(
                format!("conn_requests_per_conn"),
                format!("Records the number of requests per connection"),
                LABELS,
                CONN_REQUESTS.to_vec(),
                registry
            )
            .unwrap(),

            conn_tls_handshake_duration: register_histogram_vec_with_registry!(
                format!("conn_tls_handshake_duration_sec"),
                format!("Records the duration of the TLS handshake in seconds"),
                &LABELS[0..4],
                HANDSHAKE_DURATION_BUCKETS.to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

/// HTTP versions to use
#[derive(Debug, Clone, Copy, Eq, PartialEq, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum HttpVersion {
    Http1,
    Http2,
    All,
}

/// HTTP client options
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub timeout_connect: Duration,
    pub timeout_read: Duration,
    pub timeout: Duration,
    pub pool_idle_timeout: Option<Duration>,
    pub pool_idle_max: Option<usize>,
    pub tcp_keepalive_delay: Option<Duration>,
    pub tcp_keepalive_interval: Option<Duration>,
    pub tcp_keepalive_retries: Option<u32>,
    pub http2_keepalive: Option<Duration>,
    pub http2_keepalive_timeout: Option<Duration>,
    pub http2_keepalive_idle: bool,
    pub happy_eyeballs_timeout: Duration,
    pub http_version: HttpVersion,
    pub user_agent: String,
    pub tls_config: Option<rustls::ClientConfig>,
    pub tls_fixed_name: Option<String>,
    pub dns_overrides: Vec<(String, SocketAddr)>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            timeout_connect: Duration::from_secs(10),
            timeout_read: Duration::from_secs(60),
            timeout: Duration::from_secs(120),
            pool_idle_timeout: None,
            pool_idle_max: None,
            tcp_keepalive_delay: None,
            tcp_keepalive_interval: None,
            tcp_keepalive_retries: None,
            http2_keepalive: None,
            http2_keepalive_timeout: None,
            http2_keepalive_idle: false,
            happy_eyeballs_timeout: Duration::from_millis(500),
            http_version: HttpVersion::All,
            user_agent: "Crab".into(),
            tls_config: None,
            tls_fixed_name: None,
            dns_overrides: vec![],
        }
    }
}

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

/// HTTP Server CLI
#[derive(Args, Clone, Debug, Eq, PartialEq)]
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

/// WAF CLI
#[derive(Args)]
pub struct WafCli {
    /// Enables the WAF.
    /// Requires one of sources to be defined.
    #[clap(env, long, requires = "waf_input")]
    pub waf_enable: bool,

    /// Enables the WAF API endpoint.
    /// Conflicts with `waf_url` and `waf_file`.
    #[clap(env, long, group = "waf_input")]
    pub waf_api: bool,

    /// URL where to fetch WAF rules.
    /// Conflicts with `waf_api` and `waf_file`.
    #[clap(env, long, group = "waf_input")]
    pub waf_url: Option<Url>,

    /// File from which to load WAF rules.
    /// Conflicts with `waf_api` and `waf_url`.
    #[clap(env, long, group = "waf_input")]
    pub waf_file: Option<PathBuf>,

    /// Interval at which to fetch the rules from the file or URL.
    #[clap(env, long, value_parser = parse_duration, default_value = "10s")]
    pub waf_interval: Duration,
}

/// Reason for bypassing the HTTP cache for the particular request
#[derive(Debug, Clone, Display, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum CacheBypassReason<R: CustomBypassReason> {
    MethodNotCacheable,
    SizeUnknown,
    BodyTooBig,
    HTTPError,
    UnableToExtractKey,
    UnableToRunBypasser,
    CacheControl,
    Custom(R),
}

impl<R: CustomBypassReason> CacheBypassReason<R> {
    pub fn into_str(self) -> &'static str {
        match self {
            Self::Custom(v) => v.into(),
            _ => self.into(),
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
        server: HttpServerCli,
        #[command(flatten)]
        client: HttpClientCli,
    }

    #[test]
    fn test_cli() {
        let args: Vec<&str> = vec![];
        Cli::parse_from(args);
    }
}
