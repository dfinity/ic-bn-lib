use std::time::Duration;

use clap::Args;
use humantime::parse_duration;

use crate::{parse_size, tls};

use super::ProxyProtocolMode;

#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct HttpServer {
    /// Backlog of incoming connections to set on the listening socket
    #[clap(env, long, default_value = "2048")]
    pub http_server_backlog: u32,

    /// Maximum number of HTTP requests to serve over a single connection.
    /// After this number is reached the connection is gracefully closed.
    /// The default is consistent with nginx's `keepalive_requests` parameter.
    #[clap(env, long, default_value = "1000")]
    pub http_server_max_requests_per_conn: u64,

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
    #[clap(env, long, default_value = "60s", value_parser = parse_duration)]
    pub http_server_idle_timeout: Duration,

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
    #[clap(env, long, default_value = "20s", value_parser = parse_duration)]
    pub http_server_http2_keepalive_interval: Duration,

    /// Keepalive timeout for HTTP2 connections
    #[clap(env, long, default_value = "10s", value_parser = parse_duration)]
    pub http_server_http2_keepalive_timeout: Duration,

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

impl From<&HttpServer> for super::Options {
    fn from(c: &HttpServer) -> Self {
        Self {
            backlog: c.http_server_backlog,
            read_timeout: Some(c.http_server_read_timeout),
            write_timeout: Some(c.http_server_write_timeout),
            idle_timeout: c.http_server_idle_timeout,
            tls_handshake_timeout: c.http_server_tls_handshake_timeout,
            http1_header_read_timeout: c.http_server_http1_header_read_timeout,
            http2_keepalive_interval: c.http_server_http2_keepalive_interval,
            http2_keepalive_timeout: c.http_server_http2_keepalive_timeout,
            http2_max_streams: c.http_server_http2_max_streams,
            grace_period: c.http_server_grace_period,
            max_requests_per_conn: Some(c.http_server_max_requests_per_conn),
            proxy_protocol_mode: c.http_server_proxy_protocol_mode,
        }
    }
}

impl From<&HttpServer> for tls::Options {
    fn from(c: &HttpServer) -> Self {
        Self {
            additional_alpn: vec![],
            sessions_count: c.http_server_tls_session_cache_size,
            sessions_tti: c.http_server_tls_session_cache_tti,
            ticket_lifetime: c.http_server_tls_ticket_lifetime,
            tls_versions: vec![],
        }
    }
}
