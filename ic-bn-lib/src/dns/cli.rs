use std::{net::IpAddr, time::Duration};

use clap::Args;
use humantime::parse_duration;

use crate::dns::{DEFAULT_RESOLVERS, LookupStrategy, Protocol};

/// DNS CLI parameters
#[derive(Args)]
pub struct DnsCli {
    /// List of DNS servers to use
    #[clap(env, long, value_delimiter = ',', default_values_t = DEFAULT_RESOLVERS)]
    pub dns_servers: Vec<IpAddr>,

    /// DNS protocol to use (clear/tls/https) with an optional port separated by a colon.
    /// E.g. "clear:8053". If the port is omitted then the default is used.
    #[clap(env, long, default_value = "clear")]
    pub dns_protocol: Protocol,

    /// Cache size for the resolver (in number of DNS records)
    #[clap(env, long, default_value = "2048")]
    pub dns_cache_size: u64,

    /// Timeout for resolving
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub dns_timeout: Duration,

    /// Number of resolving attempts to do
    #[clap(env, long, default_value = "3")]
    pub dns_attempts: usize,

    /// TLS name to expect for TLS and HTTPS protocols (e.g. "dns.google" or "cloudflare-dns.com")
    #[clap(env, long, default_value = "cloudflare-dns.com")]
    pub dns_tls_name: String,

    /// IP Lookup strategy to use. Can be one of `ipv4_only`, `ipv6_only`, `ipv4_and_ipv6`, `ipv4_then_ipv6` or `ipv6_then_ipv4`.
    /// Default is to look up IPv4 and IPv6 in parallel.
    #[clap(env, long, default_value = "ipv4_and_ipv6")]
    pub dns_lookup_strategy: LookupStrategy,

    /// Disable DNSSEC validation for DNS queries (DNSSEC is enabled by default)
    #[clap(env, long)]
    pub dns_dnssec_disabled: bool,
}
