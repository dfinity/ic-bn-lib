use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use clap::Args;
use humantime::parse_duration;

use crate::http::dns::{LookupStrategy, Options, Protocol};

pub const DEFAULT_RESOLVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // Cloudflare 1.1.1.1
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), // Google 8.8.8.8
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), // Quad9 9.9.9.9
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)), // Cloudflare 1.1.1.1
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)), // Google 8.8.8.8
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)), // Quad9 9.9.9.9
];

#[derive(Args)]
pub struct Dns {
    /// List of DNS servers to use
    #[clap(env, long, value_delimiter = ',', default_values_t = DEFAULT_RESOLVERS)]
    pub dns_servers: Vec<IpAddr>,

    /// DNS protocol to use (clear/tls/https) with an optional port separated by a colon.
    /// E.g. "clear:8053". If the port is omitted then the default is used.
    #[clap(env, long, default_value = "tls")]
    pub dns_protocol: Protocol,

    /// Cache size for the resolver (in number of DNS records)
    #[clap(env, long, default_value = "2048")]
    pub dns_cache_size: usize,

    /// Timeout for resolving
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub dns_timeout: Duration,

    /// TLS name to expect for TLS and HTTPS protocols (e.g. "dns.google" or "cloudflare-dns.com")
    #[clap(env, long, default_value = "cloudflare-dns.com")]
    pub dns_tls_name: String,

    /// IP Lookup strategy to use. Can be one of `ipv4_only`, `ipv6_only`, `ipv4_and_ipv6`, `ipv4_then_ipv6` or `ipv6_then_ipv4`.
    /// Default is to look up IPv4 and IPv6 in parallel.
    #[clap(env, long, default_value = "ipv4_then_ipv6")]
    pub dns_lookup_strategy: LookupStrategy,
}

impl From<&Dns> for Options {
    fn from(c: &Dns) -> Self {
        Self {
            protocol: c.dns_protocol,
            servers: c.dns_servers.clone(),
            lookup_ip_strategy: c.dns_lookup_strategy.into(),
            cache_size: c.dns_cache_size,
            timeout: c.dns_timeout,
            tls_name: c.dns_tls_name.clone(),
        }
    }
}
