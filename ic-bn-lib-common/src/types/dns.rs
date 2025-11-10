use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, anyhow};
use clap::Args;
use hickory_resolver::config::{CLOUDFLARE_IPS, LookupIpStrategy};
use humantime::parse_duration;
use strum::EnumString;

use crate::types::http::Error;

/// Copycat of Hickory `LookupIpStrategy` but with `FromStr` derived for CLI
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum LookupStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6ThenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6 (default)
    Ipv4ThenIpv6,
}

impl From<LookupStrategy> for LookupIpStrategy {
    fn from(value: LookupStrategy) -> Self {
        match value {
            LookupStrategy::Ipv4Only => Self::Ipv4Only,
            LookupStrategy::Ipv6Only => Self::Ipv6Only,
            LookupStrategy::Ipv4AndIpv6 => Self::Ipv4AndIpv6,
            LookupStrategy::Ipv6ThenIpv4 => Self::Ipv6thenIpv4,
            LookupStrategy::Ipv4ThenIpv6 => Self::Ipv4thenIpv6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Clear(u16),
    Tls(u16),
    Https(u16),
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.split(":");
        let (proto, port) = (iter.next().unwrap(), iter.next());
        let port = if let Some(v) = port {
            Some(v.parse::<u16>().context("unable to parse port")?)
        } else {
            None
        };

        match proto {
            "clear" => Ok(Self::Clear(port.unwrap_or(53))),
            "tls" => Ok(Self::Tls(port.unwrap_or(853))),
            "https" => Ok(Self::Https(port.unwrap_or(443))),
            _ => Err(anyhow!("unknown DNS protocol: {proto}").into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub protocol: Protocol,
    pub servers: Vec<IpAddr>,
    pub lookup_ip_strategy: LookupIpStrategy,
    pub cache_size: usize,
    pub timeout: Duration,
    pub tls_name: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            protocol: Protocol::Clear(53),
            servers: CLOUDFLARE_IPS.into(),
            lookup_ip_strategy: LookupIpStrategy::Ipv4AndIpv6,
            cache_size: 1024,
            timeout: Duration::from_secs(3),
            tls_name: "cloudflare-dns.com".into(),
        }
    }
}

pub struct SocketAddrs {
    pub iter: Box<dyn Iterator<Item = IpAddr> + Send>,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

pub const DEFAULT_RESOLVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // Cloudflare 1.1.1.1
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), // Google 8.8.8.8
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), // Quad9 9.9.9.9
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)), // Cloudflare 1.1.1.1
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)), // Google 8.8.8.8
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)), // Quad9 9.9.9.9
];

#[derive(Args)]
pub struct DnsCli {
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
    #[clap(env, long, default_value = "ipv4_and_ipv6")]
    pub dns_lookup_strategy: LookupStrategy,
}

impl From<&DnsCli> for Options {
    fn from(c: &DnsCli) -> Self {
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
