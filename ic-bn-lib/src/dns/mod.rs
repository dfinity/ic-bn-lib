pub mod cli;
pub mod resolvers;

use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, anyhow};
use hickory_resolver::{
    config::{
        ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
        ResolverOpts,
    },
    net::{DnsError as HickoryDnsError, NetError},
};
use strum::EnumString;

use crate::dns::cli::DnsCli;

/// Default DNS servers
pub const DEFAULT_RESOLVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // Cloudflare 1.1.1.1
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), // Google 8.8.8.8
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), // Quad9 9.9.9.9
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)), // Cloudflare 1.1.1.1
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)), // Google 8.8.8.8
    IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)), // Quad9 9.9.9.9
];

/// Copycat of `hickory_resolver::config::LookupIpStrategy` but with `FromStr` derived for CLI
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum LookupStrategy {
    /// Only query for A (Ipv4) records
    Ipv4Only,
    /// Only query for AAAA (Ipv6) records
    Ipv6Only,
    /// Query for A and AAAA in parallel
    #[default]
    Ipv4AndIpv6,
    /// Query for Ipv6 if that fails, query for Ipv4
    Ipv6ThenIpv4,
    /// Query for Ipv4 if that fails, query for Ipv6
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

/// DNS protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Clear(u16),
    Tls(u16),
    Https(u16),
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

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
            _ => Err(anyhow!("unknown DNS protocol: {proto}")),
        }
    }
}

/// DNS resolver options
#[derive(Debug, Clone)]
pub struct Options {
    pub opts: ResolverOpts,
    pub cfg: ResolverConfig,
}

impl Options {
    /// Creates simple options with cleartext resolving using the given IPs and port
    pub fn simple(addrs: &[IpAddr], port: u16) -> Self {
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = ResolveHosts::Never;
        opts.preserve_intermediates = false;
        opts.try_tcp_on_error = true;

        let connections = vec![
            {
                let mut cfg = ConnectionConfig::udp();
                cfg.port = port;
                cfg
            },
            {
                let mut cfg = ConnectionConfig::tcp();
                cfg.port = port;
                cfg
            },
        ];

        let name_servers = addrs
            .iter()
            .map(|x| NameServerConfig::new(*x, true, connections.clone()))
            .collect();
        let cfg = ResolverConfig::from_parts(None, vec![], name_servers);

        Self { opts, cfg }
    }
}

impl Default for Options {
    fn default() -> Self {
        // A bit hacky way of using Clap CLI defaults as defaults here
        use clap::Parser;
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            dns: DnsCli,
        }
        let cli = Cli::parse_from([""]);

        Self::from(&cli.dns)
    }
}

/// Iterator over DNS lookup results
pub struct SocketAddrs {
    pub iter: Box<dyn Iterator<Item = IpAddr> + Send>,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

impl From<&DnsCli> for Options {
    fn from(c: &DnsCli) -> Self {
        Self {
            opts: ResolverOpts::from(c),
            cfg: ResolverConfig::from(c),
        }
    }
}

impl From<&DnsCli> for ResolverOpts {
    fn from(c: &DnsCli) -> Self {
        let mut opts = Self::default();
        opts.cache_size = c.dns_cache_size;
        opts.timeout = c.dns_timeout;
        opts.attempts = c.dns_attempts;
        opts.ip_strategy = c.dns_lookup_strategy.into();
        opts.use_hosts_file = ResolveHosts::Never;
        opts.preserve_intermediates = false;
        opts.validate = !c.dns_dnssec_disabled;
        opts.try_tcp_on_error = true;

        opts
    }
}

impl From<&DnsCli> for ResolverConfig {
    fn from(c: &DnsCli) -> Self {
        let mut cfg = Self::default();

        for srv in &c.dns_servers {
            let connections = match c.dns_protocol {
                Protocol::Clear(port) => vec![
                    {
                        let mut cfg = ConnectionConfig::udp();
                        cfg.port = port;
                        cfg
                    },
                    {
                        let mut cfg = ConnectionConfig::tcp();
                        cfg.port = port;
                        cfg
                    },
                ],
                Protocol::Tls(port) => vec![{
                    let mut cfg = ConnectionConfig::tls(Arc::from(c.dns_tls_name.as_str()));
                    cfg.port = port;
                    cfg
                }],
                Protocol::Https(port) => vec![{
                    let mut cfg = ConnectionConfig::https(Arc::from(c.dns_tls_name.as_str()), None);
                    cfg.port = port;
                    cfg
                }],
            };

            let name_server = NameServerConfig::new(*srv, true, connections);
            cfg.add_name_server(name_server);
        }

        cfg
    }
}

#[derive(thiserror::Error, Debug)]
pub enum DnsError {
    #[error("Resolver error: {0}")]
    Resolver(#[from] NetError),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Checks if given Hickory error means there was a negative lookup
pub fn is_error_negative_lookup(e: &NetError) -> bool {
    e.is_no_records_found()
        || e.is_nx_domain()
        || matches!(e, NetError::Dns(HickoryDnsError::Nsec { .. }))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_protocol_from_str_defaults() {
        assert_eq!(Protocol::from_str("clear").unwrap(), Protocol::Clear(53));
        assert_eq!(Protocol::from_str("tls").unwrap(), Protocol::Tls(853));
        assert_eq!(Protocol::from_str("https").unwrap(), Protocol::Https(443));
    }

    #[test]
    fn test_protocol_from_str_custom_port() {
        assert_eq!(
            Protocol::from_str("clear:5353").unwrap(),
            Protocol::Clear(5353)
        );
        assert_eq!(Protocol::from_str("tls:8853").unwrap(), Protocol::Tls(8853));
        assert_eq!(
            Protocol::from_str("https:8443").unwrap(),
            Protocol::Https(8443)
        );
    }

    #[test]
    fn test_protocol_from_str_unknown_protocol() {
        assert!(Protocol::from_str("quic").is_err());
    }

    #[test]
    fn test_protocol_from_str_invalid_port() {
        assert!(Protocol::from_str("clear:notaport").is_err());
    }

    #[test]
    fn test_lookup_strategy_conversion() {
        assert_eq!(
            LookupIpStrategy::from(LookupStrategy::Ipv4Only),
            LookupIpStrategy::Ipv4Only
        );
        assert_eq!(
            LookupIpStrategy::from(LookupStrategy::Ipv6Only),
            LookupIpStrategy::Ipv6Only
        );
        assert_eq!(
            LookupIpStrategy::from(LookupStrategy::Ipv4AndIpv6),
            LookupIpStrategy::Ipv4AndIpv6
        );
        assert_eq!(
            LookupIpStrategy::from(LookupStrategy::Ipv6ThenIpv4),
            LookupIpStrategy::Ipv6thenIpv4
        );
        assert_eq!(
            LookupIpStrategy::from(LookupStrategy::Ipv4ThenIpv6),
            LookupIpStrategy::Ipv4thenIpv6
        );
    }

    #[test]
    fn test_socket_addrs_iterator() {
        let mut addrs = SocketAddrs {
            iter: Box::new(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))].into_iter()),
        };

        assert_eq!(
            addrs.next(),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        );
        assert_eq!(addrs.next(), None);
    }
}
