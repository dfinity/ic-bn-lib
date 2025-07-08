use std::net::IpAddr;

use clap::Args;
use hickory_resolver::config::CLOUDFLARE_IPS;

use crate::http::dns::{Options, Protocol};

#[derive(Args)]
pub struct Dns {
    /// List of DNS servers to use
    #[clap(env, long, value_delimiter = ',', default_values_t = CLOUDFLARE_IPS)]
    pub dns_servers: Vec<IpAddr>,

    /// DNS protocol to use (clear/tls/https) with an optional port separated by a colon.
    /// E.g. "clear:8053". If the port is omitted then the default is used.
    #[clap(env, long, default_value = "tls")]
    pub dns_protocol: Protocol,

    /// TLS name to expect for TLS and HTTPS protocols (e.g. "dns.google" or "cloudflare-dns.com")
    #[clap(env, long, default_value = "cloudflare-dns.com")]
    pub dns_tls_name: String,

    /// Cache size for the resolver (in number of DNS records)
    #[clap(env, long, default_value = "2048")]
    pub dns_cache_size: usize,
}

impl From<&Dns> for Options {
    fn from(c: &Dns) -> Self {
        Self {
            protocol: c.dns_protocol,
            servers: c.dns_servers.clone(),
            tls_name: c.dns_tls_name.clone(),
            cache_size: c.dns_cache_size,
        }
    }
}
