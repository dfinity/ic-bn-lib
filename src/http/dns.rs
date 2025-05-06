use core::task;
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::Poll,
};

use anyhow::Context;
use async_trait::async_trait;
use hickory_proto::rr::RecordType;
use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE_IPS, NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts},
    lookup_ip::LookupIpIntoIter,
    name_server::TokioConnectionProvider,
};
use hyper_util::client::legacy::connect::dns::Name as HyperName;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use strum_macros::EnumString;
use tower::Service;

use super::{Error, client::CloneableDnsResolver};

#[derive(Clone, Copy, Debug, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum Protocol {
    Clear,
    Tls,
    Https,
}

#[async_trait]
pub trait Resolves: Send + Sync {
    async fn resolve(&self, name: &str, record: &str) -> Result<Vec<(String, String)>, Error>;
    fn flush_cache(&self);
}

pub struct Options {
    pub protocol: Protocol,
    pub servers: Vec<IpAddr>,
    pub tls_name: String,
    pub cache_size: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            protocol: Protocol::Clear,
            servers: CLOUDFLARE_IPS.into(),
            tls_name: "cloudflare-dns.com".into(),
            cache_size: 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Resolver(Arc<TokioResolver>);
impl CloneableDnsResolver for Resolver {}

impl Resolver {
    /// Creates a new resolver with given options.
    /// It must be called in Tokio context.
    pub fn new(o: Options) -> Self {
        let name_servers = match o.protocol {
            Protocol::Clear => NameServerConfigGroup::from_ips_clear(&o.servers, 53, true),
            Protocol::Tls => NameServerConfigGroup::from_ips_tls(&o.servers, 853, o.tls_name, true),
            Protocol::Https => {
                NameServerConfigGroup::from_ips_https(&o.servers, 443, o.tls_name, true)
            }
        };

        let cfg = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.cache_size = o.cache_size;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.preserve_intermediates = false;
        opts.try_tcp_on_error = true;

        let mut builder =
            TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default());
        *builder.options_mut() = opts;

        Self(Arc::new(builder.build()))
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

pub struct SocketAddrs {
    iter: LookupIpIntoIter,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

// Implement resolving for Reqwest using Hickory
impl Resolve for Resolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();

        Box::pin(async move {
            let lookup = resolver.0.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs {
                iter: lookup.into_iter(),
            });

            Ok(addrs)
        })
    }
}

#[async_trait]
impl Resolves for Resolver {
    async fn resolve(&self, name: &str, record: &str) -> Result<Vec<(String, String)>, Error> {
        let record_type = RecordType::from_str(record).context("unable to parse record")?;

        let lookup = self
            .0
            .lookup(name, record_type)
            .await
            .context("lookup failed")?;

        let rr = lookup
            .into_iter()
            .map(|x| (x.record_type().to_string(), x.to_string()))
            .collect::<Vec<_>>();

        Ok(rr)
    }

    fn flush_cache(&self) {
        self.0.clear_cache();
    }
}

// Implement resolving for Hyper
impl Service<HyperName> for Resolver {
    type Response = SocketAddrs;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: HyperName) -> Self::Future {
        let resolver = self.0.clone();

        Box::pin(async move {
            let response = resolver
                .lookup_ip(name.as_str())
                .await
                .map_err(|e| Error::DnsError(e.to_string()))?;
            let addresses = response.into_iter();

            Ok(SocketAddrs { iter: addresses })
        })
    }
}
