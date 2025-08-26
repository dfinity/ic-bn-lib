pub mod cli;

use core::task;
use std::{
    collections::BTreeMap,
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use candid::Principal;
use hickory_proto::rr::RecordType;
use hickory_resolver::{
    TokioResolver,
    config::{
        CLOUDFLARE_IPS, LookupIpStrategy, NameServerConfigGroup, ResolveHosts, ResolverConfig,
        ResolverOpts,
    },
    name_server::TokioConnectionProvider,
};
use hyper_util::client::legacy::connect::dns::Name as HyperName;
use ic_agent::Agent;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use strum::EnumString;
use tokio_util::sync::CancellationToken;
use tower::Service;

use crate::{principal, tasks::Run};

use super::Error;

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

#[async_trait]
pub trait Resolves: Send + Sync {
    async fn resolve(&self, name: &str, record: &str) -> Result<Vec<(String, String)>, Error>;
    fn flush_cache(&self);
}

pub trait HyperDnsResolver:
    Service<
        HyperName,
        Response = SocketAddrs,
        Error = Error,
        Future = Pin<Box<dyn Future<Output = Result<SocketAddrs, Error>> + Send>>,
    >
{
}

pub trait CloneableDnsResolver: Resolve + Clone + Debug + 'static {}

pub trait CloneableHyperDnsResolver:
    HyperDnsResolver + Clone + Debug + Send + Sync + 'static
{
}

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

/// DNS-resolver based on Hickory
#[derive(Debug, Clone)]
pub struct Resolver(Arc<TokioResolver>);
impl CloneableDnsResolver for Resolver {}
impl HyperDnsResolver for Resolver {}
impl CloneableHyperDnsResolver for Resolver {}

impl Resolver {
    /// Creates a new resolver with given options.
    /// It must be called in Tokio context.
    pub fn new(o: Options) -> Self {
        let name_servers = match o.protocol {
            Protocol::Clear(p) => NameServerConfigGroup::from_ips_clear(&o.servers, p, true),
            Protocol::Tls(p) => {
                NameServerConfigGroup::from_ips_tls(&o.servers, p, o.tls_name, true)
            }
            Protocol::Https(p) => {
                NameServerConfigGroup::from_ips_https(&o.servers, p, o.tls_name, true)
            }
        };

        let cfg = ResolverConfig::from_parts(None, vec![], name_servers);

        let mut opts = ResolverOpts::default();
        opts.cache_size = o.cache_size;
        opts.timeout = o.timeout;
        opts.ip_strategy = o.lookup_ip_strategy;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.preserve_intermediates = false;
        opts.try_tcp_on_error = true;

        let builder = TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
            .with_options(opts);

        Self(Arc::new(builder.build()))
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

pub struct SocketAddrs {
    iter: Box<dyn Iterator<Item = IpAddr> + Send>,
}

impl Iterator for SocketAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|ip_addr| SocketAddr::new(ip_addr, 0))
    }
}

// Implement resolving for Reqwest
impl Resolve for Resolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();

        Box::pin(async move {
            let lookup = resolver.0.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(SocketAddrs {
                iter: Box::new(lookup.into_iter()),
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

/// Implement resolving for Hyper
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

            Ok(SocketAddrs {
                iter: Box::new(addresses),
            })
        })
    }
}

/// Resolver that always resolves the predefined hostname instead of provided one.
/// Wraps `Resolver`.
#[derive(Debug, Clone)]
pub struct FixedResolver(Resolver, String, HyperName);
impl CloneableDnsResolver for FixedResolver {}
impl HyperDnsResolver for FixedResolver {}
impl CloneableHyperDnsResolver for FixedResolver {}

impl FixedResolver {
    pub fn new(o: Options, name: String) -> Result<Self, Error> {
        let resolver = Resolver::new(o);
        let hyper_name = HyperName::from_str(&name).context("unable to parse name")?;

        Ok(Self(resolver, name, hyper_name))
    }
}

/// Implement resolving for Reqwest
impl Resolve for FixedResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        // Name cannot be cloned so we have to parse it each time.
        // If new() succeeded then this will always succeed too.
        let name = Name::from_str(&self.1).unwrap();
        reqwest::dns::Resolve::resolve(&self.0, name)
    }
}

/// Implement resolving for Hyper
impl Service<HyperName> for FixedResolver {
    type Response = SocketAddrs;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _name: HyperName) -> Self::Future {
        self.0.call(self.2.clone())
    }
}

/// Resolver that resolves from the provided mappings
#[derive(Debug, Clone)]
pub struct StaticResolver(Arc<BTreeMap<String, Vec<IpAddr>>>);
impl CloneableDnsResolver for StaticResolver {}
impl HyperDnsResolver for StaticResolver {}
impl CloneableHyperDnsResolver for StaticResolver {}

impl StaticResolver {
    pub fn new(items: impl IntoIterator<Item = (String, Vec<IpAddr>)>) -> Self {
        Self(Arc::new(BTreeMap::from_iter(items)))
    }

    pub fn lookup(&self, name: &str) -> Option<Vec<IpAddr>> {
        self.0.get(name).cloned()
    }
}

/// Implement resolving for Reqwest
impl Resolve for StaticResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let addrs = self.lookup(name.as_str()).unwrap_or_default();

        Box::pin(async move {
            Ok(Box::new(SocketAddrs {
                iter: Box::new(addrs.into_iter()),
            }) as Addrs)
        })
    }
}

/// Implement resolving for Hyper
impl Service<HyperName> for StaticResolver {
    type Response = SocketAddrs;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: HyperName) -> Self::Future {
        let addrs = self.lookup(name.as_str()).unwrap_or_default();

        Box::pin(async move {
            Ok(SocketAddrs {
                iter: Box::new(addrs.into_iter()),
            })
        })
    }
}

/// Resolver that resolves the API BN IPs using the registry.
/// If the registry doesn't contain the requested host - use the normal fallback
/// DNS resolver to look it up
#[derive(Debug, Clone)]
pub struct ApiBnResolver {
    agent: Agent,
    subnet: Principal,
    resolver_static: Arc<ArcSwap<StaticResolver>>,
    resolver_fallback: Resolver,
}
impl CloneableDnsResolver for ApiBnResolver {}
impl HyperDnsResolver for ApiBnResolver {}
impl CloneableHyperDnsResolver for ApiBnResolver {}

impl ApiBnResolver {
    pub fn new(resolver_fallback: Resolver, agent: Agent) -> Result<Self, Error> {
        let resolver_static = Arc::new(ArcSwap::new(Arc::new(StaticResolver::new(vec![]))));
        let subnet = principal!("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe");

        Ok(Self {
            agent,
            subnet,
            resolver_static,
            resolver_fallback,
        })
    }

    /// Gets a list of API BN domains and their IP addresses from the registry
    async fn get_api_bns(&self) -> Result<Vec<(String, Vec<IpAddr>)>, Error> {
        let api_bns = self
            .agent
            .fetch_api_boundary_nodes_by_subnet_id(self.subnet)
            .await
            .context("unable to get API BNs from IC")?;

        let mut r = Vec::with_capacity(api_bns.len());
        for n in api_bns {
            let ipv6 = IpAddr::from_str(&n.ipv6_address)
                .context(format!("unable to parse IPv6 address for {}", n.domain))?;
            let mut addrs = vec![ipv6];

            // See if there's an IPv4 too
            if let Some(v) = n.ipv4_address {
                let ipv4 = IpAddr::from_str(&v)
                    .context(format!("unable to parse IPv4 address for {}", n.domain))?;
                addrs.push(ipv4);
            }

            r.push((n.domain, addrs));
        }

        Ok(r)
    }
}

/// Implement resolving for Reqwest
impl Resolve for ApiBnResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let api_bns = self.resolver_static.load_full().lookup(name.as_str());
        let resolver_fallback = self.resolver_fallback.clone();

        Box::pin(async move {
            let addrs = match api_bns {
                Some(v) => v,
                None => {
                    // Look up using a fallback resolver if nothing was found in the static one
                    resolver_fallback
                        .0
                        .lookup_ip(name.as_str())
                        .await
                        .map_err(|e| Error::DnsError(e.to_string()))?
                        .into_iter()
                        .collect()
                }
            };

            Ok(Box::new(SocketAddrs {
                iter: Box::new(addrs.into_iter()),
            }) as Addrs)
        })
    }
}

/// Implement resolving for Hyper
impl Service<HyperName> for ApiBnResolver {
    type Response = SocketAddrs;
    type Error = Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: HyperName) -> Self::Future {
        let api_bns = self.resolver_static.load_full().lookup(name.as_str());
        let resolver_fallback = self.resolver_fallback.clone();

        Box::pin(async move {
            let addrs = match api_bns {
                Some(v) => v,
                None => {
                    // Look up using a fallback resolver if nothing was found in the static one
                    resolver_fallback
                        .0
                        .lookup_ip(name.as_str())
                        .await
                        .map_err(|e| Error::DnsError(e.to_string()))?
                        .into_iter()
                        .collect()
                }
            };

            Ok(SocketAddrs {
                iter: Box::new(addrs.into_iter()),
            })
        })
    }
}

#[async_trait]
impl Run for ApiBnResolver {
    async fn run(&self, _token: CancellationToken) -> Result<(), anyhow::Error> {
        let api_bns = self.get_api_bns().await?;
        let resolver = StaticResolver::new(api_bns);
        self.resolver_static.store(Arc::new(resolver));

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dns_protocol() {
        assert_eq!(Protocol::from_str("clear").unwrap(), Protocol::Clear(53));
        assert_eq!(Protocol::from_str("tls").unwrap(), Protocol::Tls(853));
        assert_eq!(Protocol::from_str("https").unwrap(), Protocol::Https(443));

        assert_eq!(
            Protocol::from_str("clear:8053").unwrap(),
            Protocol::Clear(8053)
        );
        assert_eq!(Protocol::from_str("tls:8853").unwrap(), Protocol::Tls(8853));
        assert_eq!(
            Protocol::from_str("https:8443").unwrap(),
            Protocol::Https(8443)
        );

        assert!(Protocol::from_str("clear:").is_err(),);
        assert!(Protocol::from_str("clear:x").is_err(),);
        assert!(Protocol::from_str("clear:-1").is_err(),);
        assert!(Protocol::from_str("clear:65537").is_err(),);
    }
}
