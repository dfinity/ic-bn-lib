use core::task;
use std::{
    collections::BTreeMap, fmt::Debug, net::IpAddr, pin::Pin, str::FromStr, sync::Arc, task::Poll,
};

use anyhow::Context;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use candid::Principal;
use hickory_proto::rr::{Record, RecordType};
use hickory_resolver::{
    ResolveError, TokioResolver,
    config::{NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use hyper_util::client::legacy::connect::dns::Name as HyperName;
use ic_agent::Agent;
use ic_bn_lib_common::{
    principal,
    traits::{
        Run,
        dns::{CloneableDnsResolver, CloneableHyperDnsResolver, HyperDnsResolver, Resolves},
    },
    types::{
        dns::{Options, Protocol, SocketAddrs},
        http::Error,
    },
};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio_util::sync::CancellationToken;
use tower::Service;

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
        opts.validate = !o.dnssec_disabled;
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
    async fn resolve(
        &self,
        record_type: RecordType,
        name: &str,
    ) -> Result<Vec<Record>, ResolveError> {
        let lookup = self.0.lookup(name, record_type).await?;
        Ok(lookup.records().to_vec())
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
/// DNS resolver to look it up.
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
    pub fn new(resolver_fallback: Resolver, agent: Agent) -> Self {
        let resolver_static = Arc::new(ArcSwap::new(Arc::new(StaticResolver::new(vec![]))));
        let subnet = principal!("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe");

        Self {
            agent,
            subnet,
            resolver_static,
            resolver_fallback,
        }
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

/// Resolver that resolves all hostnames to the single IP address
#[derive(Debug, Clone)]
pub struct SingleResolver(IpAddr);
impl CloneableDnsResolver for SingleResolver {}

impl SingleResolver {
    pub const fn new(addr: IpAddr) -> Self {
        Self(addr)
    }
}

/// Implement resolving for Reqwest
impl Resolve for SingleResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let addr = self.0;

        Box::pin(async move {
            Ok(Box::new(SocketAddrs {
                iter: Box::new(vec![addr].into_iter()),
            }) as Addrs)
        })
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, SocketAddr};

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

    #[tokio::test]
    async fn test_single_resolver() {
        let addr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let resolver = SingleResolver::new(addr);

        let mut res = resolver
            .resolve(Name::from_str("foo.bar").unwrap())
            .await
            .unwrap();
        assert_eq!(res.next(), Some(SocketAddr::new(addr, 0)));
    }
}
