pub mod cli;

use core::task;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::Poll,
};

use anyhow::{Context, anyhow};
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
use tower::Service;

use super::Error;

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

pub trait CloneableDnsResolver: Resolve + Clone + fmt::Debug + 'static {}

pub trait CloneableHyperDnsResolver:
    HyperDnsResolver + Clone + fmt::Debug + Send + Sync + 'static
{
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
            protocol: Protocol::Clear(53),
            servers: CLOUDFLARE_IPS.into(),
            tls_name: "cloudflare-dns.com".into(),
            cache_size: 1024,
        }
    }
}

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

            Ok(SocketAddrs { iter: addresses })
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

/// Implement resolving for Reqwest using Hickory
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
