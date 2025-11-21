use std::{fmt::Debug, pin::Pin};

use async_trait::async_trait;
use hickory_proto::rr::{Record, RecordType};
use hickory_resolver::ResolveError;
use hyper_util::client::legacy::connect::dns::Name;
use reqwest::dns::Resolve;
use tower_service::Service;

use crate::types::{dns::SocketAddrs, http::Error};

/// Generic trait to resolve a DNS record
#[async_trait]
pub trait Resolves: Send + Sync {
    async fn resolve(
        &self,
        record_type: RecordType,
        name: &str,
    ) -> Result<Vec<Record>, ResolveError>;

    fn flush_cache(&self);
}

/// Cloneable version of `reqwest::dns::resolve``
pub trait CloneableDnsResolver: Resolve + Clone + Debug + 'static {}

/// Trait that satisfies Hyper's DNS resolver constraints
pub trait HyperDnsResolver:
    Service<
        Name,
        Response = SocketAddrs,
        Error = Error,
        Future = Pin<Box<dyn Future<Output = Result<SocketAddrs, Error>> + Send>>,
    >
{
}

/// Cloneable version of `HyperDnsResolver``
pub trait CloneableHyperDnsResolver:
    HyperDnsResolver + Clone + Debug + Send + Sync + 'static
{
}
