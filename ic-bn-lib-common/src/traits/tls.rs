use std::{fmt::Debug, sync::Arc};

use anyhow::Error;
use async_trait::async_trait;
use rustls::{server::ClientHello, sign::CertifiedKey};

use crate::types::tls::{Cert, Pem};

/// Trait that the certificate providers should implement
/// It should return a vector of PEM-encoded cert-keys pairs
#[async_trait]
pub trait ProvidesCertificates: Sync + Send + std::fmt::Debug {
    /// Returns a list of certificates in PEM format
    async fn get_certificates(&self) -> Result<Vec<Pem>, Error>;
}

pub trait StoresCertificates<T: Clone + Send + Sync>: Send + Sync {
    fn store(&self, cert_list: Vec<Cert<T>>) -> Result<(), Error>;
}

/// Custom `ResolvesServerCert` trait that borrows `ClientHello`.
/// It's needed because Rustls' `ResolvesServerCert` consumes `ClientHello`
/// <https://github.com/rustls/rustls/issues/1908>
pub trait ResolvesServerCert: Debug + Send + Sync {
    fn resolve(&self, client_hello: &ClientHello) -> Option<Arc<CertifiedKey>>;

    /// Return first available certificate, if any.
    /// Can be used as a fallback option.
    fn resolve_any(&self) -> Option<Arc<CertifiedKey>> {
        None
    }
}
