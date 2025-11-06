use std::{ops::Deref, sync::Arc, time::Duration};

use rustls::{
    SupportedProtocolVersion,
    sign::CertifiedKey,
    version::{TLS12, TLS13},
};

/// A single PEM-encoded certificate+private key pair
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pem(pub Vec<u8>);

impl Deref for Pem {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

/// Generic certificate and a list of its SANs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert<T: Clone + Send + Sync> {
    pub san: Vec<String>,
    pub not_after: i64,
    pub cert: T,
}

/// Commonly used concrete type of the above for Rustls
pub type CertKey = Cert<Arc<CertifiedKey>>;

/// Certificate and private key pair issued by ACME
pub struct AcmeCert {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

pub struct TlsOptions {
    pub additional_alpn: Vec<Vec<u8>>,
    pub sessions_count: u64,
    pub sessions_tti: Duration,
    pub ticket_lifetime: Duration,
    pub tls_versions: Vec<&'static SupportedProtocolVersion>,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            additional_alpn: vec![],
            sessions_count: 1024,
            sessions_tti: Duration::from_secs(3600),
            ticket_lifetime: Duration::from_secs(3600),
            tls_versions: vec![&TLS13, &TLS12],
        }
    }
}
