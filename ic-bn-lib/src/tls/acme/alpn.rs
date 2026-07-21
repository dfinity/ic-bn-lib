use std::{io, path::PathBuf, sync::Arc};

use anyhow::Error;
use async_trait::async_trait;
use futures::StreamExt;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{
    AccountCache, AcmeConfig, AcmeState, ResolvesServerCertAcme, caches::DirCache,
    futures_rustls::rustls::ClientConfig,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{tasks::Run, tls::acme::AcmeUrl};

/// Simple AccountCache implementation that just gives out a predefined account.
/// Store is a noop.
struct StubAccountCache(Vec<u8>);

#[async_trait]
impl AccountCache for StubAccountCache {
    type EA = std::io::Error;

    async fn load_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
    ) -> Result<Option<Vec<u8>>, Self::EA> {
        Ok(Some(self.0.clone()))
    }

    async fn store_account(
        &self,
        _contact: &[String],
        _directory_url: &str,
        _account: &[u8],
    ) -> Result<(), Self::EA> {
        Ok(())
    }
}

#[derive(derive_new::new)]
pub struct Opts {
    pub acme_url: AcmeUrl,
    pub domains: Vec<String>,
    pub contact: String,
    pub cache_path: PathBuf,
    pub account_credentials: Option<Vec<u8>>,
    pub tls_config: Option<ClientConfig>,
}

/// ACME client that obtains certificates using TLS-ALPN-01 challenge.
/// Must be used as a rustls certificate resolver.
#[derive(Debug)]
pub struct AcmeAlpn(
    Mutex<AcmeState<io::Error, io::Error>>,
    Arc<ResolvesServerCertAcme>,
);

impl AcmeAlpn {
    pub fn new(opts: Opts) -> Self {
        let state = if let Some(v) = opts.tls_config {
            AcmeConfig::new_with_client_config(opts.domains, Arc::new(v))
        } else {
            AcmeConfig::new(opts.domains)
        }
        .contact_push(format!("mailto:{}", opts.contact))
        .directory(opts.acme_url.to_string());

        let cert_cache = DirCache::new(opts.cache_path);

        // If the credentials were provided - use a stub account cache
        let state = if let Some(v) = opts.account_credentials {
            state.cache_compose(cert_cache, StubAccountCache(v))
        } else {
            state.cache(cert_cache)
        }
        .state();

        let cert_resolver = state.resolver();
        Self(Mutex::new(state), cert_resolver)
    }
}

impl ResolvesServerCert for AcmeAlpn {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.1.resolve(client_hello)
    }
}

#[allow(clippy::significant_drop_tightening)]
#[async_trait]
impl Run for AcmeAlpn {
    async fn run(&self, token: CancellationToken) -> Result<(), Error> {
        // Tokio Mutex here is just to make it Send+Sync
        let mut state = self.0.lock().await;

        warn!("ACME-ALPN: started");
        loop {
            tokio::select! {
                biased; // Poll top-down

                () = token.cancelled() => {
                    warn!("ACME-ALPN: exiting");
                    return Ok(());
                },

                // Kick the ACME process forward
                x = state.next() => {
                    match x {
                        Some(Ok(v)) => warn!("ACME-ALPN: success: {v:?}"),
                        Some(Err(e)) => warn!("ACME-ALPN: error: {e:#}"),
                        _ => warn!("ACME-ALPN: unexpected None"),
                    }
                }
            }
        }
    }
}
