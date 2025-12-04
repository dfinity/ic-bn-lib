use std::{io, path::PathBuf, sync::Arc};

use anyhow::Error;
use async_trait::async_trait;
use futures::StreamExt;
use ic_bn_lib_common::{traits::Run, types::acme::AcmeUrl};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_acme::{
    AcmeConfig, AcmeState, ResolvesServerCertAcme, caches::DirCache,
    futures_rustls::rustls::ClientConfig,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::warn;

#[derive(derive_new::new)]
pub struct Opts {
    pub acme_url: AcmeUrl,
    pub domains: Vec<String>,
    pub contact: String,
    pub cache_path: PathBuf,
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
        .contact_push(opts.contact)
        .directory(opts.acme_url.to_string());

        let state = state.cache(DirCache::new(opts.cache_path)).state();
        let resolver = state.resolver();

        Self(Mutex::new(state), resolver)
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
