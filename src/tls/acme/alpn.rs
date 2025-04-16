use std::{io, sync::Arc};

use anyhow::Error;
use futures::StreamExt;
use rustls::server::ResolvesServerCert;
use rustls_acme::{AcmeConfig, AcmeState, caches::DirCache};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::AcmeOptions;

struct Runner(AcmeState<io::Error, io::Error>, CancellationToken);

pub fn new(opts: AcmeOptions, token: CancellationToken) -> Arc<dyn ResolvesServerCert> {
    let state = AcmeConfig::new(opts.domains)
        .contact_push(opts.contact)
        .directory_lets_encrypt(!opts.staging);

    let state = state.cache(DirCache::new(opts.cache_path)).state();
    let resolver = state.resolver();

    let mut runner = Runner(state, token);
    tokio::spawn(async move { runner.run().await });

    resolver
}

impl Runner {
    async fn run(&mut self) -> Result<(), Error> {
        warn!("ACME-ALPN: started");

        loop {
            tokio::select! {
                biased; // Poll top-down

                () = self.1.cancelled() => {
                    warn!("ACME-ALPN: exiting");
                    return Ok(());
                },

                // Kick the ACME process forward
                x = self.0.next() => {
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
