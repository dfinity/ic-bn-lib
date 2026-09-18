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

#[cfg(test)]
mod test {
    use std::{str::FromStr, time::Duration};

    use super::*;

    fn opts(url: &str, credentials: Option<Vec<u8>>) -> (tempfile::TempDir, Opts) {
        let dir = tempfile::tempdir().unwrap();

        let opts = Opts::new(
            AcmeUrl::from_str(url).unwrap(),
            vec!["foo.bar".to_string(), "baz.bar".to_string()],
            "admin@foo.bar".to_string(),
            dir.path().to_path_buf(),
            credentials,
            None,
        );

        (dir, opts)
    }

    #[tokio::test]
    async fn test_stub_account_cache() {
        let cache = StubAccountCache(vec![1, 2, 3]);

        // The predefined account is given out regardless of the arguments
        assert_eq!(
            cache.load_account(&[], "").await.unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            cache
                .load_account(
                    &["mailto:admin@foo.bar".to_string()],
                    "https://acme.foo/directory"
                )
                .await
                .unwrap(),
            Some(vec![1, 2, 3])
        );

        // Storing is a noop & doesn't affect what's loaded afterwards
        cache
            .store_account(
                &["mailto:admin@foo.bar".to_string()],
                "https://acme.foo",
                &[9, 9, 9],
            )
            .await
            .unwrap();
        assert_eq!(
            cache.load_account(&[], "").await.unwrap(),
            Some(vec![1, 2, 3])
        );

        // Empty credentials are given out as an empty vector, not as None
        assert_eq!(
            StubAccountCache(vec![])
                .load_account(&[], "")
                .await
                .unwrap(),
            Some(vec![])
        );
    }

    #[test]
    fn test_acme_alpn_new() {
        // Rustls-ACME defaults to the LE staging directory, so using the production
        // one makes sure that our URL is actually applied.
        let (_dir, o) = opts("le_prod", None);
        let dbg = format!("{:?}", AcmeAlpn::new(o));
        assert!(
            dbg.contains("https://acme-v02.api.letsencrypt.org/directory"),
            "{dbg}"
        );
        assert!(!dbg.contains("staging"), "{dbg}");

        // Domains are passed through as-is & the contact gets a mailto: prefix
        assert!(dbg.contains("\"foo.bar\""), "{dbg}");
        assert!(dbg.contains("\"baz.bar\""), "{dbg}");
        assert!(dbg.contains("\"mailto:admin@foo.bar\""), "{dbg}");

        // A custom directory URL is used verbatim
        let (_dir, o) = opts("http://127.0.0.1:1/directory", Some(b"account".to_vec()));
        let dbg = format!("{:?}", AcmeAlpn::new(o));
        assert!(dbg.contains("http://127.0.0.1:1/directory"), "{dbg}");
    }

    /// The certificate resolver that we hand over to Rustls must be the very same one
    /// that the ACME state pushes the certificates & challenges into.
    #[tokio::test]
    async fn test_acme_alpn_resolver() {
        let (_dir, o) = opts("le_stag", None);
        let acme = AcmeAlpn::new(o);
        let state = acme.0.lock().await;
        assert!(Arc::ptr_eq(&state.resolver(), &acme.1));
    }

    #[tokio::test]
    async fn test_acme_alpn_run_stops_on_cancel() {
        let (_dir, o) = opts("http://127.0.0.1:1/directory", Some(b"account".to_vec()));
        let acme = AcmeAlpn::new(o);

        let token = CancellationToken::new();
        // Cancel upfront: the select! is biased, so the ACME state is never polled
        // and no network access is attempted.
        token.cancel();

        let res = tokio::time::timeout(Duration::from_secs(10), acme.run(token.clone()))
            .await
            .expect("run() did not return after the token was cancelled");
        assert!(res.is_ok(), "{res:?}");

        // The state mutex must be released after run() has returned
        assert!(acme.0.try_lock().is_ok());
    }
}
