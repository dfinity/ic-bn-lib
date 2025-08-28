pub mod dir;
pub mod file;
pub mod issuer;
pub mod storage;

pub use dir::Provider as Dir;
pub use file::Provider as File;
pub use issuer::CertificatesImporter as Issuer;

use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use storage::StoresCertificates;

use crate::{
    tasks::Run,
    tls::{extract_sans_der, pem_convert_to_rustls_single},
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

/// Trait that the certificate providers should implement
/// It should return a vector of PEM-encoded cert-keys pairs
#[async_trait]
pub trait ProvidesCertificates: Sync + Send + std::fmt::Debug {
    /// Returns a list of certificates in PEM format
    async fn get_certificates(&self) -> Result<Vec<Pem>, anyhow::Error>;
}

/// Generic certificate and a list of its SANs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert<T: Clone + Send + Sync> {
    pub san: Vec<String>,
    pub cert: T,
}

/// Commonly used concrete type of the above for Rustls
pub type CertKey = Cert<Arc<CertifiedKey>>;

/// Converts a PEM-encoded cert+key pair into CertKey
pub fn pem_convert_to_certkey(pem: &[u8]) -> Result<CertKey, Error> {
    let cert_key = pem_convert_to_rustls_single(pem)
        .context("unable to convert certificate chain and/or private key from PEM")?;

    let san = extract_sans_der(cert_key.cert[0].as_ref()).context("unable to extract SANs")?;
    if san.is_empty() {
        return Err(anyhow!(
            "no supported names found in SubjectAlternativeName extension"
        ));
    }

    Ok(CertKey {
        san,
        cert: Arc::new(cert_key),
    })
}

/// Snapshot of provider's certificates.
/// Raw PEM format is needed because we can't compare parsed one.
#[derive(Clone, Debug)]
struct AggregatorSnapshot {
    pem: Vec<Option<Vec<Pem>>>,
    parsed: Vec<Option<Vec<CertKey>>>,
}

impl AggregatorSnapshot {
    fn flatten(&self) -> Vec<CertKey> {
        self.parsed
            .clone()
            .into_iter()
            .flatten()
            .flatten()
            .collect()
    }
}

impl PartialEq for AggregatorSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.pem == other.pem
    }
}
impl Eq for AggregatorSnapshot {}

/// Collects certificates from providers and stores them in the provided storage
pub struct Aggregator {
    providers: Vec<Arc<dyn ProvidesCertificates>>,
    storage: Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
    snapshot: Mutex<AggregatorSnapshot>,
}

impl std::fmt::Debug for Aggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CertificateAggregator")
    }
}

/// Convert a list of PEM-encoded certificates to a Vec of CertKeys
fn parse_pem(pem: &[Pem]) -> Result<Vec<CertKey>, Error> {
    pem.iter().map(|x| pem_convert_to_certkey(x)).collect()
}

impl Aggregator {
    pub fn new(
        providers: Vec<Arc<dyn ProvidesCertificates>>,
        storage: Arc<dyn StoresCertificates<Arc<CertifiedKey>>>,
    ) -> Self {
        let snapshot = AggregatorSnapshot {
            pem: vec![None; providers.len()],
            parsed: vec![None; providers.len()],
        };

        Self {
            providers,
            storage,
            snapshot: Mutex::new(snapshot),
        }
    }

    /// Returns true if all providers returned data successfully at least once
    pub fn is_initialized(&self) -> bool {
        self.snapshot
            .lock()
            .unwrap()
            .parsed
            .iter()
            .all(|x| x.is_some())
    }

    /// Fetches certificates concurrently from all providers.
    /// It returns both raw & parsed since parsed don't implement PartialEq and can't be compared.
    async fn fetch(&self, mut snapshot: AggregatorSnapshot) -> AggregatorSnapshot {
        // Go over the providers and try to fetch the certificates
        for (i, p) in self.providers.iter().enumerate() {
            // Update the certificates on successful fetch & parse, otherwise old version will be used if any
            match p.get_certificates().await {
                Ok(pem) => {
                    // Try to parse them first to make sure they're valid
                    match parse_pem(&pem) {
                        Ok(mut parsed) => {
                            parsed.sort_by(|a, b| a.san.cmp(&b.san));

                            // Update the entries in the snapshot
                            snapshot.pem[i] = Some(pem);
                            snapshot.parsed[i] = Some(parsed);
                        }

                        Err(e) => warn!(
                            "{self:?}: failed to parse certificates from provider {p:?}: {e:#}"
                        ),
                    }
                }

                Err(e) => warn!("{self:?}: failed to fetch from provider {p:?}: {e:#}"),
            }
        }

        snapshot
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn refresh(&self) {
        // Get a snapshot of current data to update
        let snapshot_old = self.snapshot.lock().unwrap().clone();

        // Fetch new certificates on top of the old snapshot
        let snapshot = self.fetch(snapshot_old.clone()).await;

        // Check if the new set is different
        if snapshot == snapshot_old {
            debug!("{self:?}: certs haven't changed, not updating");
            return;
        }

        let certs = snapshot.flatten();
        warn!(
            "{self:?}: publishing new snapshot with {} certs",
            certs.len()
        );

        debug!("{self:?}: {} certs fetched:", certs.len());
        for v in &certs {
            debug!("{self:?}: {:?}", v.san);
        }

        // Store the new snapshot
        *self.snapshot.lock().unwrap() = snapshot;

        // Publish to storage
        if let Err(e) = self.storage.store(certs) {
            warn!("{self:?}: error storing certificates: {e:#}");
        }
    }
}

#[async_trait]
impl Run for Aggregator {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        self.refresh().await;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use prometheus::Registry;

    use crate::tests::{TEST_CERT_1, TEST_CERT_2, TEST_KEY_1, TEST_KEY_2};

    use super::*;

    #[derive(Debug)]
    struct TestProvider(Pem, AtomicUsize);

    #[async_trait]
    impl ProvidesCertificates for TestProvider {
        async fn get_certificates(&self) -> Result<Vec<Pem>, Error> {
            if self.1.load(Ordering::SeqCst) == 0 {
                self.1.fetch_add(1, Ordering::SeqCst);
                Ok(vec![self.0.clone()])
            } else {
                Err(anyhow!("foo"))
            }
        }
    }

    #[derive(Debug)]
    struct TestProviderBroken;

    #[async_trait]
    impl ProvidesCertificates for TestProviderBroken {
        async fn get_certificates(&self) -> Result<Vec<Pem>, Error> {
            Err(anyhow!("I'm dead"))
        }
    }

    #[test]
    fn test_pem_convert_to_certkey() -> Result<(), Error> {
        let cert = pem_convert_to_certkey([TEST_KEY_1, TEST_CERT_1].concat().as_bytes())?;
        assert_eq!(cert.san, vec!["novg"]);
        let cert = pem_convert_to_certkey([TEST_KEY_2, TEST_CERT_2].concat().as_bytes())?;
        assert_eq!(cert.san, vec!["devenv-igornovg"]);
        Ok(())
    }

    #[tokio::test]
    async fn test_aggregator() -> Result<(), Error> {
        let prov1 = TestProvider(
            Pem([TEST_KEY_1.as_bytes(), TEST_CERT_1.as_bytes()]
                .concat()
                .to_vec()),
            AtomicUsize::new(0),
        );
        let prov2 = TestProvider(
            Pem([TEST_KEY_2.as_bytes(), TEST_CERT_2.as_bytes()]
                .concat()
                .to_vec()),
            AtomicUsize::new(0),
        );

        let storage = Arc::new(storage::StorageKey::new(
            None,
            storage::Metrics::new(&Registry::new()),
        ));
        let aggregator = Aggregator::new(
            vec![
                Arc::new(prov1),
                Arc::new(prov2),
                Arc::new(TestProviderBroken),
            ],
            storage,
        );
        aggregator.refresh().await;

        let certs = aggregator.snapshot.lock().unwrap().clone().flatten();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].san, vec!["novg"]);
        assert_eq!(certs[1].san, vec!["devenv-igornovg"]);

        // The providers will fail on the 2nd request, make sure the snapshot stays the same
        aggregator.refresh().await;

        let certs = aggregator.snapshot.lock().unwrap().clone().flatten();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].san, vec!["novg"]);
        assert_eq!(certs[1].san, vec!["devenv-igornovg"]);

        Ok(())
    }
}
