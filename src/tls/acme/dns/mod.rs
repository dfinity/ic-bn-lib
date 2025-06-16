pub mod cloudflare;

use std::{
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Error, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use core::fmt;
use derive_new::new;
use fqdn::FQDN;
use instant_acme::AccountCredentials;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use strum_macros::{Display, EnumString};
use tokio::fs;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{
    RetryError,
    http::dns::Resolves,
    retry_async,
    tasks::Run,
    tls::{
        acme::client::{AcmeUrl, Client, ClientBuilder},
        extract_sans, pem_convert_to_rustls_single, sni_matches,
    },
};

use super::TokenManager;

const ACME_RECORD: &str = "_acme-challenge";
const FILE_CERT: &str = "cert.pem";

// 60s is the lowest possible Cloudflare TTL
const TTL: u32 = 60;

#[derive(Clone, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum DnsBackend {
    Cloudflare,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    Txt(String),
}

#[async_trait]
pub trait DnsManager: Sync + Send {
    async fn create(&self, zone: &str, name: &str, record: Record, ttl: u32) -> Result<(), Error>;
    async fn delete(&self, zone: &str, name: &str) -> Result<(), Error>;
}

/// Manages ACME tokens using DNS.
/// It creates `_acme-challenge` TXT records and verifies
/// if they can be resolved using the provided resolver.
#[derive(new)]
pub struct TokenManagerDns {
    resolver: Arc<dyn Resolves>,
    manager: Arc<dyn DnsManager>,
}

#[async_trait]
impl TokenManager for TokenManagerDns {
    async fn verify(&self, zone: &str, token: &str) -> Result<(), Error> {
        // Try to resolve the hostname with backoff and verify that the record is there and correct.
        // Retry for up to double the DNS TTL.

        let host = format!("{ACME_RECORD}.{zone}");
        retry_async! {
        async {
            self.resolver.flush_cache();

            // Get all TXT records for given hostname
            let records = self
                .resolver
                .resolve(&host, "TXT")
                .await
                .map_err(|e| RetryError::Transient(e.into()))?;

            // See if any of them matches given token
            records
                .iter()
                .find(|&x| x.0 == "TXT" && x.1 == token)
                .ok_or_else(|| RetryError::Transient(anyhow!("requested record not found")))?;

            Ok(())
        }, Duration::from_secs(2 * TTL as u64)}
    }

    async fn set(&self, zone: &str, token: &str) -> Result<(), Error> {
        self.manager
            .create(zone, ACME_RECORD, Record::Txt(token.into()), TTL)
            .await
    }

    async fn unset(&self, zone: &str) -> Result<(), Error> {
        self.manager.delete(zone, ACME_RECORD).await
    }
}

#[derive(Debug, Clone, Display, EnumString, PartialEq, Eq)]
pub enum Validity {
    Missing,
    Expires,
    SANMismatch,
    Valid,
}

#[derive(Debug, Clone, Display, EnumString, PartialEq, Eq)]
pub enum RefreshResult {
    StillValid,
    Refreshed,
}

pub struct AcmeDns {
    client: Arc<Client>,
    path: PathBuf,
    domains: Vec<FQDN>,
    names: Vec<String>,
    wildcard: bool,
    renew_before: Duration,
    cert: ArcSwapOption<CertifiedKey>,
}

pub struct Opts {
    pub acme_url: AcmeUrl,
    pub path: PathBuf,
    pub domains: Vec<FQDN>,
    pub wildcard: bool,
    pub renew_before: Duration,
    pub account_credentials: Option<AccountCredentials>,
    pub token_manager: Arc<dyn TokenManager>,
    pub insecure_tls: bool,
}

impl AcmeDns {
    pub async fn new(opts: Opts) -> Result<Self, Error> {
        let mut builder = ClientBuilder::new(opts.insecure_tls)
            .with_acme_url(opts.acme_url)
            .with_token_manager(opts.token_manager);
        let account_path = opts.path.join("account.json");

        // Generate a list of identifiers for a certificate
        let mut names = opts
            .domains
            .clone()
            .into_iter()
            .flat_map(|x| {
                let x = x.to_string();
                let mut out = vec![x.clone()];
                if opts.wildcard {
                    out.push(format!("*.{x}"));
                }
                out.into_iter()
            })
            .collect::<Vec<_>>();
        names.sort();

        // If creds were provided - use them
        if let Some(v) = opts.account_credentials {
            builder = builder
                .load_account(v)
                .await
                .context("unable to load ACME account")?;
        } else if let Ok(v) = fs::read(&account_path).await {
            // Otherwise first try to load them from file
            let creds: AccountCredentials =
                serde_json::from_slice(&v).context("unable to parse ACME account credentials")?;

            builder = builder
                .load_account(creds)
                .await
                .context("unable to load ACME account")?;
        } else {
            // Finally just create a new account
            let (builder2, creds) = builder
                .create_account("mailto:boundary-nodes@dfinity.org")
                .await
                .context("unable to create ACME account")?;
            builder = builder2;

            // Save the credentials to file
            let creds = serde_json::to_vec_pretty(&creds)
                .context("unable to serialize ACME credentials to JSON")?;
            fs::write(&account_path, creds)
                .await
                .context("unable to save ACME credentials to file")?;
        }

        let client = Arc::new(
            builder
                .build()
                .await
                .context("unable to create ACME client")?,
        );

        Ok(Self {
            client,
            path: opts.path,
            domains: opts.domains,
            names,
            wildcard: opts.wildcard,
            renew_before: opts.renew_before,
            cert: ArcSwapOption::empty(),
        })
    }

    /// Loads the certificates from files into storage
    async fn load(&self) -> Result<(), Error> {
        let cert_and_key = fs::read(self.path.join(FILE_CERT))
            .await
            .context("unable to read cert")?;

        let ckey = pem_convert_to_rustls_single(&cert_and_key)
            .context("unable to convert certificate to Rustls format")?;

        self.cert.store(Some(Arc::new(ckey)));
        Ok(())
    }

    /// Checks if the certificate in the storage (if any) is still valid and issued for our domains
    pub async fn is_valid(&self) -> Result<Validity, Error> {
        let Some(ckey) = self.cert.load_full() else {
            return Ok(Validity::Missing);
        };

        if ckey.cert.is_empty() {
            return Ok(Validity::Missing);
        }

        let cert = X509Certificate::from_der(ckey.cert[0].as_ref())
            .context("Unable to parse DER-encoded certificate")?
            .1;

        // Check if it's time to renew
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let left = (cert.validity().not_after.timestamp() as u64).saturating_sub(now);
        if left < self.renew_before.as_secs() {
            return Ok(Validity::Expires);
        }

        // Check if cert's SANs match the domains that we have
        let mut sans = extract_sans(&cert)?;
        sans.sort();
        if sans != self.names {
            return Ok(Validity::SANMismatch);
        }

        Ok(Validity::Valid)
    }

    /// Checks if certificate is still valid & reissues if needed
    async fn refresh(&self) -> Result<RefreshResult, Error> {
        // Try to load certificate from disk first
        if self.cert.load_full().is_none() {
            let _ = self.load().await;
        }

        let validity = self.is_valid().await.context("unable to check validity")?;
        if validity == Validity::Valid {
            debug!("ACME-DNS: Certificate is still valid");
            return Ok(RefreshResult::StillValid);
        }

        debug!("ACME-DNS: Certificate validity is '{validity}', renewing");

        let cert = self
            .client
            .issue(&self.names, None)
            .await
            .context("unable to issue a certificate")?;

        let cert_and_key = [cert.cert, cert.key].concat();
        fs::write(self.path.join(FILE_CERT), &cert_and_key)
            .await
            .context("unable to store certificate")?;

        self.load()
            .await
            .context("unable to load certificate from disk")?;

        Ok(RefreshResult::Refreshed)
    }
}

impl fmt::Debug for AcmeDns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AcmeDns")
    }
}

/// Implement certificate resolving for Rustls
impl ResolvesServerCert for AcmeDns {
    fn resolve(&self, ch: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = FQDN::from_str(ch.server_name()?).ok()?;
        // Make sure SNI matches our domains
        sni_matches(&sni, &self.domains, self.wildcard).then_some(self.cert.load_full())?
    }
}

#[async_trait]
impl Run for AcmeDns {
    async fn run(&self, _: CancellationToken) -> Result<(), Error> {
        self.refresh()
            .await
            .context("unable to refresh")
            .map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;
    use tempdir::TempDir;

    use super::*;
    use crate::{
        tests::pebble::{Env, dns::TokenManagerPebble},
        tls::extract_sans_der,
    };

    #[ignore]
    #[tokio::test]
    async fn test_acme_dns() {
        let pebble_env = Env::new();
        let dir = TempDir::new("test_acme_dns").unwrap();

        let token_manager = Arc::new(TokenManagerPebble::new(
            format!("http://{}", pebble_env.addr_dns_management())
                .parse()
                .unwrap(),
        ));

        let resolver = pebble_env.resolver();
        let token_manager_dns = Arc::new(TokenManagerDns::new(resolver, token_manager));

        let opts = Opts {
            acme_url: AcmeUrl::Custom(
                format!("https://{}/dir", pebble_env.addr_acme())
                    .parse()
                    .unwrap(),
            ),
            path: dir.path().to_path_buf(),
            domains: vec![fqdn!("foo")],
            wildcard: true,
            renew_before: Duration::from_secs(30),
            account_credentials: None,
            token_manager: token_manager_dns,
            insecure_tls: true,
        };

        let acme_dns = AcmeDns::new(opts).await.unwrap();
        assert_eq!(acme_dns.refresh().await.unwrap(), RefreshResult::Refreshed);
        let cert = acme_dns.cert.load_full().unwrap();
        let mut sans = extract_sans_der(cert.end_entity_cert().unwrap()).unwrap();
        sans.sort();
        assert_eq!(sans, vec!["*.foo", "foo"]);

        assert_eq!(acme_dns.refresh().await.unwrap(), RefreshResult::StillValid);
        let cert = acme_dns.cert.load_full().unwrap();
        let mut sans = extract_sans_der(cert.end_entity_cert().unwrap()).unwrap();
        sans.sort();
        assert_eq!(sans, vec!["*.foo", "foo"]);
    }
}
