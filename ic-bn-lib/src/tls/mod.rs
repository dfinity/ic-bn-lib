#[cfg(feature = "acme")]
pub mod acme;
#[cfg(feature = "cert-providers")]
pub mod providers;
pub mod resolver;
pub mod sessions;
pub mod tickets;
pub mod verify;

use std::{fs::read, path::PathBuf, sync::Arc};

use anyhow::{Context, anyhow};
use fqdn::{FQDN, Fqdn};
use ic_bn_lib_common::types::{
    http::{ALPN_H1, ALPN_H2},
    tls::TlsOptions,
};
use prometheus::Registry;
use rustls::{
    ClientConfig, ServerConfig, SupportedProtocolVersion, TicketRotator,
    client::{ClientSessionMemoryCache, Resumption},
    compress::CompressionCache,
    crypto::ring,
    server::ResolvesServerCert,
    sign::CertifiedKey,
};
use rustls_platform_verifier::Verifier;
use std::net::{Ipv4Addr, Ipv6Addr};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

/// Generic error for now
/// TODO improve
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

/// Checks if given host matches any of domains.
/// If wildcard is true then also checks if host is a direct child of any of domains
pub fn sni_matches(host: &Fqdn, domains: &[FQDN], wildcard: bool) -> bool {
    domains
        .iter()
        .any(|x| x == host || (wildcard && Some(x.as_ref()) == host.parent()))
}

fn parse_general_name(name: &GeneralName<'_>) -> Result<Option<String>, Error> {
    let name = match name {
        GeneralName::DNSName(v) => (*v).to_string(),
        GeneralName::IPAddress(v) => match v.len() {
            4 => {
                let b: [u8; 4] = (*v).try_into().unwrap(); // We already checked that it's 4
                let ip = Ipv4Addr::from(b);
                ip.to_string()
            }

            16 => {
                let b: [u8; 16] = (*v).try_into().unwrap(); // We already checked that it's 16
                let ip = Ipv6Addr::from(b);
                ip.to_string()
            }

            _ => return Err(anyhow!("Invalid IP address length {}", v.len()).into()),
        },

        // Ignore other types
        _ => return Ok(None),
    };

    Ok(Some(name))
}

/// Extracts a list of SubjectAlternativeName from a single certificate in DER format, formatted as strings.
/// Skips everything except DNSName and IPAddress
pub fn extract_sans_der(cert: &[u8]) -> Result<Vec<String>, Error> {
    let cert = X509Certificate::from_der(cert)
        .context("unable to parse DER-encoded certificate")?
        .1;

    // Extract a list of SANs from the 1st certificate in the chain (the leaf one)
    extract_sans(&cert)
}

/// Parses the given PEM-encoded certificate (1st if there are more than one) & extracts its validity period.
pub fn extract_validity(mut pem: &[u8]) -> Result<(i64, i64), Error> {
    let certs = rustls_pemfile::certs(&mut pem)
        .collect::<Result<Vec<_>, _>>()
        .context("unable to read certificate")?;

    if certs.is_empty() {
        return Err(anyhow!("no certificates found").into());
    }

    extract_validity_der(&certs[0])
}

/// Parses the given DER-encoded certificate (1st if there are more than one) & extracts its validity period.
pub fn extract_validity_der(der: &[u8]) -> Result<(i64, i64), Error> {
    let cert = X509Certificate::from_der(der)
        .context("unable to parse DER-encoded certificate")?
        .1;

    Ok((
        cert.validity().not_before.timestamp(),
        cert.validity().not_after.timestamp(),
    ))
}

/// Extracts a list of SubjectAlternativeName from a single certificate, formatted as strings.
/// Skips everything except DNSName and IPAddress
pub fn extract_sans(cert: &X509Certificate) -> Result<Vec<String>, Error> {
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            let names = san
                .general_names
                .iter()
                .map(parse_general_name)
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();

            return Ok(names);
        }
    }

    Err(anyhow!("SubjectAlternativeName extension not found").into())
}

/// Converts raw PEM certificate chain & private key to a CertifiedKey ready to be consumed by Rustls.
/// This reads the first private key and ignores any others.
pub fn pem_convert_to_rustls(key: &[u8], certs: &[u8]) -> Result<CertifiedKey, Error> {
    let (key, certs) = (key.to_vec(), certs.to_vec());
    #[allow(clippy::tuple_array_conversions)] // Clippy being stupid here
    let pem = [key, certs].concat();

    pem_convert_to_rustls_single(&pem)
}

/// Converts raw concatenated PEM certificate chain & private key to a CertifiedKey ready to be consumed by Rustls.
/// This reads the first private key and ignores any others.
pub fn pem_convert_to_rustls_single(pem: &[u8]) -> Result<CertifiedKey, Error> {
    let pem = pem.to_vec();

    let key = rustls_pemfile::private_key(&mut pem.as_ref())
        .context("unable to read private key")?
        .ok_or_else(|| anyhow!("no private key found"))?;

    // Load the cert chain
    let certs = rustls_pemfile::certs(&mut pem.as_ref())
        .collect::<Result<Vec<_>, _>>()
        .context("unable to read certificate chain")?;

    if certs.is_empty() {
        return Err(anyhow!("no certificates found").into());
    }

    // Parse private key
    let key = ring::sign::any_supported_type(&key).context("unable to parse private key")?;

    Ok(CertifiedKey::new(certs, key))
}

/// Loads raw concatenated PEM certificate chain & private key and converts to a CertifiedKey ready to be consumed by Rustls.
/// This reads the first private key and ignores any others.
pub fn pem_load_rustls(key: PathBuf, certs: PathBuf) -> Result<CertifiedKey, Error> {
    let key = read(key).context("unable to read private key")?;
    let certs = read(certs).context("unable to read certificate chain")?;
    pem_convert_to_rustls(&key, &certs)
}

/// Loads raw PEM certificate chain & private key and converts to a CertifiedKey ready to be consumed by Rustls.
/// This reads the first private key and ignores any others.
pub fn pem_load_rustls_single(pem: PathBuf) -> Result<CertifiedKey, Error> {
    let pem = read(pem).context("unable to read PEM file")?;
    pem_convert_to_rustls_single(&pem)
}

/// Creates Rustls server config.
/// Must be run in Tokio environment since it spawns a task to record metrics
pub fn prepare_server_config(
    opts: TlsOptions,
    resolver: Arc<dyn ResolvesServerCert>,
    registry: &Registry,
) -> ServerConfig {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&opts.tls_versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Create custom session storage to allow effective TLS session resumption
    let session_storage = Arc::new(sessions::Storage::new(
        opts.sessions_count,
        opts.sessions_tti,
        registry,
    ));
    let session_storage_metrics = session_storage.clone();
    // Spawn metrics runner
    tokio::spawn(async move { session_storage_metrics.metrics_runner().await });
    cfg.session_storage = session_storage;

    // Enable ticketer to encrypt/decrypt TLS tickets.
    // TicketSwitcher rotates the inner ticketers every `ticket_lifetime`
    // while keeping the previous one available for decryption of tickets
    // issued earlier than `ticket_lifetime` ago.
    let ticketer = tickets::WithMetrics(
        TicketRotator::new(opts.ticket_lifetime.as_secs() as u32, move || {
            Ok(Box::new(tickets::Ticketer::new()))
        })
        .unwrap(),
        tickets::Metrics::new(registry),
    );
    cfg.ticketer = Arc::new(ticketer);

    // Enable certificate compression cache.
    // See https://datatracker.ietf.org/doc/rfc8879/ for details
    cfg.cert_compression_cache = Arc::new(CompressionCache::new(8192));

    // Enable ALPN
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];
    cfg.alpn_protocols.extend_from_slice(&opts.additional_alpn);

    cfg
}

pub fn prepare_client_config(tls_versions: &[&'static SupportedProtocolVersion]) -> ClientConfig {
    let cfg = ClientConfig::builder_with_protocol_versions(tls_versions);

    let crypto_provider = rustls::crypto::CryptoProvider::get_default()
        .unwrap()
        .clone();

    // Use a custom certificate verifier from rustls project that is presumably secure.
    let verifier = Verifier::new_with_extra_roots(
        webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(),
        crypto_provider,
    )
    .unwrap();

    let mut cfg = cfg
        .dangerous() // Nothing really dangerous here
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    // Session resumption
    let store = ClientSessionMemoryCache::new(2048);
    cfg.resumption = Resumption::store(Arc::new(store));
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];

    cfg
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;

    use crate::tests::{TEST_CERT_1, TEST_KEY_1};

    use super::*;

    #[test]
    fn test_sni_matches() {
        let domains = vec![fqdn!("foo1.bar"), fqdn!("foo2.bar"), fqdn!("foo3.bar")];

        // Check direct
        assert!(sni_matches(&fqdn!("foo1.bar"), &domains, false));
        assert!(sni_matches(&fqdn!("foo2.bar"), &domains, false));
        assert!(sni_matches(&fqdn!("foo3.bar"), &domains, false));
        assert!(!sni_matches(&fqdn!("foo4.bar"), &domains, false));

        // Check wildcard
        assert!(sni_matches(&fqdn!("foo1.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("baz.foo1.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("bza.foo1.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("baz.foo2.bar"), &domains, true));
        assert!(sni_matches(&fqdn!("bza.foo2.bar"), &domains, true));

        // Make sure deeper subdomains are not matched
        assert!(!sni_matches(&fqdn!("baz.baz.foo1.bar"), &domains, true));
    }

    #[test]
    fn test_pem_convert_to_rustls_single() {
        let pem = [TEST_KEY_1, TEST_CERT_1].concat();
        let res = pem_convert_to_rustls_single(pem.as_bytes()).unwrap();
        assert!(res.cert.len() == 1);
    }

    #[test]
    fn test_pem_convert_to_rustls() {
        let res = pem_convert_to_rustls(TEST_KEY_1.as_bytes(), TEST_CERT_1.as_bytes()).unwrap();
        assert!(res.cert.len() == 1);
    }

    #[test]
    fn test_prepare_client_config() {
        prepare_client_config(&[&rustls::version::TLS13, &rustls::version::TLS12]);
    }

    #[test]
    fn test_extract_validity() {
        let (from, to) = extract_validity(TEST_CERT_1.as_bytes()).unwrap();
        assert_eq!(from, 1673300396);
        assert_eq!(to, 1988660396);
    }
}
