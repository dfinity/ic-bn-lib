pub mod acme;
pub mod sessions;
pub mod tickets;

use std::sync::Arc;

use anyhow::{anyhow, Context};
use fqdn::{Fqdn, FQDN};
use prometheus::Registry;
use rustls::{
    compress::CompressionCache,
    crypto::aws_lc_rs,
    server::{ResolvesServerCert, StoresServerSessions},
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    ServerConfig, TicketSwitcher,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

use crate::http::{ALPN_H1, ALPN_H2};

/// Generic error for now
/// TODO improve
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

// Checks if given host matches any of domains
// If wildcard is true then also checks if host is a direct child of any of domains
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

// Extracts a list of SubjectAlternativeName from a single certificate in DER format, formatted as strings.
// Skips everything except DNSName and IPAddress
pub fn extract_sans_der(cert: &[u8]) -> Result<Vec<String>, Error> {
    let cert = X509Certificate::from_der(cert)
        .context("unable to parse DER-encoded certificate")?
        .1;

    // Extract a list of SANs from the 1st certificate in the chain (the leaf one)
    extract_sans(&cert)
}

// Extracts a list of SubjectAlternativeName from a single certificate, formatted as strings.
// Skips everything except DNSName and IPAddress
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

// Converts raw PEM certificate chain & private key to a CertifiedKey ready to be consumed by Rustls
pub fn pem_convert_to_rustls(key: &[u8], certs: &[u8]) -> Result<CertifiedKey, Error> {
    let (key, certs) = (key.to_vec(), certs.to_vec());

    let key = rustls_pemfile::private_key(&mut key.as_ref())
        .context("unable to read private key")?
        .ok_or_else(|| anyhow!("no private key found"))?;

    // Load the cert chain
    let certs = rustls_pemfile::certs(&mut certs.as_ref())
        .collect::<Result<Vec<_>, _>>()
        .context("unable to read certificate chain")?;

    if certs.is_empty() {
        return Err(anyhow!("no certificates found").into());
    }

    // Parse private key
    let key = aws_lc_rs::sign::any_supported_type(&key).context("unable to parse private key")?;

    Ok(CertifiedKey::new(certs, key))
}

pub fn prepare_server_config(
    resolver: Arc<dyn ResolvesServerCert>,
    session_storage: Arc<dyn StoresServerSessions + Send + Sync>,
    additional_alpn: &[Vec<u8>],
    ticket_lifetime: Duration,
    registry: &Registry,
) -> ServerConfig {
    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Set custom session storage with to allow effective TLS session resumption
    let session_storage = sessions::WithMetrics(session_storage, sessions::Metrics::new(registry));
    cfg.session_storage = Arc::new(session_storage);

    // Enable ticketer to encrypt/decrypt TLS tickets.
    // TicketSwitcher rotates the inner ticketers every `ticket_lifetime`
    // while keeping the previous one available for decryption of tickets
    // issued earlier than `ticket_lifetime` ago.
    let ticketer = tickets::WithMetrics(
        TicketSwitcher::new(ticket_lifetime.as_secs() as u32, move || {
            Ok(Box::new(tickets::Ticketer::new()))
        })
        .unwrap(),
        tickets::Metrics::new(registry),
    );
    cfg.ticketer = Arc::new(ticketer);

    // Enable certificate compression cache.
    // See https://datatracker.ietf.org/doc/rfc8879/ for details
    cfg.cert_compression_cache = Arc::new(CompressionCache::new(1024));

    // Enable ALPN
    cfg.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_H1.to_vec()];
    cfg.alpn_protocols.extend_from_slice(additional_alpn);

    cfg
}

#[cfg(test)]
mod test {
    use fqdn::fqdn;

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
}
