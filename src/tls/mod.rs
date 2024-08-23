pub mod acme;
pub mod sessions;
pub mod tickets;

use anyhow::{anyhow, Context};
use fqdn::{Fqdn, FQDN};
use rustls::{crypto::aws_lc_rs, sign::CertifiedKey};
use std::net::{Ipv4Addr, Ipv6Addr};
use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension, X509Certificate};

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
