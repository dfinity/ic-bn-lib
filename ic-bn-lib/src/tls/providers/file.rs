use std::path::PathBuf;

use anyhow::{Context, Error};
use async_trait::async_trait;
use ic_bn_lib_common::{traits::tls::ProvidesCertificates, types::tls::Pem};

/// Loads the certificate chain & private key from provided PEM-encoded file
#[derive(derive_new::new)]
pub struct Provider {
    path: PathBuf,
}

impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileProvider({})", self.path.to_str().unwrap_or(""))
    }
}

#[async_trait]
impl ProvidesCertificates for Provider {
    async fn get_certificates(&self) -> Result<Vec<Pem>, Error> {
        let pem = std::fs::read(&self.path).context("unable to read the PEM file")?;
        Ok(vec![Pem(pem)])
    }
}

#[cfg(test)]
mod test {
    use crate::tests::{TEST_CERT_1, TEST_KEY_1};

    use super::*;

    #[tokio::test]
    async fn test() -> Result<(), Error> {
        let dir = tempfile::tempdir()?;

        let pemfile = dir.path().join("foobar.pem");
        let pem = [TEST_KEY_1, TEST_CERT_1].concat();
        std::fs::write(&pemfile, pem.as_bytes())?;

        let prov = Provider::new(pemfile);
        let certs = prov.get_certificates().await?;

        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].0, pem.as_bytes());

        Ok(())
    }
}
