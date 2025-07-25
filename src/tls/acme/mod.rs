#[cfg(feature = "acme-alpn")]
pub mod alpn;
#[cfg(feature = "acme")]
pub mod client;
#[cfg(feature = "acme-dns")]
pub mod dns;

use std::{fmt::Display, str::FromStr};

use anyhow::{Context, Error};
use async_trait::async_trait;
use instant_acme::LetsEncrypt;
use strum_macros::{Display, EnumString};

#[cfg(feature = "acme")]
pub use instant_acme;
use url::Url;

#[derive(Clone, Display, EnumString, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum Challenge {
    Alpn,
    Dns,
}

#[async_trait]
pub trait TokenManager: Sync + Send {
    async fn set(&self, id: &str, token: &str) -> Result<(), Error>;
    async fn unset(&self, id: &str) -> Result<(), Error>;
    async fn verify(&self, id: &str, token: &str) -> Result<(), Error>;
}

/// Type of ACME server.
/// Can be either Prod or Staging LetsEncrypt or a custom one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeUrl {
    LetsEncryptStaging,
    LetsEncryptProduction,
    Custom(Url),
}

impl Display for AcmeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LetsEncryptStaging => write!(f, "{}", LetsEncrypt::Staging.url()),
            Self::LetsEncryptProduction => write!(f, "{}", LetsEncrypt::Production.url()),
            Self::Custom(v) => write!(f, "{v}"),
        }
    }
}

impl FromStr for AcmeUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "le_prod" => Ok(Self::LetsEncryptProduction),
            "le_stag" => Ok(Self::LetsEncryptStaging),
            _ => Ok(Self::Custom(Url::parse(s).context("unable to parse URL")?)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_acme_url() {
        assert_eq!(
            AcmeUrl::from_str("le_prod").unwrap(),
            AcmeUrl::LetsEncryptProduction
        );
        assert_eq!(
            AcmeUrl::from_str("le_stag").unwrap(),
            AcmeUrl::LetsEncryptStaging
        );
        assert_eq!(
            AcmeUrl::from_str("https://foo.bar/dir").unwrap(),
            AcmeUrl::Custom("https://foo.bar/dir".parse().unwrap())
        );
        assert!(AcmeUrl::from_str("123#3##!").is_err());
    }
}
