use std::{fmt::Display, str::FromStr};

use anyhow::{Context, anyhow};
use cloudflare::endpoints::dns::dns::DnsContent;
use instant_acme::{
    AuthorizationStatus, ChallengeType, Error as AcmeError, Identifier, LetsEncrypt, OrderStatus,
};
use strum::{Display, EnumString};
use url::Url;

/// Challenge type
#[derive(Clone, Display, EnumString, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum Challenge {
    Alpn,
    Dns,
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "le_prod" => Ok(Self::LetsEncryptProduction),
            "le_stag" => Ok(Self::LetsEncryptStaging),
            _ => Ok(Self::Custom(Url::parse(s).context("unable to parse URL")?)),
        }
    }
}

/// Certificate and private key pair issued by ACME
pub struct AcmeCert {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

/// Type of DNS backend to use
#[derive(Clone, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum DnsBackend {
    Cloudflare,
}

/// Record type for DnsManager trait
#[derive(Debug, PartialEq, Eq)]
pub enum Record {
    Txt(String),
}

impl TryFrom<DnsContent> for Record {
    type Error = anyhow::Error;

    fn try_from(value: DnsContent) -> Result<Self, Self::Error> {
        match value {
            DnsContent::TXT { content } => Ok(Self::Txt(content)),
            _ => Err(anyhow!("not supported")),
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

/// Error thet ACME client returns
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unexpected authorization status: {0:?}")]
    UnexpectedAuthorizationStatus(AuthorizationStatus),
    #[error("Unexpected order status: {0:?}")]
    UnexpectedOrderStatus(OrderStatus),
    #[error("Unable to set challenge token: {0}")]
    UnableToSetChallengeToken(anyhow::Error),
    #[error("Unable to unset challenge token: {0}")]
    UnableToUnsetChallengeToken(anyhow::Error),
    #[error("Unable to verify challenge token: {0}")]
    UnableToVerifyChallengeToken(anyhow::Error),
    #[error("Unable to create order: {0}")]
    UnableToCreateOrder(AcmeError),
    #[error("Unable to get authorizations: {0}")]
    UnableToGetAuthorizations(AcmeError),
    #[error("Unable to set challenge as ready: {0}")]
    UnableToSetChallengeReady(AcmeError),
    #[error("Unable to finalize order: {0}")]
    UnableToFinalizeOrder(AcmeError),
    #[error("Unable to get certificate: {0}")]
    UnableToGetCertificate(AcmeError),
    #[error("Unable to generate certificate params: {0}")]
    UnableToGenerateCertificateParams(rcgen::Error),
    #[error("Unable to generate private key: {0}")]
    UnableToGeneratePrivateKey(rcgen::Error),
    #[error("Unable to parse private key: {0}")]
    UnableToParsePrivateKey(rcgen::Error),
    #[error("Unable to create CSR: {0}")]
    UnableToCreateCSR(rcgen::Error),
    #[error("No challenge found: {0:?}")]
    NoChallengeFound(ChallengeType),
    #[error("Unsupported identifier type: {0:?}")]
    UnsupportedIdentifierType(Identifier),
    #[error("Order unable to reach ready status: {0}")]
    OrderUnableToReachReadyStatus(AcmeError),
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

impl Error {
    /// Checks if the error is due to Let's Encrypt rate limiting
    pub fn rate_limited(&self) -> bool {
        let acme_error = match self {
            Self::UnableToCreateOrder(v) => v,
            Self::UnableToGetAuthorizations(v) => v,
            Self::UnableToSetChallengeReady(v) => v,
            Self::UnableToFinalizeOrder(v) => v,
            Self::UnableToGetCertificate(v) => v,
            Self::OrderUnableToReachReadyStatus(v) => v,
            _ => return false,
        };

        if let AcmeError::Api(problem) = acme_error {
            // Check if this is a rate limiting error
            return problem.status == Some(429);
        }

        false
    }
}
