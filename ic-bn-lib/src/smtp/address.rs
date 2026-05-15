use std::{fmt::Display, str::FromStr};

use derive_new::new;
use fqdn::FQDN;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum EmailAddressError {
    #[error("@ is missing")]
    AtMissing,
    #[error("Domain incorrect: {0}")]
    DomainIncorrect(String),
}

/// E-Mail address representation.
///
/// Currently we don't validate the local part at all
/// and just consider everything to the right from the
/// rightmost @ as a domain part.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, new)]
pub struct EmailAddress {
    pub local: String,
    pub domain: FQDN,
}

impl Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl FromStr for EmailAddress {
    type Err = EmailAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (local, domain) = s.rsplit_once('@').ok_or(EmailAddressError::AtMissing)?;
        if domain.is_empty() {
            return Err(EmailAddressError::DomainIncorrect("Empty domain".into()));
        }

        let domain = FQDN::from_ascii_str(domain)
            .map_err(|e| EmailAddressError::DomainIncorrect(e.to_string()))?;

        Ok(Self {
            local: local.into(),
            domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_address() {
        // ok
        for v in ["foo@bar", "john.doe@jane.doe", "\"foo+bar@baz\"@dead.beef"] {
            assert_eq!(EmailAddress::from_str(v).unwrap().to_string(), v);
        }

        // no @
        assert_eq!(
            EmailAddress::from_str("foo").unwrap_err(),
            EmailAddressError::AtMissing
        );

        // bad domain
        for v in ["foo@bar\"baz", "\"jane@doe\""] {
            assert!(matches!(
                EmailAddress::from_str(v).unwrap_err(),
                EmailAddressError::DomainIncorrect(_)
            ));
        }
    }
}
