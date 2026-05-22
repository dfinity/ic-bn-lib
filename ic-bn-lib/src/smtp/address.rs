use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use fqdn::{FQDN, Fqdn};

use crate::smtp::ic::candid;

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EmailAddress {
    local: String,
    domain: FQDN,
    domain_str: String,
}

impl EmailAddress {
    pub fn new(local: String, domain: FQDN) -> Self {
        Self {
            local,
            domain_str: domain.to_string(),
            domain,
        }
    }

    pub fn from_text(s: &str) -> Result<Self, EmailAddressError> {
        let (local, domain) = s.rsplit_once('@').ok_or(EmailAddressError::AtMissing)?;
        if domain.is_empty() {
            return Err(EmailAddressError::DomainIncorrect("Empty domain".into()));
        }

        let domain = FQDN::from_ascii_str(domain)
            .map_err(|e| EmailAddressError::DomainIncorrect(e.to_string()))?;

        Ok(Self {
            local: local.into(),
            domain_str: domain.to_string(),
            domain,
        })
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub fn domain(&self) -> &Fqdn {
        &self.domain
    }

    pub fn domain_str(&self) -> &str {
        &self.domain_str
    }
}

impl Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain_str)
    }
}

impl Debug for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain_str)
    }
}

impl FromStr for EmailAddress {
    type Err = EmailAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_text(s)
    }
}

impl TryFrom<&str> for EmailAddress {
    type Error = EmailAddressError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl From<&EmailAddress> for candid::Address {
    fn from(v: &EmailAddress) -> Self {
        v.clone().into()
    }
}

impl From<EmailAddress> for candid::Address {
    fn from(v: EmailAddress) -> Self {
        Self {
            user: v.local,
            domain: v.domain.to_string(),
        }
    }
}

impl PartialEq<&str> for EmailAddress {
    fn eq(&self, other: &&str) -> bool {
        other
            .rsplit_once('@')
            .is_some_and(|(local, domain)| local == self.local && domain == self.domain_str)
    }
}

#[cfg(test)]
mod tests {
    use crate::email;

    use super::*;

    #[test]
    fn test_email_address() {
        // ok
        for v in ["foo@bar", "john.doe@jane.doe", "\"foo+bar@baz\"@dead.beef"] {
            assert_eq!(EmailAddress::from_str(v).unwrap().to_string(), v);
        }
        assert_eq!(email!("foo@bar"), "foo@bar");

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
