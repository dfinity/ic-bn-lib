use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use derive_new::new;
use fqdn::{FQDN, Fqdn};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::smtp::ic::candid;

#[derive(thiserror::Error, Clone, Debug, PartialEq, Eq)]
pub enum EmailAddressError {
    #[error("@ is missing")]
    AtMissing,
    #[error("Domain incorrect: {0}")]
    DomainIncorrect(String),
    #[error("Local part contains a disallowed character: {0:?}")]
    LocalPartIncorrect(char),
}

/// Whether `c` is allowed in the local part of an address.
///
/// This rejects ASCII control characters (in particular CR/LF, which could
/// otherwise enable header injection if this value is ever reconstructed
/// into a raw mail header downstream) and non-ASCII bytes. Everything else -
/// including characters used by RFC 5321 quoted-string local parts like `"`,
/// an `@` within quotes, `+`, `.` - is left as-is, since this type does not
/// otherwise validate local-part syntax.
const fn is_valid_local_part_char(c: char) -> bool {
    c.is_ascii() && !c.is_ascii_control()
}

/// E-Mail address representation.
///
/// Currently we don't validate the local part's syntax at all (beyond
/// rejecting control/non-ASCII characters) and just consider everything to
/// the right from the rightmost @ as a domain part.
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Hash, SerializeDisplay, DeserializeFromStr, new,
)]
pub struct EmailAddress {
    local: String,
    domain: FQDN,
}

impl EmailAddress {
    pub fn from_text(s: &str) -> Result<Self, EmailAddressError> {
        let (local, domain) = s.rsplit_once('@').ok_or(EmailAddressError::AtMissing)?;
        if domain.is_empty() {
            return Err(EmailAddressError::DomainIncorrect("Empty domain".into()));
        }

        if let Some(c) = local.chars().find(|c| !is_valid_local_part_char(*c)) {
            return Err(EmailAddressError::LocalPartIncorrect(c));
        }

        let domain = FQDN::from_ascii_str(domain)
            .map_err(|e| EmailAddressError::DomainIncorrect(e.to_string()))?;

        Ok(Self {
            local: local.into(),
            domain,
        })
    }

    pub fn local(&self) -> &str {
        &self.local
    }

    pub fn domain(&self) -> &Fqdn {
        &self.domain
    }
}

impl Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

impl Debug for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
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

#[cfg(test)]
impl PartialEq<&str> for EmailAddress {
    #[allow(clippy::cmp_owned)]
    fn eq(&self, other: &&str) -> bool {
        self.to_string() == *other
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

        // control characters (e.g. CR/LF) in the local part must be rejected,
        // since this value can end up forwarded downstream verbatim.
        for v in ["foo\r\nbar@baz", "foo\nbar@baz", "foo\0bar@baz"] {
            assert!(matches!(
                EmailAddress::from_str(v).unwrap_err(),
                EmailAddressError::LocalPartIncorrect(_)
            ));
        }

        // non-ASCII in the local part is also rejected
        assert!(matches!(
            EmailAddress::from_str("föö@bar").unwrap_err(),
            EmailAddressError::LocalPartIncorrect(_)
        ));
    }
}
