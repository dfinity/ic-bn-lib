use std::{fmt::Display, ops::BitOrAssign, str::FromStr};

use anyhow::anyhow;

use crate::Error;

/// Flag that signifies that this domain should be passed
/// through the pre-rendering service.
pub const FLAG_PRERENDER: DomainFlag = DomainFlag(1 << 0);
/// Used only in tests
pub const FLAG_TEST: DomainFlag = DomainFlag(1 << 31);

const FLAGS: [(DomainFlag, &str); 2] = [(FLAG_PRERENDER, "prerender"), (FLAG_TEST, "test")];

/// Single flag
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainFlag(u32);

impl FromStr for DomainFlag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for (flag, name) in FLAGS {
            if s == name {
                return Ok(flag);
            }
        }

        Err(anyhow!("unknown flag {s}").into())
    }
}

impl Display for DomainFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (flag, name) in FLAGS {
            if *self == flag {
                return write!(f, "{}", name);
            }
        }

        write!(f, "unknown")
    }
}

/// Bitmask with flags
#[derive(Clone, Default, Copy, Debug, PartialEq, Eq)]
pub struct DomainFlags(u32);

impl DomainFlags {
    pub fn new(flags_in: impl IntoIterator<Item = DomainFlag>) -> Self {
        let mut flags = Self::default();
        for x in flags_in.into_iter() {
            flags.set_flag(x);
        }

        flags
    }

    pub const fn has_flag(&self, f: DomainFlag) -> bool {
        self.0 & f.0 != 0
    }

    pub fn set_flag(&mut self, f: DomainFlag) {
        *self |= f
    }

    pub const fn unset_flag(&mut self, f: DomainFlag) {
        self.0 &= !f.0;
    }
}

impl BitOrAssign<DomainFlag> for DomainFlags {
    fn bitor_assign(&mut self, rhs: DomainFlag) {
        self.0 |= rhs.0;
    }
}

impl FromStr for DomainFlags {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut flags = Self::default();
        for x in s.split('|') {
            let flag = DomainFlag::from_str(x.trim())?;
            flags.set_flag(flag);
        }

        Ok(flags)
    }
}

impl Display for DomainFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::with_capacity(self.0.count_ones() as usize);

        for (flag, name) in FLAGS {
            if self.has_flag(flag) {
                flags.push(name);
            }
        }

        write!(f, "{}", flags.join("|"))
    }
}

#[cfg(test)]
mod tests {
    use fqdn::fqdn;

    use super::*;
    use crate::{custom_domains::CustomDomain, principal};

    #[test]
    fn test_custom_domain_flags() {
        let mut cd = CustomDomain {
            name: fqdn!("foo"),
            canister_id: principal!("aaaaa-aa"),
            timestamp: 0,
            flags: Some(DomainFlags(0b10010001000000001001000100000000)),
            priority: 0,
        };

        assert!(!cd.has_flag(FLAG_PRERENDER));

        cd.set_flag(FLAG_PRERENDER);
        assert_eq!(cd.flags.unwrap().0, 0b10010001000000001001000100000001);
        assert!(cd.has_flag(FLAG_PRERENDER));

        cd.unset_flag(FLAG_PRERENDER);
        assert_eq!(cd.flags.unwrap().0, 0b10010001000000001001000100000000);
        assert!(!cd.has_flag(FLAG_PRERENDER));

        assert_eq!(
            DomainFlags::new([FLAG_PRERENDER, FLAG_TEST]).to_string(),
            "prerender|test"
        );

        let flags = DomainFlags::from_str("test | prerender").unwrap();
        assert!(flags.has_flag(FLAG_PRERENDER));
        assert!(flags.has_flag(FLAG_TEST));

        assert!(DomainFlags::from_str("test|prerender|foo").is_err());
    }
}
