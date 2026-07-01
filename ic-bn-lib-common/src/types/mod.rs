pub mod acme;
pub mod dns;
pub mod http;
pub mod shed;
pub mod tls;
pub mod utils;
pub mod vector;

use std::{fmt::Display, ops::BitOrAssign, str::FromStr};

use anyhow::anyhow;
use candid::Principal;
use fqdn::FQDN;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, IntoStaticStr};

use crate::Error;

/// Flag that signifies that this domain should be passed
/// through the pre-rendering service.
pub const FLAG_PRERENDER: DomainFlag = DomainFlag(1 << 0);
/// Used only in tests
pub const FLAG_TEST: DomainFlag = DomainFlag(1 << 31);

const FLAGS: [DomainFlag; 2] = [FLAG_PRERENDER, FLAG_TEST];

/// Single flag
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainFlag(u32);

impl FromStr for DomainFlag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "prerender" => FLAG_PRERENDER,
            "test" => FLAG_TEST,
            _ => return Err(anyhow!("unknown flag {s}").into()),
        })
    }
}

impl Display for DomainFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                FLAG_PRERENDER => "prerender",
                FLAG_TEST => "test",
                _ => "unknown",
            }
        )
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

    pub fn has_flag(&self, f: DomainFlag) -> bool {
        self.0 & f.0 != 0
    }

    pub fn set_flag(&mut self, f: DomainFlag) {
        *self |= f
    }

    pub fn unset_flag(&mut self, f: DomainFlag) {
        self.0 &= !f.0;
    }

    pub fn merge(&mut self, other: DomainFlags) {
        self.0 |= other.0;
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
            let flag = DomainFlag::from_str(x)?;
            flags.set_flag(flag);
        }

        Ok(flags)
    }
}

impl Display for DomainFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = vec![];

        for flag in FLAGS {
            if self.has_flag(flag) {
                flags.push(flag.to_string());
            }
        }

        write!(f, "{}", flags.join(", "))
    }
}

/// Represents a custom domain with a corresponding canister ID
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomDomain {
    pub name: FQDN,
    pub canister_id: Principal,
    /// Opaque timestamp to reflect when the domain was created, can be zero
    pub timestamp: u64,
    pub flags: Option<DomainFlags>,
}

impl CustomDomain {
    pub fn new(name: FQDN, canister_id: Principal) -> Self {
        Self {
            name,
            canister_id,
            timestamp: 0,
            flags: None,
        }
    }

    pub fn has_flag(&self, flag: DomainFlag) -> bool {
        self.flags.is_some_and(|x| x.0 & flag.0 == 1)
    }

    pub fn set_flag(mut self, flag: DomainFlag) -> Self {
        match &mut self.flags {
            Some(v) => v.set_flag(flag),
            None => self.flags = Some(DomainFlags::new([flag])),
        }

        self
    }

    pub fn unset_flag(mut self, flag: DomainFlag) -> Self {
        if let Some(v) = &mut self.flags {
            v.unset_flag(flag)
        }
        self
    }
}

/// Type of IC API request
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    IntoStaticStr,
    EnumString,
    Serialize,
    Deserialize,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    #[default]
    Unknown,
    Status,
    QueryV2,
    QueryV3,
    QuerySubnetV3,
    CallV2,
    CallV3,
    CallV4,
    CallSubnetV4,
    ReadStateV2,
    ReadStateV3,
    ReadStateSubnetV2,
    ReadStateSubnetV3,
}

impl RequestType {
    pub const fn is_query(&self) -> bool {
        matches!(self, Self::QueryV2 | Self::QueryV3 | Self::QuerySubnetV3)
    }

    pub const fn is_call(&self) -> bool {
        matches!(
            self,
            Self::CallV2 | Self::CallV3 | Self::CallV4 | Self::CallSubnetV4
        )
    }

    pub const fn is_read_state(&self) -> bool {
        matches!(
            self,
            Self::ReadStateV2
                | Self::ReadStateV3
                | Self::ReadStateSubnetV2
                | Self::ReadStateSubnetV3
        )
    }
}

#[cfg(test)]
mod tests {
    use fqdn::fqdn;

    use crate::principal;

    use super::*;

    #[test]
    fn test_custom_domain_flags() {
        let mut cd = CustomDomain {
            name: fqdn!("foo"),
            canister_id: principal!("aaaaa-aa"),
            timestamp: 0,
            flags: Some(DomainFlags(0b10010001000000001001000100000000)),
        };

        assert!(!cd.has_flag(FLAG_PRERENDER));

        cd = cd.set_flag(FLAG_PRERENDER);
        assert_eq!(cd.flags.unwrap().0, 0b10010001000000001001000100000001);
        assert!(cd.has_flag(FLAG_PRERENDER));

        cd = cd.unset_flag(FLAG_PRERENDER);
        assert_eq!(cd.flags.unwrap().0, 0b10010001000000001001000100000000);
        assert!(!cd.has_flag(FLAG_PRERENDER));

        assert_eq!(
            DomainFlags::new([FLAG_PRERENDER, FLAG_TEST]).to_string(),
            "prerender, test"
        );

        let mut flags = DomainFlags::new([FLAG_TEST]);
        flags.merge(DomainFlags::new([FLAG_PRERENDER]));
        assert!(flags.has_flag(FLAG_PRERENDER));
        assert!(flags.has_flag(FLAG_TEST));

        let flags = DomainFlags::from_str("test|prerender").unwrap();
        assert!(flags.has_flag(FLAG_PRERENDER));
        assert!(flags.has_flag(FLAG_TEST));

        assert!(DomainFlags::from_str("test|prerender|foo").is_err());
    }
}
