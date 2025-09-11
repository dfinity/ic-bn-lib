use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, IntoStaticStr};

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
    CallV2,
    CallV3,
    CallV4,
    ReadStateV2,
    ReadStateV3,
    ReadStateSubnetV2,
    ReadStateSubnetV3,
}

impl RequestType {
    pub const fn is_query(&self) -> bool {
        matches!(self, Self::QueryV2 | Self::QueryV3)
    }

    pub const fn is_call(&self) -> bool {
        matches!(self, Self::CallV2 | Self::CallV3 | Self::CallV4)
    }
}

/// Generic trait that allows components to signal their health status
pub trait Healthy: Send + Sync + Debug + 'static {
    fn healthy(&self) -> bool;
}
