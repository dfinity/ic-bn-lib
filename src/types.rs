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
    Query,
    Call,
    SyncCall,
    ReadState,
    ReadStateSubnet,
}

impl RequestType {
    pub const fn is_call(&self) -> bool {
        matches!(self, Self::Call | Self::SyncCall)
    }
}
