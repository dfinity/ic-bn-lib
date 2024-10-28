use std::fmt::Debug;

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
)]
#[strum(serialize_all = "snake_case")]
pub enum RequestType {
    #[default]
    Status,
    Query,
    Call,
    SyncCall,
    ReadState,
    ReadStateSubnet,
}
