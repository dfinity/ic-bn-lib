use std::fmt::Debug;

use strum::{Display, EnumString, IntoStaticStr};

/// Type of IC API request
#[derive(Debug, Clone, Copy, Display, PartialEq, Eq, Hash, IntoStaticStr, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum RequestType {
    Status,
    Query,
    Call,
    SyncCall,
    ReadState,
    ReadStateSubnet,
}
