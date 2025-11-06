use strum::{Display, IntoStaticStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoStaticStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum TargetState {
    Unknown,
    Degraded,
    Healthy,
}
