use std::str::FromStr;

use anyhow::{Context, anyhow};
use clap::Args;
use humantime::parse_duration;

use super::{sharded::TypeLatency, system::SystemOptions};
use crate::Error;

/// Generic parser for TypeLatency in "foo:<duration>" format.
/// Supports anything that implements FromStr.
impl<T: FromStr> FromStr for TypeLatency<T>
where
    T::Err: std::error::Error + Send + Sync + Sized + 'static,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rtype, lat) = s
            .split_once(":")
            .ok_or_else(|| anyhow!("incorrect format"))?;

        let rtype = T::from_str(rtype).context("unknown request type")?;
        let lat = parse_duration(lat).context("unable to parse latency")?;

        Ok(Self(rtype, lat))
    }
}

#[derive(Args, Clone, Debug, PartialEq)]
pub struct ShedSystem {
    /// EWMA alpha coefficient in [0.0, 1.0] range.
    /// It represents the weight of the more recent measurements relative to the older ones.
    #[clap(env, long, default_value = "0.8")]
    pub shed_system_ewma: f64,

    /// CPU load where to start shedding, range [0.0, 1.0]
    #[clap(env, long)]
    pub shed_system_cpu: Option<f64>,

    /// Memory usage where to start shedding, range [0.0, 1.0]
    #[clap(env, long)]
    pub shed_system_memory: Option<f64>,

    /// 1-minute load average where to start shedding, range [0.0, inf)
    #[clap(env, long)]
    pub shed_system_load_avg_1: Option<f64>,

    /// 5-minute load average where to start shedding, range [0.0, inf)
    #[clap(env, long)]
    pub shed_system_load_avg_5: Option<f64>,

    /// 15-minute load average where to start shedding, range [0.0, inf)
    #[clap(env, long)]
    pub shed_system_load_avg_15: Option<f64>,
}

impl From<ShedSystem> for SystemOptions {
    fn from(v: ShedSystem) -> Self {
        Self {
            cpu: v.shed_system_cpu,
            memory: v.shed_system_memory,
            loadavg_1: v.shed_system_load_avg_1,
            loadavg_5: v.shed_system_load_avg_5,
            loadavg_15: v.shed_system_load_avg_15,
        }
    }
}

#[derive(Args, Clone, Debug, PartialEq)]
pub struct ShedSharded<T: FromStr + Clone + Send + Sync + 'static>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    /// EWMA alpha coefficient in [0.0, 1.0] range.
    /// It represents the weight of the more recent measurements relative to the older ones.
    #[clap(env, long, default_value = "0.8")]
    pub shed_sharded_ewma: f64,

    /// Number of initial requests to allow through without shedding.
    /// This allows for a gradual load buildup avoiding false positives.
    #[clap(env, long, default_value = "1000")]
    pub shed_sharded_passthrough: u64,

    /// Request types and their target latency, colon separated e.g. "query:100ms".
    /// This specifies target latency for Little's load-shedding algorithm for a given request type.
    /// Can be specified several times.
    /// Important: if the request type is not specified in the list then it's not shedded at all.
    #[clap(env, long, value_delimiter = ',')]
    pub shed_sharded_latency: Vec<TypeLatency<T>>,
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use crate::types::RequestType;

    #[test]
    fn test_type_latency() {
        assert!(TypeLatency::<RequestType>::from_str("foo").is_err());
        assert!(TypeLatency::<RequestType>::from_str(":").is_err());
        assert!(TypeLatency::<RequestType>::from_str("foo:100ms").is_err());
        assert!(TypeLatency::<RequestType>::from_str("query:").is_err());
        assert!(TypeLatency::<RequestType>::from_str("query:1gigasecond").is_err());

        assert_eq!(
            TypeLatency::<RequestType>::from_str("query:100ms").unwrap(),
            TypeLatency::<RequestType>(RequestType::Query, Duration::from_millis(100))
        );

        assert_eq!(
            TypeLatency::<RequestType>::from_str("sync_call:1s").unwrap(),
            TypeLatency::<RequestType>(RequestType::SyncCall, Duration::from_millis(1000))
        );
    }
}
