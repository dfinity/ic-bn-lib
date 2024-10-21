use std::str::FromStr;

use anyhow::{anyhow, Context};
use clap::Args;
use humantime::parse_duration;

use super::sharded::TypeLatency;
use crate::{types::RequestType, Error};

#[derive(Args)]
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

    /// 1-minute load average where to start shedding
    #[clap(env, long)]
    pub shed_system_load_avg_1: Option<f64>,

    /// 5-minute load average where to start shedding
    #[clap(env, long)]
    pub shed_system_load_avg_5: Option<f64>,

    /// 15-minute load average where to start shedding
    #[clap(env, long)]
    pub shed_system_load_avg_15: Option<f64>,
}

impl FromStr for TypeLatency<RequestType> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rtype, lat) = s
            .split_once(":")
            .ok_or_else(|| anyhow!("incorrect format"))?;
        let rtype = RequestType::from_str(rtype).context("unknown request type")?;
        let lat = parse_duration(lat).context("unable to parse latency")?;

        Ok(Self(rtype, lat))
    }
}

#[derive(Args)]
pub struct ShedSharded {
    /// EWMA alpha coefficient in [0.0, 1.0] range.
    /// It represents the weight of the more recent measurements relative to the older ones.
    #[clap(env, long, default_value = "0.8")]
    pub shed_sharded_ewma: f64,

    /// Number of initial requests to pass through without shedding.
    /// This allows for a gradual load build up avoiding false positives.
    #[clap(env, long, default_value = "1000")]
    pub shed_sharded_passthrough: u64,

    /// Request type and target latency, colon separated e.g. "query:100ms".
    /// This specifies target latency for Little's load-shedding algorithm for a given request type.
    /// Can be specified several times.
    /// Important: if the request type is not specified in the list then it's not shedded at all.
    #[clap(env, long, value_delimiter = ',')]
    pub shed_sharded_latency: Vec<TypeLatency<RequestType>>,
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

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
