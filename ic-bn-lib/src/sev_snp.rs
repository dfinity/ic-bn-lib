use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use ahash::RandomState;
use anyhow::Error;
use axum::{extract::State, response::IntoResponse};
use bytes::Bytes;
use http::StatusCode;
use humantime::parse_duration;
use moka::sync::{Cache, CacheBuilder};
use sev::firmware::guest::Firmware;

use crate::parse_size;

/// SEV-SNP CLI
#[derive(clap::Args)]
pub struct SevSnpCli {
    /// Enable SEV-SNP measurement reporting
    #[clap(env, long)]
    pub sev_snp_enable: bool,

    /// Cache TTL for SEV-SNP reports
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub sev_snp_cache_ttl: Duration,

    /// Max cache size for SEV-SNP reports
    #[clap(env, long, default_value = "10m", value_parser = parse_size)]
    pub sev_snp_cache_size: u64,
}

#[derive(Clone)]
pub struct SevSnpState {
    fw: Arc<Mutex<Firmware>>,
    cache: Cache<Bytes, Bytes, RandomState>,
}

const fn weigh_entry(k: &Bytes, v: &Bytes) -> u32 {
    (k.len() + v.len()) as u32
}

impl SevSnpState {
    pub fn new(cache_ttl: Duration, cache_max_size: u64) -> Result<Self, Error> {
        Ok(Self {
            fw: Arc::new(Mutex::new(Firmware::open()?)),
            cache: CacheBuilder::new(cache_max_size)
                .time_to_live(cache_ttl)
                .weigher(weigh_entry)
                .build_with_hasher(RandomState::new()),
        })
    }
}

pub async fn handler(
    State(state): State<SevSnpState>,
    body: Bytes,
) -> Result<impl IntoResponse, impl IntoResponse> {
    if body.len() != 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "The input data should be exactly 64 bytes".into(),
        ));
    }

    // Check if we have the report in the cache
    if let Some(v) = state.cache.get(&body) {
        return Ok(v);
    }

    // SAFETY: We already made sure body is 64 bytes
    let data: [u8; 64] = body.as_ref().try_into().unwrap();

    // `get_report()` performs a blocking ioctl to the SEV-SNP firmware
    // device. Run it on a blocking thread rather than tying up a tokio
    // worker thread (and every other concurrent request waiting on the same
    // `Mutex`) for the duration of the syscall.
    let fw = state.fw.clone();
    let report = tokio::task::spawn_blocking(move || {
        let mut fw = fw.lock().unwrap();
        fw.get_report(None, Some(data), Some(1))
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Attestation report task failed: {e}"),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to create attestation report: {e}"),
        )
    })?;

    // Store the report in the cache
    let report = Bytes::from(report);
    state.cache.insert(body, report.clone());

    Ok(report)
}
