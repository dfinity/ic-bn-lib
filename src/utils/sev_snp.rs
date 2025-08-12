use std::sync::{Arc, Mutex};

use anyhow::Error;
use axum::{extract::State, response::IntoResponse};
use bytes::Bytes;
use http::StatusCode;
use sev::firmware::guest::Firmware;

#[derive(Clone)]
pub struct SevSnpState {
    fw: Arc<Mutex<Firmware>>,
}

impl SevSnpState {
    pub fn new(cache_ttl: Duration) -> Result<Self, Error> {
        Ok(Self {
            fw: Arc::new(Mutex::new(Firmware::open()?)),
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

    let data: [u8; 64] = body.as_ref().try_into().unwrap();

    let report = state
        .fw
        .lock()
        .unwrap()
        .get_report(None, Some(data), Some(1))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unable to create attestation report: {e}"),
            )
        })?;

    Ok(report)
}
