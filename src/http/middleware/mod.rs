use std::{net::IpAddr, str::FromStr, sync::Arc};

use http::Request;

use crate::http::{ConnInfo, headers::X_REAL_IP};

pub mod rate_limiter;
pub mod waf;

/// Extracts IP address from `x-real-ip` header or ConnInfo extension
pub fn extract_ip_from_request<B>(req: &Request<B>) -> Option<IpAddr> {
    // Try to extract from the header first
    req.headers()
        .get(X_REAL_IP)
        .and_then(|x| x.to_str().ok())
        .and_then(|x| IpAddr::from_str(x).ok())
        .or_else(|| {
            // Then, if that failed, from the ConnInfo extension
            req.extensions()
                .get::<Arc<ConnInfo>>()
                .map(|x| x.remote_addr.ip())
        })
}
