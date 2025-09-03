use std::{net::IpAddr, str::FromStr, sync::Arc};

use http::Request;

use crate::http::{ConnInfo, headers::X_REAL_IP};

pub mod rate_limiter;
pub mod waf;

/// Extracts IP address from `x-real-ip` header or `ConnInfo` extension
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

#[cfg(test)]
mod test {
    use std::net::SocketAddr;

    use crate::http::server::Addr;

    use super::*;

    #[test]
    fn test_extract_ip_from_request() {
        let addr1 = IpAddr::from_str("10.0.0.1").unwrap();
        let addr2 = IpAddr::from_str("192.168.0.1").unwrap();

        let mut ci = ConnInfo::default();
        ci.remote_addr = Addr::Tcp(SocketAddr::new(addr1, 31337));
        let ci = Arc::new(ci);

        // Header takes precedence
        let req = Request::builder()
            .extension(ci.clone())
            .header(X_REAL_IP, addr2.to_string())
            .body("")
            .unwrap();
        assert_eq!(extract_ip_from_request(&req), Some(addr2));

        // Only ConnInfo
        let req = Request::builder().extension(ci).body("").unwrap();
        assert_eq!(extract_ip_from_request(&req), Some(addr1));

        // Only header
        let req = Request::builder()
            .header(X_REAL_IP, addr2.to_string())
            .body("")
            .unwrap();
        assert_eq!(extract_ip_from_request(&req), Some(addr2));
    }
}
