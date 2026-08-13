use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    str::FromStr,
    sync::Arc,
};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use derive_new::new;
use http::{HeaderMap, header::HeaderValue};
use ipnet::IpNet;

use crate::{
    http::{
        headers::{X_REAL_IP, X_REQUEST_ID},
        server::conn::ConnInfo,
    },
    uuid::Uuid,
};

/// Subnet list that covers the whole IPv4+IPv6 address space
pub const ALL_NETWORKS: [IpNet; 2] = [
    IpNet::new_assert(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    IpNet::new_assert(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
];

/// Client address
#[derive(Debug, Clone, Copy)]
pub struct RemoteAddr(pub IpAddr);

impl Deref for RemoteAddr {
    type Target = IpAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(pub Uuid);

impl Deref for RequestId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Extracts remote IP address from the `ConnInfo` extension.
pub fn extract_network_address<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<Arc<ConnInfo>>()
        .map(|x| x.remote_addr.ip())
}

/// State for [`middleware`]
#[derive(Clone, new)]
pub struct RequestMetaState {
    /// Trust incoming headers from these subnets for the purpose of IP address extraction.
    /// If not set - headers will not be used.
    trust_ip_from: Vec<IpNet>,

    /// Trust incoming headers from these subnets for the purpose of Request ID extraction.
    /// If not set - headers will not be used and a new Request ID will be generated.
    trust_request_id_from: Vec<IpNet>,
}

impl RequestMetaState {
    /// Extracts remote IP address from the `x-real-ip` header if remote is trusted & header exists
    fn extract_ip(&self, headers: &HeaderMap, network_address: &IpAddr) -> Option<IpAddr> {
        // Do we trust this address?
        self.trust_ip_from
            .iter()
            .any(|net| net.contains(network_address))
            .then(|| {
                // If yes - get the IP from the headers if it's there
                headers
                    .get(&X_REAL_IP)
                    .and_then(|x| x.to_str().ok())
                    .and_then(|x| IpAddr::from_str(x).ok())
            })
            .flatten()
    }

    /// Extracts request ID address from the `x-request-id` header if remote is trusted & header exists.
    fn extract_request_id(
        &self,
        headers: &HeaderMap,
        network_address: &IpAddr,
    ) -> Option<RequestId> {
        self.trust_request_id_from
            .iter()
            .any(|net| net.contains(network_address))
            .then(|| {
                headers
                    .get(X_REQUEST_ID)
                    .and_then(|x| x.to_str().ok())
                    .and_then(|x| Uuid::from_str(x).ok())
                    .map(RequestId)
            })
            .flatten()
    }
}

/// Extracts the metadata (request ID & client's IP address) about the request & inserts it as extensions
pub async fn middleware(
    State(state): State<RequestMetaState>,
    mut request: Request,
    next: Next,
) -> Response {
    let network_address = extract_network_address(&request);

    // Extract request ID if trusted or generate a new one
    let request_id = network_address
        .and_then(|ip| state.extract_request_id(request.headers(), &ip))
        .unwrap_or_else(|| RequestId(Uuid::now_v7()));

    // Extract client's IP
    let remote_addr = network_address
        .and_then(|ip| state.extract_ip(request.headers(), &ip))
        .or(network_address)
        .map(RemoteAddr);

    if let Some(v) = remote_addr {
        request.extensions_mut().insert(v);
    }

    let hdr = HeaderValue::from_maybe_shared(Bytes::from(request_id.to_string())).unwrap();

    request.extensions_mut().insert(request_id);
    request.headers_mut().insert(X_REQUEST_ID, hdr.clone());

    let mut response = next.run(request).await;
    response.headers_mut().insert(X_REQUEST_ID, hdr);

    response.extensions_mut().insert(request_id);
    if let Some(v) = remote_addr {
        response.extensions_mut().insert(v);
    }

    response
}
