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

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, SocketAddr};

    use axum::{
        Router, body::Body, middleware::from_fn_with_state, response::IntoResponse, routing::get,
    };
    use http::{HeaderName, StatusCode};
    use tower::Service;

    use super::*;
    use crate::{http::server::conn::ConnInfo, hval, network::Addr};

    const X_TEST_REQUEST_ID: &str = "x-test-request-id";
    const X_TEST_REMOTE_ADDR: &str = "x-test-remote-addr";

    // ---- RequestMetaState::extract_ip ----

    #[test]
    fn extract_ip_ignores_header_from_untrusted_source() {
        let state = RequestMetaState::new(vec![], vec![]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, hval!("1.2.3.4"));

        assert_eq!(state.extract_ip(&headers, &network_address), None);
    }

    #[test]
    fn extract_ip_uses_header_from_trusted_source() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![trusted], vec![]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, hval!("1.2.3.4"));

        assert_eq!(
            state.extract_ip(&headers, &network_address),
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
    }

    #[test]
    fn extract_ip_trusted_source_but_header_missing() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![trusted], vec![]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        assert_eq!(state.extract_ip(&HeaderMap::new(), &network_address), None);
    }

    #[test]
    fn extract_ip_trusted_source_but_header_invalid() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![trusted], vec![]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, hval!("not-an-ip"));

        assert_eq!(state.extract_ip(&headers, &network_address), None);
    }

    #[test]
    fn extract_ip_source_outside_trusted_subnet() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![trusted], vec![]);
        let network_address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, hval!("1.2.3.4"));

        assert_eq!(state.extract_ip(&headers, &network_address), None);
    }

    // ---- RequestMetaState::extract_request_id ----

    #[test]
    fn extract_request_id_ignores_header_from_untrusted_source() {
        let state = RequestMetaState::new(vec![], vec![]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let id = Uuid::now_v7();

        let mut headers = HeaderMap::new();
        headers.insert(
            X_REQUEST_ID,
            HeaderValue::from_str(&id.to_string()).unwrap(),
        );

        assert_eq!(state.extract_request_id(&headers, &network_address), None);
    }

    #[test]
    fn extract_request_id_uses_header_from_trusted_source() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![], vec![trusted]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let id = Uuid::now_v7();

        let mut headers = HeaderMap::new();
        headers.insert(
            X_REQUEST_ID,
            HeaderValue::from_str(&id.to_string()).unwrap(),
        );

        assert_eq!(
            state.extract_request_id(&headers, &network_address),
            Some(RequestId(id))
        );
    }

    #[test]
    fn extract_request_id_trusted_source_but_header_missing() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![], vec![trusted]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        assert_eq!(
            state.extract_request_id(&HeaderMap::new(), &network_address),
            None
        );
    }

    #[test]
    fn extract_request_id_trusted_source_but_header_invalid() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![], vec![trusted]);
        let network_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

        let mut headers = HeaderMap::new();
        headers.insert(X_REQUEST_ID, hval!("not-a-uuid"));

        assert_eq!(state.extract_request_id(&headers, &network_address), None);
    }

    #[test]
    fn extract_request_id_source_outside_trusted_subnet() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let state = RequestMetaState::new(vec![], vec![trusted]);
        let network_address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let id = Uuid::now_v7();

        let mut headers = HeaderMap::new();
        headers.insert(
            X_REQUEST_ID,
            HeaderValue::from_str(&id.to_string()).unwrap(),
        );

        assert_eq!(state.extract_request_id(&headers, &network_address), None);
    }

    // ---- middleware ----

    /// Echoes the `RequestId`/`RemoteAddr` extensions the middleware attached to the
    /// *request* back as response headers, so tests can tell those apart from the
    /// extensions/headers the middleware separately attaches to the *response*.
    async fn echo_handler(req: Request) -> impl IntoResponse {
        let request_id = req.extensions().get::<RequestId>().copied();
        let remote_addr = req.extensions().get::<RemoteAddr>().copied();

        let mut resp = StatusCode::OK.into_response();
        if let Some(v) = request_id {
            resp.headers_mut().insert(
                HeaderName::from_static(X_TEST_REQUEST_ID),
                HeaderValue::from_str(&v.0.to_string()).unwrap(),
            );
        }
        if let Some(v) = remote_addr {
            resp.headers_mut().insert(
                HeaderName::from_static(X_TEST_REMOTE_ADDR),
                HeaderValue::from_str(&v.0.to_string()).unwrap(),
            );
        }
        resp
    }

    fn app(state: RequestMetaState) -> Router {
        Router::new()
            .route("/", get(echo_handler))
            .layer(from_fn_with_state(state, middleware))
    }

    fn with_conn_info(mut req: Request, ip: IpAddr) -> Request {
        let conn_info = ConnInfo {
            remote_addr: Addr::Tcp(SocketAddr::new(ip, 4433)),
            ..Default::default()
        };
        req.extensions_mut().insert(Arc::new(conn_info));
        req
    }

    #[tokio::test]
    async fn middleware_without_conn_info_generates_request_id_and_no_remote_addr() {
        let mut app = app(RequestMetaState::new(vec![], vec![]));
        let req = Request::builder().body(Body::empty()).unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // A fresh, valid request ID was generated & attached both to the request
        // (echoed back by the handler) and to the response.
        let resp_request_id_hdr = resp
            .headers()
            .get(&X_REQUEST_ID)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(Uuid::from_str(&resp_request_id_hdr).is_ok());
        assert_eq!(
            resp.headers()
                .get(X_TEST_REQUEST_ID)
                .unwrap()
                .to_str()
                .unwrap(),
            resp_request_id_hdr
        );
        assert_eq!(
            resp.extensions().get::<RequestId>().unwrap().0.to_string(),
            resp_request_id_hdr
        );

        // No connection info => no remote address extracted at all.
        assert!(resp.headers().get(X_TEST_REMOTE_ADDR).is_none());
        assert!(resp.extensions().get::<RemoteAddr>().is_none());
    }

    #[tokio::test]
    async fn middleware_untrusted_source_falls_back_to_network_address() {
        let mut app = app(RequestMetaState::new(vec![], vec![]));
        let network_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));

        let req = Request::builder()
            .header(X_REAL_IP, "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let req = with_conn_info(req, network_ip);

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // x-real-ip is ignored (untrusted) - falls back to the raw network address.
        assert_eq!(
            resp.headers()
                .get(X_TEST_REMOTE_ADDR)
                .unwrap()
                .to_str()
                .unwrap(),
            network_ip.to_string()
        );
        assert_eq!(resp.extensions().get::<RemoteAddr>().unwrap().0, network_ip);
    }

    #[tokio::test]
    async fn middleware_trusted_source_uses_header_ip_and_header_request_id() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let mut app = app(RequestMetaState::new(vec![trusted], vec![trusted]));

        let network_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let header_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let header_request_id = Uuid::now_v7();

        let req = Request::builder()
            .header(X_REAL_IP, header_ip.to_string())
            .header(X_REQUEST_ID, header_request_id.to_string())
            .body(Body::empty())
            .unwrap();
        let req = with_conn_info(req, network_ip);

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        assert_eq!(
            resp.headers().get(&X_REQUEST_ID).unwrap().to_str().unwrap(),
            header_request_id.to_string()
        );
        assert_eq!(
            resp.extensions().get::<RequestId>().unwrap().0,
            header_request_id
        );

        assert_eq!(
            resp.headers()
                .get(X_TEST_REMOTE_ADDR)
                .unwrap()
                .to_str()
                .unwrap(),
            header_ip.to_string()
        );
        assert_eq!(resp.extensions().get::<RemoteAddr>().unwrap().0, header_ip);
    }

    #[tokio::test]
    async fn middleware_trusted_source_falls_back_when_headers_missing() {
        let trusted: IpNet = "203.0.113.0/24".parse().unwrap();
        let mut app = app(RequestMetaState::new(vec![trusted], vec![trusted]));

        let network_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let req = Request::builder().body(Body::empty()).unwrap();
        let req = with_conn_info(req, network_ip);

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Trusted, but no headers present => fresh request ID, remote address falls
        // back to the raw network address.
        let resp_request_id_hdr = resp
            .headers()
            .get(&X_REQUEST_ID)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(Uuid::from_str(&resp_request_id_hdr).is_ok());

        assert_eq!(
            resp.headers()
                .get(X_TEST_REMOTE_ADDR)
                .unwrap()
                .to_str()
                .unwrap(),
            network_ip.to_string()
        );
    }
}
