use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use arrayvec::ArrayString;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use bytes::Bytes;
use http::{HeaderMap, header::HeaderValue};
use ipnet::IpNet;
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};

use crate::{
    Error,
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RemoteAddr(pub IpAddr);

impl Deref for RemoteAddr {
    type Target = IpAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for RemoteAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Request ID (UUID)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestId(pub Uuid);

impl Deref for RequestId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Two-letter country code.
/// See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct CountryCode(pub ArrayString<2>);

impl Deref for CountryCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Looks up the client's country using his IP address
pub struct GeoIp {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    /// Creates a new GeoIp instance from a provided database
    pub fn new(db_path: &PathBuf) -> Result<Self, Error> {
        Ok(Self {
            db: maxminddb::Reader::open_readfile(db_path).context("unable to load GeoIP DB")?,
        })
    }

    /// Looks up the country code from an IP
    pub fn lookup(&self, ip: IpAddr) -> Option<CountryCode> {
        let country: Option<geoip2::Country> = self.db.lookup(ip).ok()?.decode().ok()?;
        // Country code should always fit into 2-letter ArrayString.
        // If for whatever reason it does not - return None.
        Some(CountryCode(country?.country.iso_code?.try_into().ok()?))
    }
}

/// State for [`middleware`]
pub struct RequestMetaState {
    /// Optional GeoIP database
    geoip: Option<GeoIp>,

    /// Trust incoming headers from these subnets for the purpose of IP address extraction.
    /// If not set - headers will not be used.
    trust_ip_from: Vec<IpNet>,

    /// Trust incoming headers from these subnets for the purpose of Request ID extraction.
    /// If not set - headers will not be used and a new Request ID will be generated.
    trust_request_id_from: Vec<IpNet>,
}

impl RequestMetaState {
    /// Creates a new [`RequestMetaState`]
    pub const fn new(trust_ip_from: Vec<IpNet>, trust_request_id_from: Vec<IpNet>) -> Self {
        Self {
            geoip: None,
            trust_ip_from,
            trust_request_id_from,
        }
    }

    /// Creates a new [`RequestMetaState`] with a GeoIP DB
    pub fn new_with_geoip(
        trust_ip_from: Vec<IpNet>,
        trust_request_id_from: Vec<IpNet>,
        geoip_db_path: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let geoip = if let Some(v) = geoip_db_path {
            Some(GeoIp::new(&v).context("unable to init GeoIP")?)
        } else {
            None
        };

        Ok(Self {
            geoip,
            trust_ip_from,
            trust_request_id_from,
        })
    }

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

    /// Extracts a request ID from the `x-request-id` header if the remote is trusted and the header exists.
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
    State(state): State<Arc<RequestMetaState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let network_address = request
        .extensions()
        .get::<Arc<ConnInfo>>()
        .map(|x| x.remote_addr.ip());

    // Extract request ID if trusted or generate a new one
    let request_id = network_address
        .and_then(|ip| state.extract_request_id(request.headers(), &ip))
        .unwrap_or_else(|| RequestId(Uuid::now_v7()));

    // Extract client's IP falling back to the network_address if we can't
    let remote_addr = network_address
        .and_then(|ip| state.extract_ip(request.headers(), &ip))
        .or(network_address)
        .map(RemoteAddr);

    let country_code = remote_addr.and_then(|v| {
        request.extensions_mut().insert(v);

        // Look up country code if GeoIP is enabled
        state.geoip.as_ref().and_then(|x| x.lookup(v.0))
    });

    if let Some(v) = country_code {
        request.extensions_mut().insert(v);
    }
    if let Some(v) = remote_addr {
        // SAFETY: Any IP is a valid HeaderValue
        request.headers_mut().insert(
            X_REAL_IP,
            HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
        );
    }

    // SAFETY: UUID is a valid HeaderValue
    let request_id_hdr =
        HeaderValue::from_maybe_shared(Bytes::from(request_id.to_string())).unwrap();
    request.extensions_mut().insert(request_id);
    request
        .headers_mut()
        .insert(X_REQUEST_ID, request_id_hdr.clone());

    let mut response = next.run(request).await;
    response.headers_mut().insert(X_REQUEST_ID, request_id_hdr);
    response.extensions_mut().insert(request_id);

    if let Some(v) = remote_addr {
        response.extensions_mut().insert(v);
    }

    if let Some(v) = country_code {
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
    use http::StatusCode;
    use tower::Service;

    use super::*;
    use crate::{hname, http::server::conn::ConnInfo, hval, network::Addr};

    const X_TEST_REQUEST_ID: &str = "x-test-request-id";
    const X_TEST_REMOTE_ADDR: &str = "x-test-remote-addr";
    const X_TEST_COUNTRY_CODE: &str = "x-test-country-code";
    const X_TEST_REAL_IP: &str = "x-test-real-ip";

    // Known entries in the MaxMind test DB
    const IP_KNOWN: Ipv4Addr = Ipv4Addr::new(89, 160, 20, 112);
    const COUNTRY_KNOWN: &str = "SE";
    const IP_UNKNOWN: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 10);

    fn test_db_path() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/geoip-test-db.mmdb"
        ))
    }

    #[test]
    fn lookup_known_ip_returns_country_code() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        assert_eq!(
            geoip.lookup(IpAddr::V4(IP_KNOWN)).unwrap().0.as_str(),
            COUNTRY_KNOWN
        );
    }

    #[test]
    fn lookup_unknown_ip_returns_none() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        assert!(geoip.lookup(IpAddr::V4(IP_UNKNOWN)).is_none());
    }

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

    /// Echoes the `RequestId`/`RemoteAddr`/`CountryCode` extensions the middleware attached
    /// to the *request* back as response headers, so tests can tell those apart from the
    /// extensions/headers the middleware separately attaches to the *response*.
    async fn echo_handler(req: Request) -> impl IntoResponse {
        let request_id = req.extensions().get::<RequestId>().copied();
        let remote_addr = req.extensions().get::<RemoteAddr>().copied();
        let country_code = req.extensions().get::<CountryCode>().copied();
        let x_real_ip = req.headers().get(X_REAL_IP).cloned();

        let mut resp = StatusCode::OK.into_response();
        if let Some(v) = request_id {
            resp.headers_mut().insert(
                hname!(X_TEST_REQUEST_ID),
                HeaderValue::from_str(&v.0.to_string()).unwrap(),
            );
        }
        if let Some(v) = remote_addr {
            resp.headers_mut().insert(
                hname!(X_TEST_REMOTE_ADDR),
                HeaderValue::from_str(&v.0.to_string()).unwrap(),
            );
        }
        if let Some(v) = country_code {
            resp.headers_mut().insert(
                hname!(X_TEST_COUNTRY_CODE),
                HeaderValue::from_str(&v.0).unwrap(),
            );
        }
        if let Some(v) = x_real_ip {
            resp.headers_mut().insert(hname!(X_TEST_REAL_IP), v);
        }
        resp
    }

    fn app(state: RequestMetaState) -> Router {
        Router::new()
            .route("/", get(echo_handler))
            .layer(from_fn_with_state(Arc::new(state), middleware))
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

        // No GeoIP configured => no country code either.
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
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

        // No GeoIP configured => no country code either.
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
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
        assert_eq!(
            resp.headers()
                .get(X_TEST_REAL_IP)
                .unwrap()
                .to_str()
                .unwrap(),
            header_ip.to_string()
        );

        // No GeoIP configured => no country code either.
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
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

        // No GeoIP configured => no country code either.
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
    }

    #[tokio::test]
    async fn middleware_geoip_disabled_skips_country_lookup() {
        let mut app = app(RequestMetaState::new(vec![], vec![]));
        let req = Request::builder().body(Body::empty()).unwrap();
        let req = with_conn_info(req, IpAddr::V4(IP_KNOWN));

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GeoIP not configured on the state => no lookup happens even for a known IP.
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
    }

    #[tokio::test]
    async fn middleware_geoip_unknown_ip_no_country_code() {
        let state = RequestMetaState::new_with_geoip(vec![], vec![], Some(test_db_path())).unwrap();
        let mut app = app(state);

        let req = Request::builder().body(Body::empty()).unwrap();
        let req = with_conn_info(req, IpAddr::V4(IP_UNKNOWN));

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
    }

    #[tokio::test]
    async fn middleware_geoip_known_ip_attaches_country_code_to_request_and_response() {
        let state = RequestMetaState::new_with_geoip(vec![], vec![], Some(test_db_path())).unwrap();
        let mut app = app(state);

        let req = Request::builder().body(Body::empty()).unwrap();
        let req = with_conn_info(req, IpAddr::V4(IP_KNOWN));

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(X_TEST_COUNTRY_CODE)
                .unwrap()
                .to_str()
                .unwrap(),
            COUNTRY_KNOWN
        );
        assert_eq!(
            resp.extensions().get::<CountryCode>().unwrap().0.as_str(),
            COUNTRY_KNOWN
        );
    }
}
