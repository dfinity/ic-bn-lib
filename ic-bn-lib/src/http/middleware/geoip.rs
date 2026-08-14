use std::{net::IpAddr, ops::Deref, path::PathBuf, sync::Arc, time::Instant};

use anyhow::Error;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use maxminddb::geoip2;
use tracing::warn;

use super::RemoteAddr;

#[derive(Clone, Debug)]
pub struct CountryCode(pub String);

impl Deref for CountryCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Looks up the client's country using his IP address
pub struct GeoIp {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn new(db_path: &PathBuf) -> Result<Self, Error> {
        let start = Instant::now();
        let db = maxminddb::Reader::open_readfile(db_path)?;

        warn!(
            "GeoIP loaded with {} entries in {}s",
            db.metadata().node_count,
            start.elapsed().as_secs_f64()
        );

        Ok(Self { db })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<CountryCode> {
        let country: Option<geoip2::Country> = self.db.lookup(ip).ok()?.decode().ok()?;
        Some(CountryCode(country?.country.iso_code?.into()))
    }
}

/// Tries to look up user's country using his IP address
pub async fn middleware(
    State(geoip): State<Arc<GeoIp>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to get the IP
    let remote_addr = request.extensions().get::<RemoteAddr>().copied();

    // Lookup country
    let country_code = remote_addr.and_then(|x| geoip.lookup(*x));

    if let Some(v) = &country_code {
        request.extensions_mut().insert(v.clone());
    }

    let mut response = next.run(request).await;

    if let Some(v) = country_code {
        response.extensions_mut().insert(v);
    }

    response
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use axum::{
        Router, body::Body, middleware::from_fn_with_state, response::IntoResponse, routing::get,
    };
    use http::{HeaderName, HeaderValue, StatusCode};
    use tower::Service;

    use super::*;

    const X_TEST_COUNTRY_CODE: &str = "x-test-country-code";

    // Known entries in the MaxMind test test DB
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
        assert_eq!(geoip.lookup(IpAddr::V4(IP_KNOWN)).unwrap().0, COUNTRY_KNOWN);
    }

    #[test]
    fn lookup_unknown_ip_returns_none() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        assert!(geoip.lookup(IpAddr::V4(IP_UNKNOWN)).is_none());
    }

    /// Echoes the `CountryCode` extension the middleware attached to the *request*
    /// back as a response header, so tests can tell it apart from the extension the
    /// middleware separately attaches to the *response*.
    async fn echo_handler(req: Request) -> impl IntoResponse {
        let country_code = req.extensions().get::<CountryCode>().cloned();

        let mut resp = StatusCode::OK.into_response();
        if let Some(v) = country_code {
            resp.headers_mut().insert(
                HeaderName::from_static(X_TEST_COUNTRY_CODE),
                HeaderValue::from_str(&v.0).unwrap(),
            );
        }
        resp
    }

    fn app(geoip: Arc<GeoIp>) -> Router {
        Router::new()
            .route("/", get(echo_handler))
            .layer(from_fn_with_state(geoip, middleware))
    }

    fn with_remote_addr(mut req: Request, ip: IpAddr) -> Request {
        req.extensions_mut().insert(RemoteAddr(ip));
        req
    }

    #[tokio::test]
    async fn geoip_without_remote_addr_skips_lookup() {
        let geoip = Arc::new(GeoIp::new(&test_db_path()).unwrap());
        let mut app = app(geoip);

        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = app.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
    }

    #[tokio::test]
    async fn geoip_unknown_ip_no_result() {
        let geoip = Arc::new(GeoIp::new(&test_db_path()).unwrap());
        let mut app = app(geoip);

        let req = Request::builder().body(Body::empty()).unwrap();
        let req = with_remote_addr(req, IpAddr::V4(IP_UNKNOWN));
        let resp = app.call(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(X_TEST_COUNTRY_CODE).is_none());
        assert!(resp.extensions().get::<CountryCode>().is_none());
    }

    #[tokio::test]
    async fn geoip_known_ip_attaches_country_code_to_request_and_response() {
        let geoip = Arc::new(GeoIp::new(&test_db_path()).unwrap());
        let mut app = app(geoip);

        let req = Request::builder().body(Body::empty()).unwrap();
        let req = with_remote_addr(req, IpAddr::V4(IP_KNOWN));
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
            resp.extensions().get::<CountryCode>().unwrap().0,
            COUNTRY_KNOWN
        );
    }
}
