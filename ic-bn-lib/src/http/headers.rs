// Clippy complains that these are interior-mutable.
// We don't mutate them, so silence it.
// https://rust-lang.github.io/rust-clippy/master/index.html#/declare_interior_mutable_const
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::borrow_interior_mutable_const)]

use http::header::{
    CONNECTION, HeaderMap, HeaderName, HeaderValue, TE, TRANSFER_ENCODING, UPGRADE,
};

#[macro_export]
macro_rules! hname {
    ($id:expr) => {{ http::header::HeaderName::from_static($id) }};
}

#[macro_export]
macro_rules! hval {
    ($id:expr) => {{ http::header::HeaderValue::from_static($id) }};
}

// Header names
pub const X_IC_CACHE_STATUS: HeaderName = hname!("x-ic-cache-status");
pub const X_IC_CACHE_BYPASS_REASON: HeaderName = hname!("x-ic-cache-bypass-reason");
pub const X_IC_SUBNET_ID: HeaderName = hname!("x-ic-subnet-id");
pub const X_IC_NODE_ID: HeaderName = hname!("x-ic-node-id");
pub const X_IC_SUBNET_TYPE: HeaderName = hname!("x-ic-subnet-type");
pub const X_IC_CANISTER_ID_CBOR: HeaderName = hname!("x-ic-canister-id-cbor");
pub const X_IC_METHOD_NAME: HeaderName = hname!("x-ic-method-name");
pub const X_IC_SENDER: HeaderName = hname!("x-ic-sender");
pub const X_IC_RETRIES: HeaderName = hname!("x-ic-retries");
pub const X_IC_ERROR_CAUSE: HeaderName = hname!("x-ic-error-cause");
pub const X_IC_REQUEST_TYPE: HeaderName = hname!("x-ic-request-type");
pub const X_IC_CANISTER_ID: HeaderName = hname!("x-ic-canister-id");
pub const X_IC_COUNTRY_CODE: HeaderName = hname!("x-ic-country-code");
pub const X_CACHE_TTL: HeaderName = hname!("x-cache-ttl");
pub const X_FORWARDED_FOR: HeaderName = hname!("x-forwarded-for");
pub const X_FORWARDED_HOST: HeaderName = hname!("x-forwarded-host");
pub const X_REQUEST_ID: HeaderName = hname!("x-request-id");
pub const X_REQUESTED_WITH: HeaderName = hname!("x-requested-with");
pub const X_REAL_IP: HeaderName = hname!("x-real-ip");

// Header values
pub const CONTENT_TYPE_CBOR: HeaderValue = hval!("application/cbor");
pub const CONTENT_TYPE_OCTET_STREAM: HeaderValue = hval!("application/octet-stream");
pub const CONTENT_TYPE_HTML: HeaderValue = hval!("text/html; charset=utf-8");
pub const HSTS_1YEAR: HeaderValue = hval!("max-age=31536000; includeSubDomains");
pub const X_CONTENT_TYPE_OPTIONS_NO_SNIFF: HeaderValue = hval!("nosniff");
pub const X_FRAME_OPTIONS_DENY: HeaderValue = hval!("DENY");

static CONNECTION_HEADERS: [HeaderName; 5] = [
    hname!("keep-alive"),
    hname!("proxy-connection"),
    hname!("http2-settings"),
    TRANSFER_ENCODING,
    UPGRADE,
];

/// Strip connection-related headers from an HTTP/1.1
/// request so that it becomes a valid HTTP/2 request
pub fn strip_connection_headers(headers: &mut HeaderMap) {
    for header in &CONNECTION_HEADERS {
        headers.remove(header);
    }

    // TE is forbidden unless it's "trailers"
    if headers
        .get(TE)
        .is_some_and(|te_header| te_header != "trailers")
    {
        headers.remove(TE);
    }

    if let Some(header) = headers.remove(CONNECTION) {
        let header_contents = header.to_str().unwrap();

        // A `Connection` header may have a comma-separated list of names of other headers that
        // are meant for only this specific connection.
        // Iterate these names and remove them as headers.
        for name in header_contents.split(',') {
            let name = name.trim();
            headers.remove(name);
        }
    }
}

#[cfg(test)]
mod test {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn test_strips_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        headers.insert(
            HeaderName::from_static("proxy-connection"),
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert(
            HeaderName::from_static("http2-settings"),
            HeaderValue::from_static("foo"),
        );
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );

        strip_connection_headers(&mut headers);

        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("proxy-connection").is_none());
        assert!(headers.get("http2-settings").is_none());
        assert!(headers.get(TRANSFER_ENCODING).is_none());
        assert!(headers.get(UPGRADE).is_none());
        assert_eq!(
            headers.get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn test_te_trailers_is_kept() {
        let mut headers = HeaderMap::new();
        headers.insert(TE, HeaderValue::from_static("trailers"));

        strip_connection_headers(&mut headers);

        assert_eq!(headers.get(TE).unwrap(), "trailers");
    }

    #[test]
    fn test_te_non_trailers_is_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(TE, HeaderValue::from_static("gzip"));

        strip_connection_headers(&mut headers);

        assert!(headers.get(TE).is_none());
    }

    #[test]
    fn test_headers_listed_in_connection_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("x-foo, x-bar"));
        headers.insert(
            HeaderName::from_static("x-foo"),
            HeaderValue::from_static("1"),
        );
        headers.insert(
            HeaderName::from_static("x-bar"),
            HeaderValue::from_static("2"),
        );
        headers.insert(
            HeaderName::from_static("x-baz"),
            HeaderValue::from_static("3"),
        );

        strip_connection_headers(&mut headers);

        assert!(headers.get(CONNECTION).is_none());
        assert!(headers.get("x-foo").is_none());
        assert!(headers.get("x-bar").is_none());
        assert_eq!(headers.get("x-baz").unwrap(), "3");
    }

    #[test]
    fn test_unrelated_headers_are_untouched() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        strip_connection_headers(&mut headers);

        assert_eq!(
            headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }
}
