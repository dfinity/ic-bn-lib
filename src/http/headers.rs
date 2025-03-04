// Clippy complains that these are interior-mutable.
// We don't mutate them, so silence it.
// https://rust-lang.github.io/rust-clippy/master/index.html#/declare_interior_mutable_const
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::borrow_interior_mutable_const)]

use http::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, TE, TRANSFER_ENCODING, UPGRADE,
};

// Header names
pub const X_IC_CACHE_STATUS: HeaderName = HeaderName::from_static("x-ic-cache-status");
pub const X_IC_CACHE_BYPASS_REASON: HeaderName =
    HeaderName::from_static("x-ic-cache-bypass-reason");
pub const X_IC_SUBNET_ID: HeaderName = HeaderName::from_static("x-ic-subnet-id");
pub const X_IC_NODE_ID: HeaderName = HeaderName::from_static("x-ic-node-id");
pub const X_IC_SUBNET_TYPE: HeaderName = HeaderName::from_static("x-ic-subnet-type");
pub const X_IC_CANISTER_ID_CBOR: HeaderName = HeaderName::from_static("x-ic-canister-id-cbor");
pub const X_IC_METHOD_NAME: HeaderName = HeaderName::from_static("x-ic-method-name");
pub const X_IC_SENDER: HeaderName = HeaderName::from_static("x-ic-sender");
pub const X_IC_RETRIES: HeaderName = HeaderName::from_static("x-ic-retries");
pub const X_IC_ERROR_CAUSE: HeaderName = HeaderName::from_static("x-ic-error-cause");
pub const X_IC_REQUEST_TYPE: HeaderName = HeaderName::from_static("x-ic-request-type");
pub const X_IC_CANISTER_ID: HeaderName = HeaderName::from_static("x-ic-canister-id");
pub const X_IC_COUNTRY_CODE: HeaderName = HeaderName::from_static("x-ic-country-code");
pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
pub const X_REQUESTED_WITH: HeaderName = HeaderName::from_static("x-requested-with");
pub const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

// Header values
pub const CONTENT_TYPE_CBOR: HeaderValue = HeaderValue::from_static("application/cbor");
pub const CONTENT_TYPE_OCTET_STREAM: HeaderValue =
    HeaderValue::from_static("application/octet-stream");
pub const CONTENT_TYPE_HTML: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");
pub const HSTS_1YEAR: HeaderValue = HeaderValue::from_static("max-age=31536000; includeSubDomains");
pub const X_CONTENT_TYPE_OPTIONS_NO_SNIFF: HeaderValue = HeaderValue::from_static("nosniff");
pub const X_FRAME_OPTIONS_DENY: HeaderValue = HeaderValue::from_static("DENY");

static CONNECTION_HEADERS: [HeaderName; 5] = [
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    HeaderName::from_static("http2-settings"),
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
