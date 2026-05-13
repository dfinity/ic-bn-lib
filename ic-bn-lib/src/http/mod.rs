pub mod body;
pub mod cache;
pub mod client;
pub mod dns;
pub mod headers;
pub mod middleware;
pub mod proxy;
pub mod server;
pub mod shed;

use axum::response::{IntoResponse, Redirect};
use http::{HeaderMap, Method, Request, StatusCode, Uri, Version, header::HOST, uri::PathAndQuery};

#[cfg(feature = "clients-hyper")]
pub use client::clients_hyper::{HyperClient, HyperClientLeastLoaded};
pub use client::clients_reqwest::{
    ReqwestClient, ReqwestClientLeastLoaded, ReqwestClientRoundRobin,
};
pub use server::{Server, ServerBuilder};
use url::Url;

use crate::{http::headers::X_FORWARDED_HOST, network::AsyncReadWrite};

/// Calculate very approximate HTTP request/response headers size in bytes.
/// More or less accurate only for http/1.1 since in h2 headers are in HPACK-compressed.
/// But it seems there's no better way.
pub fn calc_headers_size(h: &HeaderMap) -> usize {
    h.iter().map(|(k, v)| k.as_str().len() + v.len() + 2).sum()
}

/// Get a static string representing given HTTP version
pub const fn http_version(v: Version) -> &'static str {
    match v {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "-",
    }
}

/// Get a static string representing given HTTP method
pub const fn http_method(v: &Method) -> &'static str {
    match *v {
        Method::OPTIONS => "OPTIONS",
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::TRACE => "TRACE",
        Method::CONNECT => "CONNECT",
        Method::PATCH => "PATCH",
        _ => "",
    }
}

/// Attempts to extract "host" from "host:port" format.
/// Host can be either FQDN or IPv4/IPv6 address.
pub fn extract_host(host_port: &str) -> Option<&str> {
    if host_port.is_empty() {
        return None;
    }

    // Cover IPv6 case
    if host_port.as_bytes()[0] == b'[' {
        host_port.find(']').map(|i| &host_port[1..i])
    } else {
        host_port.split(':').next()
    }
    .filter(|x| !x.is_empty())
}

/// Attempts to extract host from `X-Forwarded-Host` header, HTTP2 "authority" pseudo-header or from HTTP/1.1 `Host` header
/// (in this order of preference)
pub fn extract_authority<T>(request: &Request<T>) -> Option<&str> {
    // Try `X-Forwarded-Host` header first
    request
        .headers()
        .get(X_FORWARDED_HOST)
        .and_then(|x| x.to_str().ok())
        // Then URI authority
        .or_else(|| request.uri().authority().map(|x| x.host()))
        // THen `Host` header
        .or_else(|| request.headers().get(HOST).and_then(|x| x.to_str().ok()))
        // Extract host w/o port
        .and_then(extract_host)
}

/// Error that might happen during Url to Uri conversion
#[derive(thiserror::Error, Debug)]
pub enum UrlToUriError {
    #[error("No Authority")]
    NoAuthority,
    #[error("No Host")]
    NoHost,
    #[error(transparent)]
    Http(#[from] http::Error),
}

/// Converts `Url` to `Uri`
pub fn url_to_uri(url: &Url) -> Result<Uri, UrlToUriError> {
    if !url.has_authority() {
        return Err(UrlToUriError::NoAuthority);
    }

    if !url.has_host() {
        return Err(UrlToUriError::NoHost);
    }

    let scheme = url.scheme();
    let authority = url.authority();

    let authority_end = scheme.len() + "://".len() + authority.len();
    let path_and_query = &url.as_str()[authority_end..];

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(UrlToUriError::Http)
}

/// Redirects any request to an HTTPS scheme
pub async fn redirect_to_https(
    request: axum::extract::Request,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let host = extract_authority(&request)
        .ok_or((StatusCode::BAD_REQUEST, "Unable to extract authority"))?;
    let uri = request.uri().clone();

    let fallback_path = PathAndQuery::from_static("/");
    let pq = uri.path_and_query().unwrap_or(&fallback_path).as_str();

    Ok::<_, (_, _)>(Redirect::permanent(
        &Uri::builder()
            .scheme("https")
            .authority(host)
            .path_and_query(pq)
            .build()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Incorrect URL"))?
            .to_string(),
    ))
}

#[cfg(test)]
mod test {
    use axum::{Router, body::Body};
    use http::{
        Uri,
        header::{HOST, LOCATION},
    };
    use tower::ServiceExt;

    use crate::hval;

    use super::*;

    #[test]
    fn test_extract_host() {
        assert_eq!(extract_host("foo.bar"), Some("foo.bar"));
        assert_eq!(extract_host("foo.bar:443"), Some("foo.bar"));
        assert_eq!(extract_host("foo.bar:"), Some("foo.bar"));
        assert_eq!(extract_host("foo:443"), Some("foo"));

        assert_eq!(extract_host("127.0.0.1:443"), Some("127.0.0.1"));
        assert_eq!(extract_host("[::1]:443"), Some("::1"));

        assert_eq!(
            extract_host("[fe80::b696:91ff:fe84:3ae8]"),
            Some("fe80::b696:91ff:fe84:3ae8")
        );
        assert_eq!(
            extract_host("[fe80::b696:91ff:fe84:3ae8]:123"),
            Some("fe80::b696:91ff:fe84:3ae8")
        );

        // Unterminated bracket
        assert_eq!(extract_host("[fe80::b696:91ff:fe84:3ae8:123"), None);
        // Empty
        assert_eq!(extract_host(""), None);
        assert_eq!(extract_host("[]:443"), None);
    }

    #[test]
    fn test_extract_authority() {
        // No authority & no host header
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        assert_eq!(extract_authority(&req), None);

        // Authority
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .scheme("http")
            .authority("foo.bar:443")
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        assert_eq!(extract_authority(&req), Some("foo.bar"));

        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .scheme("http")
            .authority("[::1]:443")
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        assert_eq!(extract_authority(&req), Some("::1"));

        // Host header
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        (*req.headers_mut()).insert(HOST, hval!("foo.baz:443"));
        assert_eq!(extract_authority(&req), Some("foo.baz"));

        // XFH header
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        (*req.headers_mut()).insert(X_FORWARDED_HOST, hval!("foo.baz:443"));
        assert_eq!(extract_authority(&req), Some("foo.baz"));

        // Host+Authority: authority should take precedence
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .scheme("http")
            .authority("foo.bar:443")
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        (*req.headers_mut()).insert(HOST, hval!("foo.baz:443"));
        assert_eq!(extract_authority(&req), Some("foo.bar"));

        // XFH+Host+Authority: XFH should take precedence
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .scheme("http")
            .authority("foo.bar:443")
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        (*req.headers_mut()).insert(HOST, hval!("foo.baz:443"));
        (*req.headers_mut()).insert(X_FORWARDED_HOST, hval!("dead.beef:443"));
        assert_eq!(extract_authority(&req), Some("dead.beef"));
    }

    #[test]
    fn test_url_to_uri() {
        let url = "https://foo.bar/baz?dead=beef".parse().unwrap();

        assert_eq!(
            url_to_uri(&url).unwrap(),
            Uri::from_static("https://foo.bar/baz?dead=beef")
        );

        let url = "unix:/foo/bar".parse().unwrap();
        assert!(url_to_uri(&url).is_err());
    }

    #[tokio::test]
    async fn test_redirect_to_https() {
        let mut request = axum::extract::Request::new(Body::empty());
        *request.uri_mut() = Uri::from_static("http://foo/bar/baz.bin?a=b");

        let router = Router::new().fallback(redirect_to_https);

        let response = router.oneshot(request).await.unwrap();
        let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert_eq!(location, "https://foo/bar/baz.bin?a=b");
    }
}
