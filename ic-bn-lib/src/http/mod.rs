pub mod body;
pub mod cache;
pub mod client;
pub mod dns;
pub mod headers;
pub mod middleware;
pub mod proxy;
pub mod server;
pub mod shed;

use std::{
    io,
    pin::{Pin, pin},
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};

use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::Host;
use http::{HeaderMap, Method, Request, StatusCode, Uri, Version, header::HOST, uri::PathAndQuery};
use ic_bn_lib_common::types::http::Stats;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "clients-hyper")]
pub use client::clients_hyper::{HyperClient, HyperClientLeastLoaded};
pub use client::clients_reqwest::{
    ReqwestClient, ReqwestClientLeastLoaded, ReqwestClientRoundRobin,
};
pub use server::{Server, ServerBuilder};
use url::Url;

use crate::http::headers::X_FORWARDED_HOST;

/// Blanket async read+write trait for streams Box-ing
trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

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

/// Async read+write wrapper that counts bytes read/written
struct AsyncCounter<T: AsyncReadWrite> {
    inner: T,
    stats: Arc<Stats>,
}

impl<T: AsyncReadWrite> AsyncCounter<T> {
    pub fn new(inner: T) -> (Self, Arc<Stats>) {
        let stats = Arc::new(Stats::new());

        (
            Self {
                inner,
                stats: stats.clone(),
            },
            stats,
        )
    }
}

impl<T: AsyncReadWrite> AsyncRead for AsyncCounter<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let size_before = buf.filled().len();
        let poll = pin!(&mut self.inner).poll_read(cx, buf);
        if matches!(&poll, Poll::Ready(Ok(()))) {
            let rcvd = buf.filled().len() - size_before;
            self.stats.rcvd.fetch_add(rcvd as u64, Ordering::SeqCst);
        }

        poll
    }
}

impl<T: AsyncReadWrite> AsyncWrite for AsyncCounter<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = pin!(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(v)) = &poll {
            self.stats.sent.fetch_add(*v as u64, Ordering::SeqCst);
        }

        poll
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        pin!(&mut self.inner).poll_flush(cx)
    }
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
    Host(host): Host,
    OriginalUri(uri): OriginalUri,
) -> Result<impl IntoResponse, impl IntoResponse> {
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
    use http::{Uri, header::HOST};

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
}
