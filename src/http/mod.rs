pub mod body;
pub mod cache;
pub mod client;
pub mod dns;
pub mod headers;
pub mod proxy;
pub mod server;
pub mod shed;

use std::{
    io,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use axum::{
    extract::OriginalUri,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::Host;
use derive_new::new;
use http::{HeaderMap, Method, Request, StatusCode, Uri, Version, uri::PathAndQuery};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "clients-hyper")]
pub use client::clients_hyper::{HyperClient, HyperClientLeastLoaded};
pub use client::clients_reqwest::{
    ReqwestClient, ReqwestClientLeastLoaded, ReqwestClientRoundRobin,
};
pub use client::{Client, ClientHttp};
pub use server::{ConnInfo, Server, ServerBuilder};
use url::Url;

pub const ALPN_H1: &[u8] = b"http/1.1";
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_ACME: &[u8] = b"acme-tls/1";

/// Blanket async read+write trait for streams Box-ing
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

/// Generic error for now
/// TODO improve
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("HTTP body reading timed out")]
    BodyTimedOut,
    #[error("HTTP body is too big")]
    BodyTooBig,
    #[error("HTTP body reading failed: {0}")]
    BodyReadingFailed(String),
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("No Proxy Protocol v2 detected")]
    NoProxyProtocolDetected,
    #[error("DNS resolving failed: {0}")]
    DnsError(String),
    #[error("Generic HTTP failure: {0}")]
    HttpError(#[from] http::Error),
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

/// Calculate very approximate HTTP request/response headers size in bytes.
/// More or less accurate only for http/1.1 since in h2 headers are in HPACK-compressed.
/// But it seems there's no better way.
pub fn calc_headers_size(h: &HeaderMap) -> usize {
    h.iter().map(|(k, v)| k.as_str().len() + v.len() + 2).sum()
}

/// Some non-allocating functions to get static str
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
        host_port.find(']').map(|i| &host_port[0..=i])
    } else {
        host_port.split(':').next()
    }
}

/// Attempts to extract host from HTTP2 "authority" pseudo-header or from HTTP/1.1 "Host" header
pub fn extract_authority<T>(request: &Request<T>) -> Option<&str> {
    // Try HTTP2 first, then Host header
    request.uri().authority().map(|x| x.host()).or_else(|| {
        request
            .headers()
            .get(http::header::HOST)
            .and_then(|x| x.to_str().ok())
            // Extract host w/o port
            .and_then(extract_host)
    })
}

#[derive(new, Debug)]
pub struct Stats {
    #[new(default)]
    sent: AtomicU64,
    #[new(default)]
    rcvd: AtomicU64,
}

impl Stats {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::SeqCst)
    }

    pub fn rcvd(&self) -> u64 {
        self.rcvd.load(Ordering::SeqCst)
    }
}

/// Async read+write wrapper that counts bytes read/written
pub struct AsyncCounter<T: AsyncReadWrite> {
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

/// Converts Url to Uri
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
        assert_eq!(extract_host("foo.bar:123"), Some("foo.bar"));
        assert_eq!(extract_host("foo.bar:"), Some("foo.bar"));
        assert_eq!(extract_host("foo:123"), Some("foo"));

        assert_eq!(extract_host("127.0.0.1:123"), Some("127.0.0.1"));

        assert_eq!(
            extract_host("[fe80::b696:91ff:fe84:3ae8]"),
            Some("[fe80::b696:91ff:fe84:3ae8]")
        );
        assert_eq!(
            extract_host("[fe80::b696:91ff:fe84:3ae8]:123"),
            Some("[fe80::b696:91ff:fe84:3ae8]")
        );

        // Unterminated bracket
        assert_eq!(extract_host("[fe80::b696:91ff:fe84:3ae8:123"), None);
        // Empty
        assert_eq!(extract_host(""), None);
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
            .authority("foo.bar")
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        assert_eq!(extract_authority(&req), Some("foo.bar"));

        // Host header
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        (*req.headers_mut()).insert(HOST, hval!("foo.baz"));
        assert_eq!(extract_authority(&req), Some("foo.baz"));

        // Both: authority should take precedence (not a real world use case probably)
        let mut req = Request::new(());
        *req.uri_mut() = Uri::builder()
            .scheme("http")
            .authority("foo.bar")
            .path_and_query("/foo?bar=baz")
            .build()
            .unwrap();
        (*req.headers_mut()).insert(HOST, hval!("foo.baz"));
        assert_eq!(extract_authority(&req), Some("foo.bar"));
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
