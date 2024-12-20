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
    pin::{pin, Pin},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use derive_new::new;
use http::{HeaderMap, Method, Version};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use client::{Client, ReqwestClient};
pub use server::{ConnInfo, Server};

pub const ALPN_H1: &[u8] = b"http/1.1";
pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_ACME: &[u8] = b"acme-tls/1";

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

// Async read+write wrapper that counts bytes read/written
pub struct AsyncCounter<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> {
    inner: T,
    stats: Arc<Stats>,
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncCounter<T> {
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

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncRead for AsyncCounter<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let size_before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(&poll, Poll::Ready(Ok(()))) {
            let rcvd = buf.filled().len() - size_before;
            self.stats.rcvd.fetch_add(rcvd as u64, Ordering::SeqCst);
        }

        poll
    }
}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncWrite for AsyncCounter<T> {
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
