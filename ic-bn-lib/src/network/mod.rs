use std::{
    io,
    pin::{Pin, pin},
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
    time::Instant,
};

use ic_bn_lib_common::types::http::{Stats, TlsInfo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

pub mod listener;

/// Blanket async read+write trait for streams `Box`-ing
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> AsyncReadWrite for T {}

/// Performs TLS handshake on the given stream
pub async fn tls_handshake<T: AsyncReadWrite>(
    rustls_cfg: Arc<rustls::ServerConfig>,
    stream: T,
) -> io::Result<(TlsStream<T>, TlsInfo)> {
    let tls_acceptor = TlsAcceptor::from(rustls_cfg);

    // Perform the TLS handshake
    let start = Instant::now();
    let stream = tls_acceptor.accept(stream).await?;
    let duration = start.elapsed();

    // Obtain TLS info
    let conn = stream.get_ref().1;
    let mut tls_info = TlsInfo::try_from(conn).map_err(io::Error::other)?;
    tls_info.handshake_dur = duration;

    Ok((stream, tls_info))
}

/// Async read+write wrapper that counts bytes read/written
pub struct AsyncCounter<T: AsyncReadWrite> {
    inner: T,
    stats: Arc<Stats>,
}

impl<T: AsyncReadWrite> AsyncCounter<T> {
    /// Create new `AsyncCounter`
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
