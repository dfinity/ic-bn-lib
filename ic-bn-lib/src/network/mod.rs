pub mod listener;

use std::{
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::anyhow;
use derive_new::new;
use rustls::{CipherSuite, ProtocolVersion, ServerConnection};
use socket2::TcpKeepalive;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

/// TLS-related information about the connection
#[derive(Clone, Debug)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub protocol: ProtocolVersion,
    pub cipher: CipherSuite,
    pub handshake_dur: Duration,
}

impl TryFrom<&ServerConnection> for TlsInfo {
    type Error = anyhow::Error;

    fn try_from(c: &ServerConnection) -> Result<Self, Self::Error> {
        Ok(Self {
            handshake_dur: Duration::ZERO,
            sni: c.server_name().map(|x| x.to_string()),
            alpn: c
                .alpn_protocol()
                .map(|x| String::from_utf8_lossy(x).to_string()),
            protocol: c
                .protocol_version()
                .ok_or_else(|| anyhow!("No TLS protocol found"))?,
            cipher: c
                .negotiated_cipher_suite()
                .map(|x| x.suite())
                .ok_or_else(|| anyhow!("No TLS ciphersuite found"))?,
        })
    }
}

/// Options for a `Listener`
pub struct ListenerOpts {
    pub backlog: u32,
    pub mss: Option<u32>,
    pub keepalive: TcpKeepalive,
    /// Permission bits applied to a Unix domain socket's path after binding.
    /// Ignored for TCP listeners.
    pub unix_socket_permissions: u32,
}

impl Default for ListenerOpts {
    fn default() -> Self {
        Self {
            backlog: 1024,
            mss: None,
            keepalive: TcpKeepalive::new(),
            // Owner+group only by default - any local user/process able to
            // reach the socket path can otherwise connect regardless of the
            // intended peer.
            unix_socket_permissions: 0o660,
        }
    }
}

/// Atomic counters for `AsyncCounter`
#[derive(new, Debug)]
pub struct Stats {
    #[new(default)]
    pub sent: AtomicU64,
    #[new(default)]
    pub rcvd: AtomicU64,
}

impl Stats {
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::SeqCst)
    }

    pub fn rcvd(&self) -> u64 {
        self.rcvd.load(Ordering::SeqCst)
    }
}

/// Connection endpoint address
#[derive(Debug, Clone)]
pub enum Addr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Default for Addr {
    fn default() -> Self {
        Self::Tcp(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            666,
        )))
    }
}

impl Addr {
    pub const fn family(&self) -> &'static str {
        match self {
            Self::Tcp(v) => {
                if v.ip().to_canonical().is_ipv4() {
                    "v4"
                } else {
                    "v6"
                }
            }
            Self::Unix(_) => "unix",
        }
    }

    pub const fn ip(&self) -> IpAddr {
        match self {
            Self::Tcp(v) => v.ip().to_canonical(),
            Self::Unix(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Tcp(v) => v.ip().to_canonical().to_string(),
                Self::Unix(v) => v.to_string_lossy().to_string(),
            }
        )
    }
}

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

#[cfg(test)]
mod test {
    use std::net::{Ipv6Addr, SocketAddrV6};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn test_addr_family() {
        let v4 = Addr::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)));
        assert_eq!(v4.family(), "v4");

        let v6 = Addr::Tcp(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            80,
            0,
            0,
        )));
        assert_eq!(v6.family(), "v6");

        // A v4-mapped v6 address should be reported as v4
        let mapped = Addr::Tcp(SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            80,
            0,
            0,
        )));
        assert_eq!(mapped.family(), "v4");

        let unix = Addr::Unix(PathBuf::from("/tmp/foo.sock"));
        assert_eq!(unix.family(), "unix");
    }

    #[test]
    fn test_addr_ip() {
        let v4 = Addr::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)));
        assert_eq!(v4.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let unix = Addr::Unix(PathBuf::from("/tmp/foo.sock"));
        assert_eq!(unix.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_addr_display() {
        let v4 = Addr::Tcp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)));
        assert_eq!(v4.to_string(), "127.0.0.1");

        let unix = Addr::Unix(PathBuf::from("/tmp/foo.sock"));
        assert_eq!(unix.to_string(), "/tmp/foo.sock");
    }

    #[test]
    fn test_addr_default() {
        assert_eq!(Addr::default().family(), "v4");
    }

    #[tokio::test]
    async fn test_async_counter_tracks_bytes() {
        let (a, mut b) = duplex(64);
        let (mut a, stats) = AsyncCounter::new(a);

        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(stats.sent(), 5);
        assert_eq!(stats.rcvd(), 0);

        b.write_all(b"world!").await.unwrap();
        let mut buf = [0u8; 6];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world!");
        assert_eq!(stats.sent(), 5);
        assert_eq!(stats.rcvd(), 6);
    }
}
