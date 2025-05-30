use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::{Pin, pin},
    task::{Context, Poll},
};

use anyhow::{Context as _, anyhow};
use ppp::v2;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use x509_parser::nom::AsBytes;

use super::Error;
use crate::http::AsyncReadWrite;

/// The prefix length of a header in bytes.
const PREFIX_LEN: usize = 12;
/// The minimum length of a header in bytes.
const MINIMUM_LEN: usize = PREFIX_LEN + 4;
/// The index of the start of the big-endian u16 length in the header.
const LENGTH_INDEX: usize = PREFIX_LEN + 2;
/// The length of the read buffer used to read the PROXY protocol header.
const BUFFER_LEN: usize = 512;

/// Async Read+Write wrapper that appends some data before the wrapped stream
pub struct ProxyProtocolStream<T: AsyncReadWrite> {
    inner: T,
    data: Option<Vec<u8>>,
}

impl<T: AsyncReadWrite> ProxyProtocolStream<T> {
    pub const fn new(inner: T, data: Option<Vec<u8>>) -> Self {
        Self { inner, data }
    }

    pub async fn accept(mut stream: T) -> Result<(Self, Option<SocketAddr>), Error> {
        let mut buf = [0; BUFFER_LEN];

        // Try to read the first part of proxy protocol header into a buffer.
        // We assume that incoming requests are at least MINIMUM_LEN long,
        // which is Ok since even the smallest HTTP request should be longer.
        stream
            .read_exact(&mut buf[..MINIMUM_LEN])
            .await
            .context("unable to read prefix")?;

        // If the prefix doesn't match the proxy protocol signature - then we
        // assume that we have no proxy protocol and just bypass the traffic.
        if &buf[..PREFIX_LEN] != v2::PROTOCOL_PREFIX.as_bytes() {
            return Ok((Self::new(stream, Some(buf[..MINIMUM_LEN].to_vec())), None));
        }

        // Parse the header length
        let len = u16::from_be_bytes([buf[LENGTH_INDEX], buf[LENGTH_INDEX + 1]]) as usize;
        let full_len = MINIMUM_LEN + len;

        // Switch to dynamic buffer if the header is too long.
        // v2 has no maximum length (up to 2^16)
        // TODO should we limit this even lower to avoid abuse?
        #[allow(unused_assignments)]
        let mut dyn_buf = Vec::new();
        let hdr = if full_len > BUFFER_LEN {
            dyn_buf = Vec::with_capacity(full_len);
            dyn_buf.extend_from_slice(&buf[..MINIMUM_LEN]);
            stream
                .read_exact(&mut dyn_buf[MINIMUM_LEN..full_len])
                .await
                .context("unable to read proxy header")?;

            dyn_buf.as_slice()
        } else {
            // Otherwise just read into stack allocated buffer
            stream
                .read_exact(&mut buf[MINIMUM_LEN..full_len])
                .await
                .context("unable to read proxy header")?;

            &buf
        };

        // Parse the header
        let hdr = v2::Header::try_from(hdr).context("unable to parse header")?;
        let addr = match hdr.addresses {
            v2::Addresses::IPv4(v) => SocketAddr::new(IpAddr::V4(v.source_address), v.source_port),
            v2::Addresses::IPv6(v) => SocketAddr::new(IpAddr::V6(v.source_address), v.source_port),
            _ => {
                return Err(Error::Generic(anyhow!(
                    "unsupported address type: {:?}",
                    hdr.addresses
                )));
            }
        };

        Ok((Self::new(stream, None), Some(addr)))
    }
}

impl<T: AsyncReadWrite> AsyncRead for ProxyProtocolStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut v) = self.data.take() {
            let buf_avail = buf.remaining();

            // If there's enough space - just write there
            if v.len() <= buf_avail {
                buf.put_slice(&v);
                return Poll::Ready(Ok(()));
            }

            // Otherwise write as much as we can
            buf.put_slice(&v[..buf_avail]);
            // Shift the buffer left
            v.rotate_left(buf_avail);
            // Truncate it
            v.truncate(v.len() - buf_avail);
            // Put it back
            self.data.replace(v);

            return Poll::Ready(Ok(()));
        }

        pin!(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncReadWrite> AsyncWrite for ProxyProtocolStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        pin!(&mut self.inner).poll_write(cx, buf)
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
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;
    use anyhow::Error;
    use mock_io::tokio::MockStream;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_proxy_protocol_stream() -> Result<(), Error> {
        // Try big enough buffer w/o data
        let (recv, mut send) = MockStream::pair();
        tokio::task::spawn(async move {
            let _ = send.write(b"foobar").await.unwrap();
        });
        let mut s = ProxyProtocolStream::new(recv, None);
        let mut buf = vec![0; 6];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"foobar");

        // Try big enough buffer with data
        let (recv, mut send) = MockStream::pair();
        tokio::task::spawn(async move {
            let _ = send.write(b"foobar").await.unwrap();
        });
        let mut s = ProxyProtocolStream::new(recv, Some(b"deadbeef".to_vec()));
        let mut buf = vec![0; 14];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"deadbeeffoobar");

        // Try smaller buffers
        let (recv, mut send) = MockStream::pair();
        tokio::task::spawn(async move {
            let _ = send.write(b"foobar").await.unwrap();
        });
        let mut s = ProxyProtocolStream::new(recv, Some(b"deadbeef".to_vec()));
        let mut buf = vec![0; 6];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"deadbe");
        let mut buf = vec![0; 3];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"eff");
        let mut buf = vec![0; 3];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"oob");
        let mut buf = vec![0; 2];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"ar");

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_protocol_accept_with_proxy_header() -> Result<(), Error> {
        let addrs = v2::IPv4::new([1, 1, 1, 1], [2, 2, 2, 2], 31337, 443);
        let mut hdr = v2::Builder::with_addresses(
            v2::Version::Two | v2::Command::Proxy,
            v2::Protocol::Stream,
            addrs,
        )
        .build()?;
        hdr.extend_from_slice(&b"foobar foobaz foobar"[..]);

        let (recv, mut send) = MockStream::pair();
        tokio::task::spawn(async move {
            let n = send.write(&hdr).await.unwrap();
            assert_eq!(n, hdr.len());
        });

        let (mut stream, addr) = ProxyProtocolStream::accept(recv).await?;
        let addr = addr.unwrap();
        assert_eq!(
            addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 31337))
        );

        let mut buf = vec![0; 20];
        stream.read_exact(&mut buf).await?;
        assert_eq!(buf, &b"foobar foobaz foobar"[..]);

        Ok(())
    }

    #[tokio::test]
    async fn test_proxy_protocol_accept_without_proxy_header() -> Result<(), Error> {
        let (recv, mut send) = MockStream::pair();
        tokio::task::spawn(async move {
            let _ = send.write(&b"foobar foobaz foobar"[..]).await.unwrap();
        });

        let (mut stream, addr) = ProxyProtocolStream::accept(recv).await?;
        assert!(addr.is_none());

        let mut buf = vec![0; 10];
        stream.read_exact(&mut buf).await?;
        assert_eq!(buf, &b"foobar foo"[..]);

        let mut buf = vec![0; 10];
        stream.read_exact(&mut buf).await?;
        assert_eq!(buf, &b"baz foobar"[..]);

        Ok(())
    }
}
