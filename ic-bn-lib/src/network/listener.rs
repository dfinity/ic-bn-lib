use std::{io, net::SocketAddr, os::unix::fs::PermissionsExt, path::PathBuf};

use ic_bn_lib_common::types::http::{Addr, ListenerOpts};
use socket2::{Domain, Socket, Type};
use tokio::net::{TcpListener, UnixListener, UnixSocket};

use crate::network::AsyncReadWrite;

/// Generic connection listener
pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    /// Create a new Listener
    pub fn new(addr: Addr, opts: ListenerOpts) -> io::Result<Self> {
        Ok(match addr {
            Addr::Tcp(v) => Self::Tcp(listen_tcp(v, opts)?),
            Addr::Unix(v) => Self::Unix(listen_unix(v, opts)?),
        })
    }

    /// Accept the connection
    pub async fn accept(&self) -> io::Result<(Box<dyn AsyncReadWrite>, Addr)> {
        Ok(match self {
            Self::Tcp(v) => {
                let x = v.accept().await?;
                (Box::new(x.0), Addr::Tcp(x.1))
            }
            Self::Unix(v) => {
                let x = v.accept().await?;
                (
                    Box::new(x.0),
                    Addr::Unix(x.1.as_pathname().map(|x| x.into()).unwrap_or_default()),
                )
            }
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &self {
            Self::Tcp(v) => v.local_addr().ok(),
            Self::Unix(_) => None,
        }
    }
}

impl From<TcpListener> for Listener {
    /// Creates a Listener from TcpListener
    fn from(v: TcpListener) -> Self {
        Self::Tcp(v)
    }
}

impl From<UnixListener> for Listener {
    /// Creates a Listener from UnixListener
    fn from(v: UnixListener) -> Self {
        Self::Unix(v)
    }
}

/// Creates a TCP listener with given opts
pub fn listen_tcp(addr: SocketAddr, opts: ListenerOpts) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, None)?;
    socket.set_tcp_nodelay(true)?;

    if let Some(v) = opts.mss {
        socket.set_tcp_mss(v)?;
    }

    socket.set_reuse_address(true)?;
    socket.set_tcp_keepalive(&opts.keepalive)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(opts.backlog as i32)?;

    TcpListener::from_std(socket.into())
}

/// Creates a Unix Socket listener with given opts
pub fn listen_unix(path: PathBuf, opts: ListenerOpts) -> io::Result<UnixListener> {
    let socket = UnixSocket::new_stream()?;

    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    socket.bind(&path)?;
    let socket = socket.listen(opts.backlog)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;

    Ok(socket)
}
