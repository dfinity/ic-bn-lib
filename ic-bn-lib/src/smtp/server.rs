use std::{fmt::Display, io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker, time::FutureExt};
use tracing::{info, warn};

use crate::{
    network::{ListenerOpts, listener::listen_tcp},
    smtp::{
        Metrics,
        inbound::{SessionConfig, manager::SessionManager},
    },
    tasks::Run,
};

/// Listens for new SMTP connections and creates sessions
pub struct Server {
    listen_addr: SocketAddr,
    listener: TcpListener,
    params: Arc<SessionConfig>,
    tracker: TaskTracker,
    metrics: Metrics,
}

impl Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMTP/Server({})", self.listen_addr)
    }
}

impl Server {
    /// Creates a new `Server` to listen on `listen_addr`
    pub fn new(listen_addr: SocketAddr, cfg: SessionConfig, metrics: Metrics) -> io::Result<Self> {
        let listener = listen_tcp(listen_addr, ListenerOpts::default())?;
        Self::new_with_listener(listener, cfg, metrics)
    }

    /// Creates a new `Server` from a pre-built `TcpListener`
    pub fn new_with_listener(
        listener: TcpListener,
        params: SessionConfig,
        metrics: Metrics,
    ) -> io::Result<Self> {
        Ok(Self {
            listen_addr: listener.local_addr()?,
            listener,
            params: Arc::new(params),
            tracker: TaskTracker::new(),
            metrics,
        })
    }

    async fn handle_connection(
        &self,
        res: io::Result<(TcpStream, SocketAddr)>,
        token: &CancellationToken,
    ) {
        match res {
            Ok((stream, addr)) => {
                info!("{self}: New connection from {}", addr.ip().to_canonical());

                let (params, token) = (self.params.clone(), token.child_token());
                self.tracker.spawn(SessionManager::handle_connection(
                    stream,
                    addr,
                    params,
                    // Metrics are cheap to clone (Arc inside)
                    self.metrics.clone(),
                    token,
                ));
            }

            Err(e) => {
                warn!("{self}: Unable to accept connection: {e:#}");
                // Throttle a bit to avoid busy loop when accept() fails instantly
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    /// Main connection handling loop
    pub async fn serve(&self, token: CancellationToken) -> io::Result<()> {
        warn!("{self}: Accepting connections");

        loop {
            select! {
                res = self.listener.accept() => {
                    self.handle_connection(res, &token).await;
                }

                () = token.cancelled() => {
                    warn!("{self}: Shutting down, closing connections");

                    self.tracker.close();
                    if self.tracker.wait().timeout(Duration::from_secs(30)).await.is_err() {
                        warn!("{self}: Timed out waiting for connections to close");
                    }

                    break;
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Run for Server {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        self.serve(token).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    use prometheus::Registry;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;

    const GREETING: &str = "220 mx.test.local ESMTP IC SMTP Gateway\r\n";

    fn cfg() -> SessionConfig {
        SessionConfig::new("mx.test.local", 1024)
    }

    fn metrics() -> Metrics {
        Metrics::new(&Registry::new())
    }

    const fn loopback() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
    }

    /// Reads until at least `expect.len()` bytes arrive or EOF
    async fn read_reply(stream: &mut TcpStream, expect: usize) -> String {
        let mut buf = vec![];
        while buf.len() < expect {
            let mut chunk = [0; 512];
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        String::from_utf8(buf).unwrap()
    }

    #[tokio::test]
    async fn test_new_binds_ephemeral_port() {
        let server = Server::new(loopback(), cfg(), metrics()).unwrap();

        assert_eq!(server.listen_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(
            server.listen_addr.port(),
            0,
            "port 0 must be resolved to the actual one"
        );
        assert_eq!(
            server.listen_addr,
            server.listener.local_addr().unwrap(),
            "cached address must match the listener's"
        );
        assert_eq!(
            server.to_string(),
            format!("SMTP/Server({})", server.listen_addr)
        );
        assert!(!server.tracker.is_closed());
        assert!(server.tracker.is_empty());
    }

    #[tokio::test]
    async fn test_new_with_listener_uses_listener_address() {
        let listener = listen_tcp(loopback(), ListenerOpts::default()).unwrap();
        let addr = listener.local_addr().unwrap();

        let server = Server::new_with_listener(listener, cfg(), metrics()).unwrap();
        assert_eq!(server.listen_addr, addr);
        assert_eq!(server.to_string(), format!("SMTP/Server({addr})"));
    }

    #[tokio::test]
    async fn test_new_fails_when_address_is_taken() {
        // Keep the listener alive to hold the port
        let listener = listen_tcp(loopback(), ListenerOpts::default()).unwrap();
        let addr = listener.local_addr().unwrap();

        let Err(err) = Server::new(addr, cfg(), metrics()) else {
            panic!("binding an already-bound port must fail");
        };
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn test_serve_returns_on_cancelled_token() {
        let server = Server::new(loopback(), cfg(), metrics()).unwrap();

        let token = CancellationToken::new();
        token.cancel();
        server
            .serve(token)
            .timeout(Duration::from_secs(5))
            .await
            .expect("serve() must return promptly when the token is cancelled")
            .unwrap();

        // Shutdown closes the tracker so no new sessions can be spawned
        assert!(server.tracker.is_closed());
    }

    #[tokio::test]
    async fn test_run_returns_on_cancelled_token() {
        let server = Server::new(loopback(), cfg(), metrics()).unwrap();

        let token = CancellationToken::new();
        token.cancel();
        Run::run(&server, token)
            .timeout(Duration::from_secs(5))
            .await
            .expect("run() must return promptly when the token is cancelled")
            .unwrap();

        assert!(server.tracker.is_closed());
    }

    #[tokio::test]
    async fn test_serve_accepts_multiple_connections() {
        let server = Server::new(loopback(), cfg(), metrics()).unwrap();
        let addr = server.listen_addr;

        let token = CancellationToken::new();
        let handle = tokio::spawn({
            let token = token.child_token();
            async move { server.serve(token).await }
        });

        // The accept loop must keep serving after the first connection
        let mut streams = vec![];
        for _ in 0..3 {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            assert_eq!(read_reply(&mut stream, GREETING.len()).await, GREETING);
            streams.push(stream);
        }

        // The session is alive and responds to commands
        let stream = &mut streams[0];
        stream.write_all(b"NOOP\r\n").await.unwrap();
        assert!(read_reply(stream, 4).await.starts_with("250"));

        // Cancelling the token shuts down both the acceptor and the sessions
        token.cancel();
        handle
            .timeout(Duration::from_secs(10))
            .await
            .expect("server must shut down")
            .unwrap()
            .unwrap();
    }
}
