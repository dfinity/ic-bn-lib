use std::{fmt::Display, io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use ic_bn_lib_common::{traits::Run, types::http::ListenerOpts};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker, time::FutureExt};
use tracing::{info, warn};

use crate::{
    network::listener::listen_tcp,
    smtp::{
        Metrics,
        inbound::{SessionConfig, manager::SessionManager},
    },
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
                info!("{self}: New connection from {addr}");

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
