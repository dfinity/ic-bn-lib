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
    smtp::inbound::{SessionError, SessionParams, SessionResult, manager::SessionManager},
};

/// Listens for new connections and creates sessions
pub struct Server {
    listen_addr: SocketAddr,
    listener: TcpListener,
    params: Arc<SessionParams>,
    tracker: TaskTracker,
}

impl Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SMTPServer({})", self.listen_addr)
    }
}

impl Server {
    pub fn new(listen_addr: SocketAddr, params: SessionParams) -> Result<Self, SessionError> {
        let listener = listen_tcp(listen_addr, ListenerOpts::default())?;

        Ok(Self {
            listen_addr,
            listener,
            params: Arc::new(params),
            tracker: TaskTracker::new(),
        })
    }

    async fn handle_accept(
        &self,
        res: io::Result<(TcpStream, SocketAddr)>,
        token: &CancellationToken,
    ) {
        match res {
            Ok((stream, addr)) => {
                info!("{self}: New connection from {addr}");

                let (manager, params, token) =
                    (SessionManager, self.params.clone(), token.child_token());

                self.tracker.spawn(async move {
                    manager.handle_connection(stream, addr, params, token).await;
                });
            }

            Err(e) => {
                warn!("{self}: Unable to accept connection: {e:#}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    pub async fn serve(&self, token: CancellationToken) -> SessionResult<()> {
        loop {
            select! {
                res = self.listener.accept() => {
                    self.handle_accept(res, &token).await;
                }

                () = token.cancelled() => {
                    self.tracker.close();
                    if self.tracker.wait().timeout(Duration::from_secs(60)).await.is_err() {
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
