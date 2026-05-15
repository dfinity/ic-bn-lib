use std::{net::SocketAddr, sync::Arc};

use derive_new::new;
use tokio::io::AsyncWriteExt;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{
    network::{AsyncReadWrite, tls_handshake},
    smtp::inbound::{Session, SessionData, SessionParams, SessionResult, SessionUpgrade},
};

/// Manages the lifetime of a single SMTP session.
///
/// Needed because the SMTP session can transition into TLS state
/// which requires external orchestration.
#[derive(new)]
pub struct SessionManager;

impl SessionManager {
    pub async fn handle_connection<S: AsyncReadWrite>(
        &self,
        stream: S,
        remote_addr: SocketAddr,
        params: Arc<SessionParams>,
        shutdown_token: CancellationToken,
    ) {
        let mut session = Session::new(remote_addr.ip(), stream, params);

        match session.handle(shutdown_token.child_token()).await {
            Ok(v) => match v {
                SessionUpgrade::No => {
                    session.stream.shutdown().await.ok();
                }

                SessionUpgrade::StartTls => {
                    let log_name = session.to_string();
                    match session.into_tls().await {
                        Ok(mut session) => {
                            if let Err(e) = session.handle(shutdown_token.child_token()).await {
                                info!("{session}: error: {e:#}");
                                session.stream.shutdown().await.ok();
                            }
                        }
                        Err(e) => {
                            info!("{log_name}: TLS handshake failed: {e:#}");
                        }
                    };
                }
            },

            Err(e) => {
                info!("{session}: error: {e:#}, closing connection");
                if let Err(e) = session.shutdown().await {
                    debug!("{session}: error closing connection: {e:#}");
                };
            }
        }
    }
}

impl<S: AsyncReadWrite> Session<S> {
    /// Converts the plain-text session into a TLS one by doing a TLS handshake
    pub async fn into_tls(self) -> SessionResult<Session<TlsStream<S>>> {
        // SAFETY: Code makes sure that we end up here only if tls_config is Some.
        // If we ever panic here - it should mean that the core logic is flawed.
        let (stream, tls_info) =
            tls_handshake(self.params.tls_config.clone().unwrap(), self.stream).await?;

        Ok(Session {
            id: self.id,
            remote_ip: self.remote_ip,
            stream,
            state: self.state,
            // According to the RFC we need to discard all session data
            // after switching into TLS mode.
            // https://datatracker.ietf.org/doc/html/rfc3207#section-4.2
            data: SessionData::default(),
            counters: self.counters,
            params: self.params,
            tls_info: Some(tls_info),
        })
    }
}
