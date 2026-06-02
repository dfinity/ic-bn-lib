use std::{net::SocketAddr, sync::Arc, time::Instant};

use tokio::io::AsyncWriteExt;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{
    IpFamily as _,
    network::{AsyncReadWrite, tls_handshake},
    smtp::{
        Metrics,
        inbound::{
            Session, SessionConfig, SessionData, SessionError, SessionResult, SessionTlsMode,
            SessionUpgrade,
        },
    },
};

/// Manages the lifetime of a single SMTP session.
///
/// It's needed because the SMTP session can transition into TLS state
/// which requires external orchestration.
pub struct SessionManager;

impl SessionManager {
    pub async fn handle_connection<S: AsyncReadWrite>(
        stream: S,
        remote_addr: SocketAddr,
        params: Arc<SessionConfig>,
        metrics: Metrics,
        shutdown_token: CancellationToken,
    ) {
        // Convert v6-mapped address to v4
        let remote_ip = remote_addr.ip().to_canonical();
        let mut session = Session::new(remote_ip, stream, params, metrics);

        session
            .metrics
            .sessions_open
            .with_label_values(&[remote_ip.family()])
            .inc();

        match session.handle(shutdown_token.child_token()).await {
            Ok(v) => match v {
                SessionUpgrade::No => {
                    Self::notify(&session, None).await;
                    session.stream.shutdown().await.ok();
                }
                SessionUpgrade::StartTls => {
                    Self::handle_connection_tls(session, shutdown_token.child_token()).await
                }
            },

            Err(e) => {
                if !matches!(e, SessionError::Quit) {
                    info!("{session}: error: {e:#}");
                }

                if let Err(e) = session.shutdown().await {
                    debug!("{session}: error closing connection: {e:#}");
                };

                Self::notify(&session, Some(e)).await;
            }
        }
    }

    /// Converts session into TLS mode & runs it
    async fn handle_connection_tls<S: AsyncReadWrite>(
        session: Session<S>,
        shutdown_token: CancellationToken,
    ) {
        let session_name = session.to_string();
        debug!("{session}: starting TLS handshake");

        match session.into_tls().await {
            Ok(mut session) => {
                debug!("{session}: TLS handshake succeeded");

                if let Err(e) = session.handle(shutdown_token.child_token()).await {
                    if !matches!(e, SessionError::Quit) {
                        info!("{session}: error: {e:#}");
                    }

                    if let Err(e) = session.shutdown().await {
                        debug!("{session}: error closing connection: {e:#}");
                    };

                    Self::notify(&session, Some(e)).await;
                }
            }

            Err(e) => {
                info!("{session_name}: TLS handshake failed: {e:#}");
            }
        };
    }

    async fn notify<S: AsyncReadWrite>(session: &Session<S>, error: Option<SessionError>) {
        let ip_family = session.remote_ip.family();

        let tls_proto = session
            .tls_info
            .as_ref()
            .map_or("", |x| x.protocol.as_str().unwrap_or_default());
        let error_lbl: &'static str = error.as_ref().map_or("", |x| x.into());
        session
            .metrics
            .sessions_processed
            .with_label_values(&[ip_family, tls_proto, error_lbl])
            .inc();
        session
            .metrics
            .sessions_open
            .with_label_values(&[ip_family])
            .dec();
        session
            .metrics
            .session_duration
            .with_label_values(&[ip_family, tls_proto])
            .observe(
                Instant::now()
                    .duration_since(session.counters.started)
                    .as_secs_f64(),
            );

        if let Some(v) = session.cfg.notifications_handler.clone() {
            let meta = session.meta();
            tokio::spawn(async move {
                v.notify_session_finish(meta, error).await;
            });
        }
    }
}

impl<S: AsyncReadWrite> Session<S> {
    /// Converts the plain-text session into a TLS one by doing a TLS handshake
    pub async fn into_tls(self) -> SessionResult<Session<TlsStream<S>>> {
        let ip_family = self.remote_ip.family();

        // SAFETY: We should end up here only if TLS is enabled.
        // It's better to panic otherwise.
        let tls_config = match &self.cfg.tls_mode {
            SessionTlsMode::Allowed(v) | SessionTlsMode::Required(v) => v.clone(),
            SessionTlsMode::Disabled => {
                unreachable!("Session::into_tls() called with TLS disabled")
            }
        };

        let meta = self.meta();
        let (stream, tls_info) = match tls_handshake(tls_config, self.stream).await {
            Ok(v) => v,
            Err(e) => {
                let error = SessionError::TlsHandshakeFailed(e.to_string());
                let error_str = e.to_string();
                let error_lbl: &'static str = (&error).into();

                // Session is partially consumed by `tls_handshake`, so we can't use `Manager::notify()`
                self.metrics
                    .sessions_processed
                    .with_label_values(&[ip_family, "", error_lbl])
                    .inc();
                self.metrics
                    .sessions_open
                    .with_label_values(&[ip_family])
                    .dec();

                if let Some(v) = self.cfg.notifications_handler.clone() {
                    tokio::spawn(async move {
                        v.notify_session_finish(
                            meta,
                            Some(SessionError::TlsHandshakeFailed(error_str)),
                        )
                        .await;
                    });
                }

                return Err(error);
            }
        };

        let tls_proto = tls_info.protocol.as_str().unwrap_or_default();

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
            cfg: self.cfg,
            tls_info: Some(tls_info),
            labels: [ip_family, tls_proto],
            metrics: self.metrics,
        })
    }
}
