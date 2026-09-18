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
                self.metrics
                    .session_duration
                    .with_label_values(&[ip_family, ""])
                    .observe(
                        Instant::now()
                            .duration_since(self.counters.started)
                            .as_secs_f64(),
                    );

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

#[cfg(test)]
mod test {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
        time::Duration,
    };

    use async_trait::async_trait;
    use fqdn::FQDN;
    use prometheus::Registry;
    use rustls::{ClientConfig, ProtocolVersion, pki_types::ServerName};
    use tokio::{
        io::{AsyncReadExt, duplex},
        sync::mpsc,
    };
    use tokio_rustls::TlsConnector;

    use crate::{
        smtp::{
            EmailMessage, MessageError, ProtocolError, ReceivesSmtpNotifications, SessionMeta,
            inbound::mail_from::test::{test_config, tls_server_config},
        },
        tls::verify::NoopServerCertVerifier,
    };

    use super::*;

    const GREETING: &[u8] = b"220 test ESMTP IC SMTP Gateway\r\n";

    /// Forwards session-finish notifications into a channel so the test can await them
    #[derive(Debug)]
    struct Notifications(mpsc::UnboundedSender<(SessionMeta, Option<SessionError>)>);

    #[async_trait]
    impl ReceivesSmtpNotifications for Notifications {
        async fn notify_message(
            &self,
            _: SessionMeta,
            _: Arc<EmailMessage>,
            _: Duration,
            _: Option<MessageError>,
        ) {
        }

        async fn notify_protocol_error(&self, _: SessionMeta, _: ProtocolError) {}

        async fn notify_session_finish(&self, meta: SessionMeta, error: Option<SessionError>) {
            let _ = self.0.send((meta, error));
        }
    }

    /// An IPv4-mapped IPv6 peer must be accounted for as plain IPv4 everywhere
    #[tokio::test]
    async fn test_handle_connection_canonicalizes_v6_mapped_address() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = test_config();
        cfg.notifications_handler = Some(Arc::new(Notifications(tx)));

        let metrics = Metrics::new(&Registry::new());
        let (server, mut client) = duplex(4096);
        let token = CancellationToken::new();

        let task = tokio::spawn({
            let (metrics, token) = (metrics.clone(), token.clone());
            async move {
                SessionManager::handle_connection(
                    server,
                    SocketAddr::from_str("[::ffff:1.2.3.4]:25").unwrap(),
                    Arc::new(cfg),
                    metrics,
                    token,
                )
                .await;
            }
        });

        let mut buf = vec![0; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], GREETING);
        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 1);
        assert_eq!(metrics.sessions_open.with_label_values(&["v6"]).get(), 0);

        // Shut the session down cleanly via the token
        token.cancel();
        task.await.unwrap();

        let (meta, error) = rx.recv().await.unwrap();
        assert_eq!(meta.remote_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(error.is_none(), "{error:?}");

        // The gauge must come back to zero & the session be counted without an error label
        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "", ""])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .session_duration
                .with_label_values(&["v4", ""])
                .get_sample_count(),
            1
        );
    }

    /// A client QUIT is an error from the session's point of view & gets its own label
    #[tokio::test]
    async fn test_handle_connection_reports_quit() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = test_config();
        cfg.notifications_handler = Some(Arc::new(Notifications(tx)));

        let metrics = Metrics::new(&Registry::new());
        let (server, mut client) = duplex(4096);

        let task = tokio::spawn({
            let metrics = metrics.clone();
            async move {
                SessionManager::handle_connection(
                    server,
                    SocketAddr::from_str("1.2.3.4:25").unwrap(),
                    Arc::new(cfg),
                    metrics,
                    CancellationToken::new(),
                )
                .await;
            }
        });

        let mut buf = vec![0; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], GREETING);

        client.write_all(b"QUIT\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"221 2.0.0 Bye.\r\n");
        task.await.unwrap();

        let (meta, error) = rx.recv().await.unwrap();
        assert_eq!(meta.remote_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(matches!(error, Some(SessionError::Quit)));

        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "", "quit"])
                .get(),
            1
        );
    }

    /// RFC 3207 4.2: everything learned before STARTTLS has to be thrown away,
    /// while the connection-level bookkeeping survives
    #[tokio::test]
    async fn test_into_tls_discards_session_data() {
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Allowed(tls_server_config());

        let (server, client) = duplex(64 * 1024);
        let remote_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let mut session = Session::new(
            remote_ip,
            server,
            Arc::new(cfg),
            Metrics::new(&Registry::new()),
        );

        // Pretend we're mid-transaction
        session.data.ehlo_hostname = Some(FQDN::from_str("foo.bar").unwrap());
        session.data.mail_from = Some("a@example.com".try_into().unwrap());
        session
            .data
            .rcpt_to
            .push("b@example.com".try_into().unwrap());
        session.data.message.extend_from_slice(b"partial");
        session.counters.bytes_tx = 42;
        session.counters.commands = 7;
        let id = session.id;

        let client_task = tokio::spawn(async move {
            let tls_cfg = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier::default()))
                .with_no_client_auth();

            TlsConnector::from(Arc::new(tls_cfg))
                .connect(ServerName::try_from("foo").unwrap(), client)
                .await
                .unwrap()
        });

        let session = session.into_tls().await.unwrap();
        let _client = client_task.await.unwrap();

        assert!(session.data.ehlo_hostname.is_none());
        assert!(session.data.mail_from.is_none());
        assert!(session.data.rcpt_to.is_empty());
        assert!(session.data.message.is_empty());

        assert_eq!(session.id, id);
        assert_eq!(session.remote_ip, remote_ip);
        assert_eq!(session.counters.bytes_tx, 42);
        assert_eq!(session.counters.commands, 7);

        let tls_info = session.tls_info.as_ref().expect("TLS info must be set");
        assert_eq!(tls_info.protocol, ProtocolVersion::TLSv1_3);
        // The metric labels get the negotiated protocol appended
        assert_eq!(session.labels, ["v4", "TLSv1_3"]);
    }

    #[tokio::test]
    async fn test_into_tls_handshake_failure() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Required(tls_server_config());
        cfg.notifications_handler = Some(Arc::new(Notifications(tx)));

        let (server, mut client) = duplex(4096);
        let metrics = Metrics::new(&Registry::new());
        let remote_ip = IpAddr::from_str("1.2.3.4").unwrap();
        let session = Session::new(remote_ip, server, Arc::new(cfg), metrics.clone());

        // `handle_connection` is the one that increments this, so do it by hand
        // to show that the failure path still balances it out
        metrics.sessions_open.with_label_values(&["v4"]).inc();

        let client_task = tokio::spawn(async move {
            client
                .write_all(b"definitely not a TLS ClientHello\r\n")
                .await
                .ok();
            client
        });

        let Err(error) = session.into_tls().await else {
            panic!("the TLS handshake must fail");
        };
        assert!(
            matches!(error, SessionError::TlsHandshakeFailed(_)),
            "{error:?}"
        );
        let _client = client_task.await.unwrap();

        let (meta, error) = rx.recv().await.unwrap();
        assert_eq!(meta.remote_ip, remote_ip);
        assert!(meta.tls_info.is_none());
        assert!(matches!(error, Some(SessionError::TlsHandshakeFailed(_))));

        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "", "tls_handshake_failed"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .session_duration
                .with_label_values(&["v4", ""])
                .get_sample_count(),
            1
        );
    }

    /// Reaching `into_tls()` without TLS configured is a programming error
    #[tokio::test]
    #[should_panic(expected = "Session::into_tls() called with TLS disabled")]
    async fn test_into_tls_panics_when_tls_is_disabled() {
        let (server, _client) = duplex(64);
        let session = Session::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            server,
            // `SessionTlsMode::Disabled` by default
            Arc::new(test_config()),
            Metrics::new(&Registry::new()),
        );

        let _ = session.into_tls().await;
    }

    /// A plain IPv6 peer keeps its address & gets the `v6` metric label
    #[tokio::test]
    async fn test_handle_connection_labels_ipv6_peers() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = test_config();
        cfg.notifications_handler = Some(Arc::new(Notifications(tx)));

        let metrics = Metrics::new(&Registry::new());
        let (server, mut client) = duplex(4096);

        let task = tokio::spawn({
            let metrics = metrics.clone();
            async move {
                SessionManager::handle_connection(
                    server,
                    SocketAddr::from_str("[2001:db8::1]:25").unwrap(),
                    Arc::new(cfg),
                    metrics,
                    CancellationToken::new(),
                )
                .await;
            }
        });

        let mut buf = vec![0; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], GREETING);
        assert_eq!(metrics.sessions_open.with_label_values(&["v6"]).get(), 1);
        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);

        client.write_all(b"QUIT\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"221 2.0.0 Bye.\r\n");
        task.await.unwrap();

        let (meta, error) = rx.recv().await.unwrap();
        assert_eq!(meta.remote_ip, IpAddr::from_str("2001:db8::1").unwrap());
        assert!(matches!(error, Some(SessionError::Quit)));

        assert_eq!(metrics.sessions_open.with_label_values(&["v6"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v6", "", "quit"])
                .get(),
            1
        );
    }

    /// An error other than QUIT goes down the same path: reply, close, notify
    #[tokio::test]
    async fn test_handle_connection_reports_an_idle_timeout() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = test_config();
        cfg.timeout = Duration::from_millis(200);
        cfg.notifications_handler = Some(Arc::new(Notifications(tx)));

        let metrics = Metrics::new(&Registry::new());
        let (server, mut client) = duplex(4096);

        let task = tokio::spawn({
            let metrics = metrics.clone();
            async move {
                SessionManager::handle_connection(
                    server,
                    SocketAddr::from_str("1.2.3.4:25").unwrap(),
                    Arc::new(cfg),
                    metrics,
                    CancellationToken::new(),
                )
                .await;
            }
        });

        // Say nothing at all & wait to be kicked out
        let mut buf = vec![0; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], GREETING);
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"221 2.0.0 Disconnecting due to inactivity.\r\n");
        task.await.unwrap();

        let (_, error) = rx.recv().await.unwrap();
        assert!(matches!(error, Some(SessionError::Timeout)), "{error:?}");

        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "", "timeout"])
                .get(),
            1
        );
    }

    /// Everything still has to balance out without a notifications handler
    #[tokio::test]
    async fn test_handle_connection_without_a_notifications_handler() {
        let cfg = test_config();
        assert!(cfg.notifications_handler.is_none());

        let metrics = Metrics::new(&Registry::new());
        let (server, mut client) = duplex(4096);

        let task = tokio::spawn({
            let metrics = metrics.clone();
            async move {
                SessionManager::handle_connection(
                    server,
                    SocketAddr::from_str("1.2.3.4:25").unwrap(),
                    Arc::new(cfg),
                    metrics,
                    CancellationToken::new(),
                )
                .await;
            }
        });

        let mut buf = vec![0; 256];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], GREETING);
        client.write_all(b"QUIT\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"221 2.0.0 Bye.\r\n");
        task.await.unwrap();

        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "", "quit"])
                .get(),
            1
        );
    }

    /// The whole STARTTLS round trip through the manager: the session that finishes
    /// is the TLS one, so the negotiated protocol ends up in the labels & the meta
    #[tokio::test]
    async fn test_handle_connection_starttls_reports_the_negotiated_protocol() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Allowed(tls_server_config());
        cfg.notifications_handler = Some(Arc::new(Notifications(tx)));

        let metrics = Metrics::new(&Registry::new());
        let (server, mut client) = duplex(64 * 1024);

        let task = tokio::spawn({
            let metrics = metrics.clone();
            async move {
                SessionManager::handle_connection(
                    server,
                    SocketAddr::from_str("1.2.3.4:25").unwrap(),
                    Arc::new(cfg),
                    metrics,
                    CancellationToken::new(),
                )
                .await;
            }
        });

        let mut buf = vec![0; 4096];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], GREETING);

        client.write_all(b"STARTTLS\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"220 2.0.0 Ready to start TLS.\r\n");

        let tls_cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier::default()))
            .with_no_client_auth();
        let mut client = TlsConnector::from(Arc::new(tls_cfg))
            .connect(ServerName::try_from("foo").unwrap(), client)
            .await
            .unwrap();

        client.write_all(b"QUIT\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"221 2.0.0 Bye.\r\n");
        task.await.unwrap();

        let (meta, error) = rx.recv().await.unwrap();
        assert!(matches!(error, Some(SessionError::Quit)));
        assert_eq!(
            meta.tls_info.as_ref().unwrap().protocol,
            ProtocolVersion::TLSv1_3
        );

        // The gauge was incremented once & decremented once, both with the plain
        // family label, while the processed counter carries the TLS protocol
        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "TLSv1_3", "quit"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "", "quit"])
                .get(),
            0
        );
        assert_eq!(
            metrics
                .session_duration
                .with_label_values(&["v4", "TLSv1_3"])
                .get_sample_count(),
            1
        );
    }

    /// If the client bails out after we agreed to STARTTLS the accounting still has
    /// to balance, and the failure is reported once
    #[tokio::test]
    async fn test_handle_connection_starttls_handshake_failure() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Allowed(tls_server_config());
        cfg.notifications_handler = Some(Arc::new(Notifications(tx)));

        let metrics = Metrics::new(&Registry::new());
        let (server, mut client) = duplex(4096);

        let task = tokio::spawn({
            let metrics = metrics.clone();
            async move {
                SessionManager::handle_connection(
                    server,
                    SocketAddr::from_str("1.2.3.4:25").unwrap(),
                    Arc::new(cfg),
                    metrics,
                    CancellationToken::new(),
                )
                .await;
            }
        });

        let mut buf = vec![0; 4096];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], GREETING);

        client.write_all(b"STARTTLS\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"220 2.0.0 Ready to start TLS.\r\n");

        // Not a ClientHello
        client
            .write_all(b"definitely not a TLS ClientHello\r\n")
            .await
            .unwrap();
        task.await.unwrap();

        let (meta, error) = rx.recv().await.unwrap();
        assert!(
            matches!(error, Some(SessionError::TlsHandshakeFailed(_))),
            "{error:?}"
        );
        assert!(meta.tls_info.is_none());
        // Only the one notification - the handshake failure isn't reported twice
        assert!(rx.try_recv().is_err());

        assert_eq!(metrics.sessions_open.with_label_values(&["v4"]).get(), 0);
        assert_eq!(
            metrics
                .sessions_processed
                .with_label_values(&["v4", "", "tls_handshake_failed"])
                .get(),
            1
        );
    }

    /// The protocol state machine is carried over into the TLS session - only the
    /// transaction data is dropped
    #[tokio::test]
    async fn test_into_tls_preserves_the_protocol_state() {
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Allowed(tls_server_config());
        cfg.max_recipients = 17;

        let (server, client) = duplex(64 * 1024);
        let session = Session::new(
            IpAddr::from_str("1.2.3.4").unwrap(),
            server,
            Arc::new(cfg),
            Metrics::new(&Registry::new()),
        );
        // A fresh session still owes the client a greeting
        assert_eq!(session.state.to_string(), "Greeting");

        let client_task = tokio::spawn(async move {
            let tls_cfg = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier::default()))
                .with_no_client_auth();

            TlsConnector::from(Arc::new(tls_cfg))
                .connect(ServerName::try_from("foo").unwrap(), client)
                .await
                .unwrap()
        });

        let session = session.into_tls().await.unwrap();
        let _client = client_task.await.unwrap();

        assert_eq!(session.state.to_string(), "Greeting");
        // The config is carried over rather than rebuilt
        assert_eq!(session.cfg.max_recipients, 17);
    }
}
