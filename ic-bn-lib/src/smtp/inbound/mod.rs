pub mod ehlo;
pub mod mail_from;
pub mod manager;
pub mod rcpt_to;
pub mod session;

use std::{
    fmt::{self, Display},
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use fqdn::FQDN;
use ic_bn_lib_common::types::http::TlsInfo;
use mail_auth::MessageAuthenticator;
use rustls::ServerConfig;
use smtp_proto::{
    EXT_8BIT_MIME, EXT_CHUNKING, EXT_ENHANCED_STATUS_CODES, EXT_PIPELINING, EXT_SIZE,
    EXT_SMTP_UTF8, EXT_START_TLS, EhloResponse, Error as SmtpError,
    request::receiver::{
        BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, RequestReceiver,
    },
};
use strum::Display;
use uuid::Uuid;

use crate::{
    network::AsyncReadWrite,
    smtp::{
        DeliversMail, DummyDeliveryAgent, DummyRecipientResolver, ResolvesRecipient,
        address::EmailAddress,
    },
};

pub(crate) const MAX_REPLY_LEN: usize = 256;

#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Fmt error: {0}")]
    Fmt(#[from] fmt::Error),
    #[error("Timed out")]
    Timeout,
    #[error("{0}")]
    SmtpError(#[from] SmtpError),
    #[error("Session terminated by client (QUIT)")]
    Quit,
    #[error("Client is sending before greeting")]
    SendsBeforeGreeting,
    #[error("Too many messages per session")]
    TooManyMessagesPerSession,
    #[error("Session transfer quota ({0} bytes) was exceeded")]
    TransferQuotaExceeded(usize),
    #[error("Session TTL ({0}s) was exceeded")]
    TtlExceeded(u64),
    #[error("Too many errors")]
    TooManyErrors,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Indicates if a session needs to be upgraded to TLS
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionUpgrade {
    No,
    StartTls,
}

pub type SessionResult<T> = Result<T, SessionError>;

/// Session TLS mode
#[derive(Clone, Debug)]
pub enum SessionTlsMode {
    Disabled,
    Allowed(Arc<ServerConfig>),
    Required(Arc<ServerConfig>),
}

impl SessionTlsMode {
    pub const fn enabled(&self) -> bool {
        matches!(self, Self::Allowed(_) | Self::Required(_))
    }

    pub const fn required(&self) -> bool {
        matches!(self, Self::Required(_))
    }
}

/// SMTP session config
#[derive(Clone)]
pub struct SessionConfig {
    hostname: String,
    greeting: Bytes,
    helo: Bytes,
    ehlo: Bytes,
    ehlo_tls: Bytes,

    max_message_size: usize,
    pub max_recipients: usize,
    pub max_session_duration: Duration,
    pub max_session_data: usize,
    pub max_errors: usize,
    pub max_messages_per_session: usize,
    pub max_received_headers: usize,

    pub verify_ehlo_hostname: bool,
    pub verify_sender_domain: bool,
    pub verify_reverse_ip: bool,
    pub verify_reverse_ip_strict: bool,
    pub verify_spf: bool,
    pub verify_dkim: bool,
    pub verify_dkim_strict: bool,
    pub greeting_delay: Option<Duration>,

    pub timeout: Duration,
    pub tls_mode: SessionTlsMode,

    pub authenticator: Arc<MessageAuthenticator>,
    pub recipient_resolver: Arc<dyn ResolvesRecipient>,
    pub delivery_agent: Arc<dyn DeliversMail>,
}

impl SessionConfig {
    pub fn new(hostname: &str, max_message_size: usize) -> Self {
        let greeting = Bytes::from(format!("220 {hostname} ESMTP IC SMTP Gateway\r\n"));
        let helo = Bytes::from(format!("250 {hostname} you had me at HELO\r\n"));
        let (ehlo, ehlo_tls) = Self::generate_ehlo(hostname, max_message_size);

        Self {
            hostname: hostname.into(),
            greeting,
            helo,
            ehlo,
            ehlo_tls,

            max_message_size,
            max_recipients: 5,
            max_session_duration: Duration::from_secs(600),
            max_session_data: 50 * 1024 * 1024,
            max_errors: 5,
            max_messages_per_session: 5,
            max_received_headers: 50,

            verify_ehlo_hostname: false,
            verify_reverse_ip: false,
            verify_reverse_ip_strict: false,
            verify_sender_domain: false,
            verify_spf: false,
            verify_dkim: false,
            verify_dkim_strict: false,

            greeting_delay: None,
            timeout: Duration::from_secs(30),

            tls_mode: SessionTlsMode::Disabled,

            // SAFETY: this never fails
            authenticator: Arc::new(MessageAuthenticator::new_cloudflare().unwrap()),
            recipient_resolver: Arc::new(DummyRecipientResolver),
            delivery_agent: Arc::new(DummyDeliveryAgent),
        }
    }

    /// Generates all required HELO/EHLO bodies in advance
    fn generate_ehlo(hostname: &str, max_message_size: usize) -> (Bytes, Bytes) {
        let mut response = EhloResponse::new(hostname);
        response.capabilities = EXT_ENHANCED_STATUS_CODES
            | EXT_8BIT_MIME
            | EXT_SMTP_UTF8
            | EXT_CHUNKING
            | EXT_SIZE
            | EXT_PIPELINING;
        response.size = max_message_size;

        // EHLO w/o STARTTLS
        let mut ehlo = Vec::new();
        response.write(&mut ehlo).ok();

        // EHLO with STARTTLS
        let mut ehlo_tls = Vec::new();
        response.capabilities |= EXT_START_TLS;
        response.write(&mut ehlo_tls).ok();

        (Bytes::from(ehlo), Bytes::from(ehlo_tls))
    }
}

/// SMTP session state
#[derive(Display)]
pub enum SessionState {
    /// Need to send greeting
    Greeting,
    /// Default - command/response
    Request(RequestReceiver),
    /// ASCII data reception
    Data(DataReceiver),
    /// Binary data reception
    Bdat(BdatReceiver),
    /// Too long request received - blackhole
    RequestTooLarge(DummyLineReceiver),
    /// Too large data received - blackhole
    DataTooLarge(DummyDataReceiver),
    /// Dummy
    None,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::Request(RequestReceiver::default())
    }
}

/// SMTP dynamic session data
#[derive(Debug, Default)]
pub struct SessionData {
    reverse_ip_verified: bool,
    ehlo_hostname: Option<FQDN>,
    mail_from: Option<EmailAddress>,
    rcpt_to: Vec<EmailAddress>,
    message: Vec<u8>,
}

/// SMTP session counters
#[derive(Debug)]
pub struct SessionCounters {
    valid_until: Instant,
    bytes_ingested: usize,
    messages_queued: usize,
    errors: usize,
}

impl SessionCounters {
    fn new(ttl: Duration) -> Self {
        Self {
            valid_until: Instant::now() + ttl,
            bytes_ingested: 0,
            messages_queued: 0,
            errors: 0,
        }
    }
}

/// SMTP Session
pub struct Session<S: AsyncReadWrite> {
    id: Uuid,
    remote_ip: IpAddr,
    stream: S,
    state: SessionState,
    data: SessionData,
    counters: SessionCounters,
    cfg: Arc<SessionConfig>,
    tls_info: Option<TlsInfo>,
}

impl<S: AsyncReadWrite> Display for Session<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SMTP/Session({}){}",
            self.remote_ip,
            if self.tls_info.is_some() { "/TLS" } else { "" }
        )
    }
}

impl<S: AsyncReadWrite> Session<S> {
    pub fn new(remote_ip: IpAddr, stream: S, cfg: Arc<SessionConfig>) -> Self {
        Self {
            id: Uuid::now_v7(),
            remote_ip,
            stream,
            state: SessionState::Greeting,
            data: SessionData::default(),
            counters: SessionCounters::new(cfg.max_session_duration),
            cfg,
            tls_info: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, sync::Mutex};

    use async_trait::async_trait;
    use fqdn::fqdn;
    use ic_bn_lib_common::types::http::ListenerOpts;
    use mail_parser::{Addr, Address, MessageParser};
    use mail_send::{SmtpClientBuilder, mail_builder::MessageBuilder};
    use rustls::{ClientConfig, pki_types::ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio_rustls::TlsConnector;
    use tokio_util::sync::CancellationToken;

    use crate::{
        email,
        network::listener::listen_tcp,
        smtp::{
            DeliveryError, EmailMessage, RecipientPolicy, RecipientResolveError,
            inbound::manager::SessionManager, server::Server,
        },
        tests::{TEST_CERT_1, TEST_KEY_1},
        tls::{resolver::StubResolver, verify::NoopServerCertVerifier},
    };

    use super::*;

    #[derive(Debug, Default)]
    pub struct TestDeliveryAgent(Mutex<Option<EmailMessage>>, Option<DeliveryError>);

    #[async_trait]
    impl DeliversMail for TestDeliveryAgent {
        async fn deliver_mail(&self, message: EmailMessage) -> Result<(), DeliveryError> {
            if let Some(e) = &self.1 {
                return Err(e.clone());
            }

            *self.0.lock().unwrap() = Some(message);
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct TestRecipientResolver(
        EmailAddress,
        Option<EmailAddress>,
        Option<Vec<EmailAddress>>,
    );

    #[async_trait]
    impl ResolvesRecipient for TestRecipientResolver {
        async fn resolve_recipient(
            &self,
            _from: &EmailAddress,
            rcpt: &EmailAddress,
        ) -> Result<RecipientPolicy, RecipientResolveError> {
            assert_eq!(rcpt, &self.0);
            if let Some(v) = &self.1 {
                return Ok(RecipientPolicy::Rewrite(v.clone()));
            }

            if let Some(v) = &self.2 {
                return Ok(RecipientPolicy::Expand(v.clone()));
            }

            Ok(RecipientPolicy::Accept)
        }
    }

    fn create_session<S: AsyncReadWrite>(
        stream: S,
        greeting_delay: Option<Duration>,
    ) -> Session<S> {
        let mut cfg = SessionConfig::new("test", 512);
        cfg.max_errors = 5;
        cfg.greeting_delay = greeting_delay;
        cfg.max_messages_per_session = 3;
        cfg.max_session_data = 8192;
        cfg.max_recipients = 3;

        Session::new(IpAddr::from_str("1.1.1.1").unwrap(), stream, Arc::new(cfg))
    }

    fn create_basic_stream() -> tokio_test::io::Builder {
        let mut builder = tokio_test::io::Builder::new();

        builder.write(b"220 test ESMTP IC SMTP Gateway\r\n")
            .read(b"HELO foo.bar\r\n")
            .write(b"250 test you had me at HELO\r\n")
            .read(b"EHLO foo.bar\r\n")
            .write(b"250-test you had me at EHLO\r\n250-SMTPUTF8\r\n250-SIZE 512\r\n250-PIPELINING\r\n250-ENHANCEDSTATUSCODES\r\n250-CHUNKING\r\n250 8BITMIME\r\n");

        builder
    }

    fn stream_send_message(b: &mut tokio_test::io::Builder) {
        b.read(b"MAIL FROM:<foo@bar>\r\n")
            .write(b"250 2.1.0 OK\r\n")
            .read(b"RCPT TO:<dead@beef>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"DATA\r\n")
            .write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
            .read(b"foobarmessage\r\n.\r\n")
            .write(b"250 2.0.0 Message (13 bytes) queued with id 00000000-0000-0000-0000-000000000000\r\n");
    }

    #[tokio::test]
    async fn test_ehlo_required() {
        let stream = tokio_test::io::Builder::new()
            .write(b"220 test ESMTP IC SMTP Gateway\r\n")
            .read(b"MAIL FROM:<a@b>\r\n")
            .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
    }

    #[tokio::test]
    async fn test_pipelining() {
        let mut builder = create_basic_stream();
        let stream = builder
            .read(b"MAIL FROM:<a@a>\r\nRCPT TO:<a@b>\r\nDATA\r\n")
            .write(b"250 2.1.0 OK\r\n250 2.1.5 OK\r\n354 Start mail input; end with <CRLF>.<CRLF>\r\n")
            .read(b"foobarmessage\r\n.\r\n")
            .write(b"250 2.0.0 Message (13 bytes) queued with id 00000000-0000-0000-0000-000000000000\r\n")
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
    }

    #[tokio::test]
    async fn test_basic_session() {
        let mut builder = create_basic_stream();
        builder
            .read(b"RCPT TO:<a@a>\r\n")
            .write(b"503 5.5.1 MAIL FROM is required first.\r\n")
            .read(b"MAIL FROM:<a@a>\r\n")
            .write(b"250 2.1.0 OK\r\n")
            .read(b"MAIL FROM:<a@a>\r\n")
            .write(b"503 5.5.1 Multiple MAIL FROM commands are not allowed.\r\n")
            .read(b"DATA\r\n")
            .write(b"503 5.5.1 RCPT TO is required first.\r\n")
            .read(b"RSET\r\n")
            .write(b"250 2.0.0 OK\r\n")
            .read(b"NOOP\r\n")
            .write(b"250 2.0.0 OK\r\n")
            .read(b"FOOB\r\n")
            .write(b"500 5.5.1 Invalid command.\r\n")
            .read(b"HELP\r\n")
            .write(b"502 5.5.1 Command not implemented.\r\n");

        stream_send_message(&mut builder);
        let stream = builder
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
    }

    #[tokio::test]
    async fn test_client_sends_before_greeting() {
        let stream = tokio_test::io::Builder::new()
            .read(b"EHLO foo.bar\r\n")
            .write(b"501 5.7.1 Client sent command before greeting banner.\r\n")
            .build();

        let mut session = create_session(stream, Some(Duration::from_millis(100)));

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::SendsBeforeGreeting
        ));
    }

    #[tokio::test]
    async fn test_bdat() {
        let stream = create_basic_stream()
            .read(b"MAIL FROM:<foo@bar>\r\n")
            .write(b"250 2.1.0 OK\r\n")
            .read(b"RCPT TO:<dead@beef>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"BDAT 10\r\n")
            .read(b"01234")
            .read(b"56789")
            .write(b"250 2.6.0 Chunk accepted.\r\n")
            .read(b"BDAT 10\r\n")
            .read(b"987")
            .read(b"654")
            .read(b"3210")
            .write(b"250 2.6.0 Chunk accepted.\r\n")
            .read(b"BDAT 10 LAST\r\n")
            .read(b"0123456789")
            .write(b"250 2.0.0 Message (30 bytes) queued with id 00000000-0000-0000-0000-000000000000\r\n")
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let agent = Arc::new(TestDeliveryAgent::default());
        let resolver = TestRecipientResolver(
            "dead@beef".try_into().unwrap(),
            Some("bar@baz".try_into().unwrap()),
            None,
        );

        let mut cfg = SessionConfig::new("test", 512);
        cfg.delivery_agent = agent.clone();
        cfg.recipient_resolver = Arc::new(resolver);

        let mut session = Session::new(IpAddr::from_str("1.1.1.1").unwrap(), stream, Arc::new(cfg));

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));

        // Make sure the agent gets the correct mail
        assert_eq!(
            agent.0.lock().unwrap().clone(),
            Some(EmailMessage {
                id: Uuid::nil(),
                ehlo_hostname: fqdn!("foo.bar"),
                mail_from: "foo@bar".try_into().unwrap(),
                rcpt_to: vec!["bar@baz".try_into().unwrap()],
                body: b"012345678998765432100123456789".to_vec(),
            })
        );
    }

    #[tokio::test]
    async fn test_data() {
        let mut builder = create_basic_stream();
        stream_send_message(&mut builder);

        let stream = builder
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let agent = Arc::new(TestDeliveryAgent::default());
        let resolver = TestRecipientResolver(
            "dead@beef".try_into().unwrap(),
            Some("bar@baz".try_into().unwrap()),
            None,
        );

        let mut cfg = SessionConfig::new("test", 512);
        cfg.delivery_agent = agent.clone();
        cfg.recipient_resolver = Arc::new(resolver);

        let mut session = Session::new(IpAddr::from_str("1.1.1.1").unwrap(), stream, Arc::new(cfg));

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));

        // Make sure the agent gets the correct mail
        assert_eq!(
            agent.0.lock().unwrap().clone(),
            Some(EmailMessage {
                id: Uuid::nil(),
                ehlo_hostname: fqdn!("foo.bar"),
                mail_from: email!("foo@bar"),
                rcpt_to: vec![email!("bar@baz")],
                body: b"foobarmessage".to_vec(),
            })
        )
    }

    #[tokio::test]
    async fn test_expand() {
        let mut builder = create_basic_stream();
        stream_send_message(&mut builder);

        let stream = builder
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let agent = Arc::new(TestDeliveryAgent::default());
        let resolver = TestRecipientResolver(
            "dead@beef".try_into().unwrap(),
            None,
            Some(vec![
                "dead@dead".try_into().unwrap(),
                "bar@bax".try_into().unwrap(),
            ]),
        );

        let mut cfg = SessionConfig::new("test", 512);
        cfg.delivery_agent = agent.clone();
        cfg.recipient_resolver = Arc::new(resolver);

        let mut session = Session::new(IpAddr::from_str("1.1.1.1").unwrap(), stream, Arc::new(cfg));

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));

        // Make sure the agent gets the correct mail
        assert_eq!(
            agent.0.lock().unwrap().clone(),
            Some(EmailMessage {
                id: Uuid::nil(),
                ehlo_hostname: fqdn!("foo.bar"),
                mail_from: email!("foo@bar"),
                rcpt_to: vec![email!("dead@beef"), email!("dead@dead"), email!("bar@bax"),],
                body: b"foobarmessage".to_vec(),
            })
        )
    }

    #[tokio::test]
    async fn test_max_recipients() {
        let stream = create_basic_stream()
            .read(b"MAIL FROM:<foo@bar>\r\n")
            .write(b"250 2.1.0 OK\r\n")
            .read(b"RCPT TO:<a@b>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"RCPT TO:<c@d>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"RCPT TO:<c@d>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"RCPT TO:<d@e>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"RCPT TO:<e@f>\r\n")
            .write(b"455 4.5.3 Too many recipients.\r\n")
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
    }

    #[tokio::test]
    async fn test_max_message_size() {
        let stream = create_basic_stream()
            .read(b"MAIL FROM:<foo@bar>\r\n")
            .write(b"250 2.1.0 OK\r\n")
            .read(b"RCPT TO:<baz@baz>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"DATA\r\n")
            .write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
            .read(format!("{}\r\n.\r\n", "1".repeat(513)).as_bytes())
            .write(b"552 5.3.4 Message too big, we accept up to 512 bytes.\r\n")
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
    }

    #[tokio::test]
    async fn test_max_messages_per_session() {
        let mut builder = create_basic_stream();
        stream_send_message(&mut builder);
        stream_send_message(&mut builder);
        stream_send_message(&mut builder);

        let stream = builder
            .read(b"MAIL FROM:<foo@bar>\r\n")
            .write(b"250 2.1.0 OK\r\n")
            .read(b"RCPT TO:<dead@beef>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"DATA\r\n")
            .write(b"452 4.4.5 Maximum number of messages per session exceeded.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::TooManyMessagesPerSession
        ));
    }

    #[tokio::test]
    async fn test_max_errors() {
        let stream = tokio_test::io::Builder::new()
            .write(b"220 test ESMTP IC SMTP Gateway\r\n")
            .read(b"FOO\r\n")
            .write(b"500 5.5.1 Invalid command.\r\n")
            .read(b"FOO\r\n")
            .write(b"500 5.5.1 Invalid command.\r\n")
            .read(b"FOO\r\n")
            .write(b"500 5.5.1 Invalid command.\r\n")
            .read(b"FOO\r\n")
            .write(b"500 5.5.1 Invalid command.\r\n")
            .read(b"FOO\r\n")
            .write(b"500 5.5.1 Invalid command.\r\n")
            .read(b"FOO\r\n")
            .write(b"500 5.5.1 Invalid command.\r\n")
            .read(b"FOO\r\n")
            .write(b"452 4.3.2 Too many errors.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::TooManyErrors
        ));
    }

    #[tokio::test]
    async fn test_request_too_large() {
        let stream = tokio_test::io::Builder::new()
            .write(b"220 test ESMTP IC SMTP Gateway\r\n")
            .read(format!("EHLO {}", "1".repeat(2048)).as_bytes())
            .read(format!("{}\r\n", "1".repeat(2048)).as_bytes())
            .write(b"554 5.3.4 Line is too long.\r\n")
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
    }

    #[tokio::test]
    async fn test_max_session_transfer_quota() {
        let stream = tokio_test::io::Builder::new()
            .write(b"220 test ESMTP IC SMTP Gateway\r\n")
            .read(format!("EHLO {}\r\n", "1".repeat(8192)).as_bytes())
            .write(b"452 4.7.28 Session transfer quota exceeded.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::TransferQuotaExceeded(_)
        ));
    }

    #[tokio::test]
    async fn test_starttls() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        // Use an in-memory pipe
        let (stream1, mut stream2) = duplex(8192);

        let rustls_server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(
                StubResolver::new(TEST_CERT_1.as_bytes(), TEST_KEY_1.as_bytes()).unwrap(),
            ));

        let mut cfg = SessionConfig::new("test", 512);
        cfg.tls_mode = SessionTlsMode::Required(Arc::new(rustls_server_cfg));

        tokio::spawn(async move {
            SessionManager::handle_connection(
                stream1,
                SocketAddr::from_str("1.1.1.1:123").unwrap(),
                Arc::new(cfg),
                CancellationToken::new(),
            )
            .await;
        });

        let mut buf = vec![0; 8192];

        let r = stream2.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..r], b"220 test ESMTP IC SMTP Gateway\r\n");

        // Make sure EHLO advertises 250-STARTTLS
        stream2.write_all(b"EHLO foo.bar\r\n").await.unwrap();
        let r = stream2.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..r], b"250-test you had me at EHLO\r\n250-STARTTLS\r\n250-SMTPUTF8\r\n250-SIZE 512\r\n250-PIPELINING\r\n250-ENHANCEDSTATUSCODES\r\n250-CHUNKING\r\n250 8BITMIME\r\n");

        // Make sure TLS is required by the server due to SessionTlsMode::Required
        stream2.write_all(b"MAIL FROM:<a@b>\r\n").await.unwrap();
        let r = stream2.read(&mut buf).await.unwrap();
        assert_eq!(
            &buf[..r],
            b"503 5.5.1 TLS is required to submit mail on this server.\r\n"
        );

        // Fire up TLS handshake
        stream2.write_all(b"STARTTLS\r\n").await.unwrap();
        let r = stream2.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..r], b"220 2.0.0 Ready to start TLS.\r\n");

        let rustls_client_cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier::default()))
            .with_no_client_auth();
        let tls_connector = TlsConnector::from(Arc::new(rustls_client_cfg));
        let mut tls_stream = tls_connector
            .connect(ServerName::try_from("foo").unwrap(), stream2)
            .await
            .unwrap();

        // Make sure there's no 250-STARTTLS and 250-REQUIRETLS in EHLO anymore inside TLS session
        tls_stream.write_all(b"EHLO foo.bar\r\n").await.unwrap();
        let r = tls_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..r], b"250-test you had me at EHLO\r\n250-SMTPUTF8\r\n250-SIZE 512\r\n250-PIPELINING\r\n250-ENHANCEDSTATUSCODES\r\n250-CHUNKING\r\n250 8BITMIME\r\n");

        // No TLS-in-TLS allowed
        tls_stream.write_all(b"STARTTLS\r\n").await.unwrap();
        let r = tls_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..r], b"504 5.7.4 Already in TLS mode.\r\n");

        // Now MAIL FROM should work
        tls_stream.write_all(b"MAIL FROM:<a@b>\r\n").await.unwrap();
        let r = tls_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..r], b"250 2.1.0 OK\r\n");

        // All good
        tls_stream.write_all(b"QUIT\r\n").await.unwrap();
        let r = tls_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..r], b"221 2.0.0 Bye.\r\n");
    }

    #[tokio::test]
    async fn test_with_smtp_client() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();

        let rustls_server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(
                StubResolver::new(TEST_CERT_1.as_bytes(), TEST_KEY_1.as_bytes()).unwrap(),
            ));

        let agent = Arc::new(TestDeliveryAgent::default());

        // Listen on the random free port
        let listener = listen_tcp("127.0.0.1:0".parse().unwrap(), ListenerOpts::default()).unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut cfg = SessionConfig::new("test", 10 * 1024 * 1024);
        cfg.delivery_agent = agent.clone();
        cfg.tls_mode = SessionTlsMode::Allowed(Arc::new(rustls_server_cfg));

        let server = Server::new_with_listener(listener, cfg).unwrap();

        tokio::spawn(async move {
            server.serve(CancellationToken::new()).await.unwrap();
        });

        let message = MessageBuilder::new()
            .from(("John Doe", "john@doe.com"))
            .to(("Jane Doe", "jane@doe.com"))
            .subject("Hello")
            .text_body("Blah");

        let mut client = SmtpClientBuilder::new("127.0.0.1", port)
            .unwrap()
            .implicit_tls(false)
            .helo_host("foo.bar")
            .allow_invalid_certs()
            .connect()
            .await
            .unwrap();

        // Try some commands
        client.noop().await.unwrap();
        client.rset().await.unwrap();

        // Make sure we have the required caps
        let caps = client.capabilities("foo.bar", false).await.unwrap();
        assert_eq!(
            caps.capabilities,
            EXT_SMTP_UTF8
                | EXT_8BIT_MIME
                | EXT_CHUNKING
                | EXT_ENHANCED_STATUS_CODES
                | EXT_SIZE
                | EXT_PIPELINING
        );

        client.send(message).await.unwrap();

        // Make sure the agent gets the correct mail
        let msg = agent.0.lock().unwrap().clone().unwrap();
        assert_eq!(msg.id, Uuid::nil());
        assert_eq!(msg.ehlo_hostname, "foo.bar");
        assert_eq!(msg.mail_from, "john@doe.com");
        assert_eq!(msg.rcpt_to, vec!["jane@doe.com"]);

        let parsed = MessageParser::new().parse(&msg.body).unwrap();
        assert_eq!(parsed.subject(), Some("Hello"));
        assert_eq!(
            *parsed.from().unwrap(),
            Address::List(vec![Addr::new(Some("John Doe"), "john@doe.com")])
        );
        assert_eq!(
            *parsed.to().unwrap(),
            Address::List(vec![Addr::new(Some("Jane Doe"), "jane@doe.com")])
        );
        assert_eq!(parsed.body_text(0).unwrap(), "Blah");
    }
}
