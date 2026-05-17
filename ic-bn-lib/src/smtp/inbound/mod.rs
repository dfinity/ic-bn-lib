pub mod ehlo;
pub mod mail_from;
pub mod manager;
pub mod rcpt_to;
pub mod session;

use std::{
    fmt::Display,
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;
use bytes::Bytes;
use fqdn::FQDN;
use ic_bn_lib_common::types::http::TlsInfo;
use mail_auth::MessageAuthenticator;
use rustls::ServerConfig;
use smtp_proto::{
    Error as SmtpError,
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

#[derive(thiserror::Error, Debug)]
pub enum SessionError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
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
pub enum SessionTlsMode {
    Disabled,
    Allowed(Arc<ServerConfig>),
    Required(Arc<ServerConfig>),
}

/// SMTP session config
pub struct SessionConfig {
    hostname: String,
    greeting: Bytes,

    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_session_duration: Duration,
    pub max_session_data: usize,
    pub max_errors: usize,
    pub max_messages_per_session: usize,

    pub verify_ehlo_hostname: bool,
    pub verify_sender_domain: bool,
    pub verify_reverse_ip: bool,
    pub verify_spf: bool,
    pub helo_delay: Option<Duration>,

    pub timeout: Duration,
    pub tls_mode: SessionTlsMode,

    pub authenticator: Arc<MessageAuthenticator>,
    pub recipient_resolver: Arc<dyn ResolvesRecipient>,
    pub delivery_agent: Arc<dyn DeliversMail>,
}

impl SessionConfig {
    pub fn new(hostname: &str) -> Self {
        let greeting = format!("220 {hostname} ESMTP IC SMTP Gateway\r\n");

        Self {
            hostname: hostname.into(),
            greeting: Bytes::from(greeting),
            max_message_size: 10 * 1024 * 1024,
            max_recipients: 5,
            max_session_duration: Duration::from_secs(600),
            max_session_data: 50 * 1024 * 1024,
            max_errors: 5,
            max_messages_per_session: 5,
            verify_ehlo_hostname: false,
            verify_reverse_ip: false,
            verify_sender_domain: false,
            verify_spf: false,
            helo_delay: None,
            timeout: Duration::from_secs(30),
            tls_mode: SessionTlsMode::Disabled,
            // SAFETY: this never fails
            authenticator: Arc::new(MessageAuthenticator::new_cloudflare().unwrap()),
            recipient_resolver: Arc::new(DummyRecipientResolver),
            delivery_agent: Arc::new(DummyDeliveryAgent),
        }
    }

    pub const fn tls_enabled(&self) -> bool {
        matches!(
            self.tls_mode,
            SessionTlsMode::Allowed(_) | SessionTlsMode::Required(_)
        )
    }

    pub const fn tls_required(&self) -> bool {
        matches!(self.tls_mode, SessionTlsMode::Required(_))
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
    pub ehlo_hostname: Option<FQDN>,
    pub mail_from: Option<EmailAddress>,
    pub rcpt_to: AHashSet<EmailAddress>,
    pub message: Vec<u8>,
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
        write!(f, "SMTP/Session({})", self.remote_ip)
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
    use std::str::FromStr;

    use async_trait::async_trait;
    use fqdn::fqdn;
    use tokio_util::sync::CancellationToken;

    use crate::smtp::{DeliveryError, Message};

    use super::*;

    #[derive(Debug)]
    pub struct TestDeliveryAgent(Option<Message>, Option<DeliveryError>);

    #[async_trait]
    impl DeliversMail for TestDeliveryAgent {
        async fn deliver_mail(&self, message: Message) -> Result<(), DeliveryError> {
            if let Some(e) = &self.1 {
                return Err(e.clone());
            }

            if let Some(v) = &self.0 {
                assert_eq!(v, &message);
            }

            Ok(())
        }
    }

    fn create_session<S: AsyncReadWrite>(stream: S, helo_delay: Option<Duration>) -> Session<S> {
        let mut cfg = SessionConfig::new("test");
        cfg.max_errors = 5;
        cfg.max_message_size = 512;
        cfg.helo_delay = helo_delay;
        cfg.max_messages_per_session = 3;
        cfg.max_session_data = 1024;
        cfg.max_recipients = 3;

        Session::new(IpAddr::from_str("1.1.1.1").unwrap(), stream, Arc::new(cfg))
    }

    fn create_basic_stream() -> tokio_test::io::Builder {
        let mut builder = tokio_test::io::Builder::new();

        builder.write(b"220 test ESMTP IC SMTP Gateway\r\n")
            .read(b"HELO foo.bar\r\n")
            .write(b"250 test you had me at HELO\r\n")
            .read(b"EHLO foo.bar\r\n")
            .write(b"250-test you had me at EHLO\r\n250-SMTPUTF8\r\n250-ENHANCEDSTATUSCODES\r\n250-CHUNKING\r\n250 8BITMIME\r\n");

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
    async fn test_data() {
        let mut builder = create_basic_stream();
        stream_send_message(&mut builder);

        let stream = builder
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let agent = TestDeliveryAgent(
            Some(Message {
                id: Uuid::nil(),
                ehlo_hostname: fqdn!("foo.bar"),
                mail_from: EmailAddress::from_str("foo@bar").unwrap(),
                rcpt_to: vec![EmailAddress::from_str("dead@beef").unwrap()],
                body: b"foobarmessage".to_vec(),
            }),
            None,
        );

        let mut cfg = SessionConfig::new("test");
        cfg.delivery_agent = Arc::new(agent);
        let mut session = Session::new(IpAddr::from_str("1.1.1.1").unwrap(), stream, Arc::new(cfg));

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
    }

    #[tokio::test]
    async fn test_bdat() {
        let stream = create_basic_stream()
            .read(b"MAIL FROM:<foo@bar>\r\n")
            .write(b"250 2.1.0 OK\r\n")
            .read(b"RCPT TO:<baz@baz>\r\n")
            .write(b"250 2.1.5 OK\r\n")
            .read(b"BDAT 10\r\n")
            .read(b"0123456789")
            .write(b"250 2.6.0 Chunk accepted.\r\n")
            .read(b"BDAT 10\r\n")
            .read(b"9876543210")
            .write(b"250 2.6.0 Chunk accepted.\r\n")
            .read(b"BDAT 10 LAST\r\n")
            .read(b"0123456789")
            .write(b"250 2.0.0 Message (30 bytes) queued with id 00000000-0000-0000-0000-000000000000\r\n")
            .read(b"QUIT\r\n")
            .write(b"221 2.0.0 Bye.\r\n")
            .build();

        let agent = TestDeliveryAgent(
            Some(Message {
                id: Uuid::nil(),
                ehlo_hostname: fqdn!("foo.bar"),
                mail_from: EmailAddress::from_str("foo@bar").unwrap(),
                rcpt_to: vec![EmailAddress::from_str("baz@baz").unwrap()],
                body: b"012345678998765432100123456789".to_vec(),
            }),
            None,
        );

        let mut cfg = SessionConfig::new("test");
        cfg.delivery_agent = Arc::new(agent);
        let mut session = Session::new(IpAddr::from_str("1.1.1.1").unwrap(), stream, Arc::new(cfg));

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::Quit
        ));
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
            .write(b"552 5.3.4 Message too big for, we accept up to 512 bytes.\r\n")
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
            .write(b"452 4.3.2 Too many errors.\r\n")
            .build();

        let mut session = create_session(stream, None);

        assert!(matches!(
            session.handle(CancellationToken::new()).await.unwrap_err(),
            SessionError::TooManyErrors
        ));
    }
}
