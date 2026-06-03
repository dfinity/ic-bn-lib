use std::{net::SocketAddr, str::FromStr, sync::Mutex};

use async_trait::async_trait;
use ic_bn_lib_common::types::http::ListenerOpts;
use mail_parser::{Addr, Address, MessageParser};
use mail_send::{SmtpClientBuilder, mail_builder::MessageBuilder};
use prometheus::Registry;
use rustls::{ClientConfig, ProtocolVersion, pki_types::ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::{
    email,
    network::listener::listen_tcp,
    smtp::{
        DeliveryError, EmailMessage, MessageError, RecipientPolicy, RecipientResolveError,
        inbound::manager::SessionManager, server::Server,
    },
    tests::{TEST_CERT_1, TEST_KEY_1},
    tls::{resolver::StubResolver, verify::NoopServerCertVerifier},
};

use super::*;

#[derive(Debug, Default)]
pub struct TestDeliveryAgent(Mutex<Option<Arc<EmailMessage>>>, Option<DeliveryError>);

#[async_trait]
impl DeliversMail for TestDeliveryAgent {
    async fn deliver_mail(
        &self,
        _meta: SessionMeta,
        message: Arc<EmailMessage>,
    ) -> Result<(), DeliveryError> {
        if let Some(e) = &self.1 {
            return Err(e.clone());
        }

        *self.0.lock().unwrap() = Some(message);
        Ok(())
    }
}

#[allow(clippy::type_complexity)]
#[derive(Debug, Default)]
pub struct TestNotificationsReceiver {
    msg: Mutex<Option<(SessionMeta, Arc<EmailMessage>, Option<MessageError>)>>,
    sess: Mutex<Option<(SessionMeta, Option<SessionError>)>>,
    proto_error: Mutex<Option<(SessionMeta, ProtocolError)>>,
}

#[async_trait]
impl ReceivesSmtpNotifications for TestNotificationsReceiver {
    async fn notify_message(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
        _latency: Duration,
        error: Option<MessageError>,
    ) {
        *self.msg.lock().unwrap() = Some((meta, message, error));
    }

    async fn notify_protocol_error(&self, meta: SessionMeta, error: ProtocolError) {
        *self.proto_error.lock().unwrap() = Some((meta, error));
    }

    async fn notify_session_finish(&self, meta: SessionMeta, error: Option<SessionError>) {
        *self.sess.lock().unwrap() = Some((meta, error));
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

fn create_session<S: AsyncReadWrite>(stream: S, greeting_delay: Option<Duration>) -> Session<S> {
    let mut cfg = SessionConfig::new("test", 512);
    cfg.max_errors = 5;
    cfg.greeting_delay = greeting_delay;
    cfg.max_messages_per_session = 3;
    cfg.max_session_data = 8192;
    cfg.max_recipients = 3;

    Session::new(
        IpAddr::from_str("1.1.1.1").unwrap(),
        stream,
        Arc::new(cfg),
        Metrics::new(&Registry::new()),
    )
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
        .write(
            b"250 2.0.0 Message (13 bytes) queued with id 00000000-0000-0000-0000-000000000000\r\n",
        );
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
        .write(
            b"250 2.0.0 Message (13 bytes) queued with id 00000000-0000-0000-0000-000000000000\r\n",
        )
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
        .write(
            b"250 2.0.0 Message (30 bytes) queued with id 00000000-0000-0000-0000-000000000000\r\n",
        )
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

    let remote_ip = IpAddr::from_str("1.1.1.1").unwrap();
    let mut session = Session::new(
        remote_ip,
        stream,
        Arc::new(cfg),
        Metrics::new(&Registry::new()),
    );

    assert!(matches!(
        session.handle(CancellationToken::new()).await.unwrap_err(),
        SessionError::Quit
    ));

    // Make sure the agent gets the correct mail
    assert_eq!(
        agent.0.lock().unwrap().clone().unwrap().as_ref(),
        &EmailMessage {
            id: Uuid::nil(),
            mail_from: "foo@bar".try_into().unwrap(),
            rcpt_to: vec!["bar@baz".try_into().unwrap()],
            body: "012345678998765432100123456789".into(),
        }
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

    let remote_ip = IpAddr::from_str("1.1.1.1").unwrap();
    let mut session = Session::new(
        remote_ip,
        stream,
        Arc::new(cfg),
        Metrics::new(&Registry::new()),
    );

    assert!(matches!(
        session.handle(CancellationToken::new()).await.unwrap_err(),
        SessionError::Quit
    ));

    // Make sure the agent gets the correct mail
    assert_eq!(
        agent.0.lock().unwrap().clone().unwrap().as_ref(),
        &EmailMessage {
            id: Uuid::nil(),
            mail_from: email!("foo@bar"),
            rcpt_to: vec![email!("bar@baz")],
            body: "foobarmessage".into(),
        }
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

    let remote_ip = IpAddr::from_str("1.1.1.1").unwrap();
    let mut session = Session::new(
        remote_ip,
        stream,
        Arc::new(cfg),
        Metrics::new(&Registry::new()),
    );

    assert!(matches!(
        session.handle(CancellationToken::new()).await.unwrap_err(),
        SessionError::Quit
    ));

    // Make sure the agent gets the correct mail
    assert_eq!(
        agent.0.lock().unwrap().clone().unwrap().as_ref(),
        &EmailMessage {
            id: Uuid::nil(),
            mail_from: email!("foo@bar"),
            rcpt_to: vec![email!("dead@beef"), email!("dead@dead"), email!("bar@bax"),],
            body: "foobarmessage".into(),
        }
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
    rustls::crypto::aws_lc_rs::default_provider()
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
            Metrics::new(&Registry::new()),
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let rustls_server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            StubResolver::new(TEST_CERT_1.as_bytes(), TEST_KEY_1.as_bytes()).unwrap(),
        ));

    let agent = Arc::new(TestDeliveryAgent::default());
    let notification_handler = Arc::new(TestNotificationsReceiver::default());

    // Listen on the random free port
    let listener = listen_tcp("127.0.0.1:0".parse().unwrap(), ListenerOpts::default()).unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut cfg = SessionConfig::new("test", 10 * 1024 * 1024);
    cfg.delivery_agent = agent.clone();
    cfg.tls_mode = SessionTlsMode::Allowed(Arc::new(rustls_server_cfg));
    cfg.notifications_handler = Some(notification_handler.clone());

    let token = CancellationToken::new();
    let token_child = token.child_token();
    let server = Server::new_with_listener(listener, cfg, Metrics::new(&Registry::new())).unwrap();
    let server_handle = tokio::spawn(async move {
        server.serve(token_child).await.unwrap();
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
    // Send some bad command to emit a protocol error notification
    client.cmd(b"FOOBAR\r\n").await.ok();
    client.quit().await.unwrap();

    // Make sure the agent gets the correct mail
    let msg = agent.0.lock().unwrap().clone().unwrap();
    assert_eq!(msg.id, Uuid::nil());
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

    // Shutdown the server
    token.cancel();
    server_handle.await.unwrap();

    // Check notifications
    let (meta, msg, error) = notification_handler.msg.lock().unwrap().clone().unwrap();
    assert_eq!(meta.id, Uuid::nil());
    assert_eq!(meta.message_id, Uuid::nil());
    assert_eq!(msg.mail_from, "john@doe.com");
    assert_eq!(msg.rcpt_to, vec!["jane@doe.com"]);
    assert!(error.is_none());

    let (meta, error) = notification_handler.sess.lock().unwrap().take().unwrap();
    assert_eq!(meta.id, Uuid::nil());
    assert_eq!(meta.remote_ip, IpAddr::from_str("127.0.0.1").unwrap());
    assert!(matches!(meta.last_error, Some(ProtocolError::SmtpError(_))));
    assert_eq!(meta.tls_info.unwrap().protocol, ProtocolVersion::TLSv1_3);
    assert!(matches!(error, Some(SessionError::Quit)));

    // Error from the FOOBAR command
    let (meta, error) = notification_handler
        .proto_error
        .lock()
        .unwrap()
        .take()
        .unwrap();
    assert_eq!(meta.id, Uuid::nil());
    assert_eq!(meta.remote_ip, IpAddr::from_str("127.0.0.1").unwrap());
    assert!(matches!(error, ProtocolError::SmtpError(_)));
}

#[test]
fn test_session_error() {
    let s: &'static str = SessionError::Quit.into();
    assert_eq!(s, "quit");

    let s: &'static str = SessionError::SendsBeforeGreeting.into();
    assert_eq!(s, "sends_before_greeting");

    let s: &'static str = SessionError::TooManyMessagesPerSession.into();
    assert_eq!(s, "too_many_messages_per_session");
}
