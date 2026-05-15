pub mod ehlo;
pub mod mail_from;
pub mod manager;
pub mod rcpt_to;
pub mod session;

use std::{
    io,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;
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
    ProtocolError(String),
    #[error("{0}")]
    SmtpError(#[from] SmtpError),
    #[error("Session terminated by client (QUIT)")]
    Quit,
    #[error("Too many messages per session")]
    TooManyMessagesPerSession,
    #[error("Session transfer quota ({0}) was exceeded")]
    TransferQuotaExceeded(usize),
    #[error("Session TTL ({0}s) was exceeded")]
    TtlExceeded(u64),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionUpgrade {
    No,
    StartTls,
}

pub type SessionResult<T> = Result<T, SessionError>;

/// SMTP session parameters
pub struct SessionParams {
    pub hostname: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub max_session_duration: Duration,
    pub max_session_data: usize,
    pub max_errors: usize,
    pub max_messages_per_session: usize,
    pub verify_ehlo_hostname: bool,
    pub verify_spf: bool,
    pub verify_reverse_ip: bool,
    pub helo_delay: Option<Duration>,
    pub timeout: Duration,
    pub tls_config: Option<Arc<ServerConfig>>,
    pub authenticator: Arc<MessageAuthenticator>,
    pub recipient_resolver: Arc<dyn ResolvesRecipient>,
    pub delivery_agent: Arc<dyn DeliversMail>,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            hostname: "".into(),
            max_message_size: 10 * 1024 * 1024,
            max_recipients: 5,
            max_session_duration: Duration::from_secs(600),
            max_session_data: 50 * 1024 * 1024,
            max_errors: 5,
            max_messages_per_session: 5,
            verify_ehlo_hostname: false,
            verify_reverse_ip: false,
            verify_spf: false,
            helo_delay: None,
            timeout: Duration::from_secs(30),
            tls_config: None,
            // SAFETY: this never fails
            authenticator: Arc::new(MessageAuthenticator::new_cloudflare().unwrap()),
            recipient_resolver: Arc::new(DummyRecipientResolver),
            delivery_agent: Arc::new(DummyDeliveryAgent),
        }
    }
}

/// SMTP session state
#[derive(Display)]
pub enum SessionState {
    Greeting,
    Request(RequestReceiver),
    Data(DataReceiver),
    Bdat(BdatReceiver),
    RequestTooLarge(DummyLineReceiver),
    DataTooLarge(DummyDataReceiver),
    None,
}

impl Default for SessionState {
    fn default() -> Self {
        Self::Request(RequestReceiver::default())
    }
}

/// SMTP session data
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
    params: Arc<SessionParams>,
    tls_info: Option<TlsInfo>,
}
