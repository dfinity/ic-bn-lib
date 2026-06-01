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
use hickory_resolver::net::NetError;
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
use strum::{Display, IntoStaticStr};
use uuid::Uuid;

use crate::{
    network::AsyncReadWrite,
    smtp::{
        DeliversMail, DummyDeliveryAgent, DummyRecipientResolver, EmailMessage, MessageError,
        ProtocolError, ReceivesNotifications, ResolvesRecipient, address::EmailAddress,
    },
};

pub(crate) const MAX_REPLY_LEN: usize = 256;

/// Error that leads to session termination.
/// The only "expected" error is `Quit` that is caused by the client QUIT
/// command.
#[derive(thiserror::Error, Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum SessionError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Fmt error: {0}")]
    Fmt(#[from] fmt::Error),
    #[error("Dns error: {0}")]
    Dns(#[from] NetError),
    #[error("Timed out")]
    Timeout,
    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),
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
    pub notifications_handler: Option<Arc<dyn ReceivesNotifications>>,
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
            notifications_handler: None,
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
#[derive(Clone, Debug)]
pub struct SessionData {
    message_id: Uuid,
    last_error: Option<ProtocolError>,
    reverse_ip_verified: bool,
    ehlo_hostname: Option<FQDN>,
    mail_from: Option<EmailAddress>,
    rcpt_to: Vec<EmailAddress>,
    message: Vec<u8>,
}

impl Default for SessionData {
    fn default() -> Self {
        Self {
            #[cfg(not(test))]
            message_id: Uuid::now_v7(),
            #[cfg(test)]
            message_id: Uuid::nil(),
            last_error: None,
            reverse_ip_verified: false,
            ehlo_hostname: None,
            mail_from: None,
            rcpt_to: vec![],
            message: vec![],
        }
    }
}

/// SMTP session counters
#[derive(Clone, Debug)]
pub struct SessionCounters {
    pub started: Instant,
    pub bytes_ingested: usize,
    pub messages_queued: usize,
    pub errors: usize,
}

impl SessionCounters {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes_ingested: 0,
            messages_queued: 0,
            errors: 0,
        }
    }
}

/// Session metadata for logging/notification purposes
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub id: Uuid,
    pub message_id: Uuid,
    pub remote_ip: IpAddr,
    pub tls_info: Option<TlsInfo>,
    pub counters: SessionCounters,
    pub last_error: Option<ProtocolError>,
    pub ehlo_hostname: Option<FQDN>,
    pub mail_from: Option<EmailAddress>,
    pub rcpt_to: Vec<EmailAddress>,
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
            #[cfg(not(test))]
            id: Uuid::now_v7(),
            #[cfg(test)]
            id: Uuid::nil(),
            remote_ip,
            stream,
            state: SessionState::Greeting,
            data: SessionData::default(),
            counters: SessionCounters::new(),
            cfg,
            tls_info: None,
        }
    }

    fn set_error(&mut self, error: ProtocolError) {
        self.data.last_error = Some(error.clone());
        self.counters.errors += 1;

        if let Some(v) = self.cfg.notifications_handler.clone() {
            let meta = self.meta();
            tokio::spawn(async move { v.notify_protocol_error(meta, error).await });
        }
    }

    fn notify_message(&self, msg: EmailMessage, error: Option<MessageError>) {
        if let Some(v) = self.cfg.notifications_handler.clone() {
            let meta = self.meta();
            tokio::spawn(async move {
                v.notify_message(meta, msg, error).await;
            });
        };
    }

    fn meta(&self) -> SessionMeta {
        SessionMeta {
            id: self.id,
            message_id: self.data.message_id,
            remote_ip: self.remote_ip,
            tls_info: self.tls_info.clone(),
            counters: self.counters.clone(),
            last_error: self.data.last_error.clone(),
            ehlo_hostname: self.data.ehlo_hostname.clone(),
            mail_from: self.data.mail_from.clone(),
            rcpt_to: self.data.rcpt_to.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
