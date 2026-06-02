use std::{
    fmt::{Debug, Display},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::Bytes;
use itertools::Itertools;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use strum::{Display, IntoStaticStr};
use tracing::warn;
use uuid::Uuid;

use crate::smtp::{
    address::EmailAddress,
    inbound::{SessionError, SessionMeta},
};

pub mod address;
pub mod cli;
pub mod ic;
pub mod inbound;
pub mod server;

/// Recipient resolution policy
#[derive(Debug, Clone, Eq, PartialEq, Display)]
pub enum RecipientPolicy {
    #[strum(to_string = "Accept")]
    Accept,
    #[strum(to_string = "Rewrite({0})")]
    Rewrite(EmailAddress),
    #[strum(to_string = "Expand({0:?})")]
    Expand(Vec<EmailAddress>),
}

/// Recipient resolution error
#[derive(thiserror::Error, Debug, IntoStaticStr)]
pub enum RecipientResolveError {
    #[error("Unknown recipient")]
    UnknownRecipient,
    #[error("Unknown domain")]
    UnknownDomain,
    #[error("{0}")]
    Temporary(String),
    #[error("{0}")]
    Permanent(String),
}

/// Delivery error
#[derive(thiserror::Error, Clone, Debug, IntoStaticStr)]
pub enum DeliveryError {
    #[error("{0}")]
    Temporary(String),
    #[error("{0}")]
    Permanent(String),
}

/// Error that might happen during message validation or delivery
#[derive(thiserror::Error, Clone, Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum MessageError {
    #[error("Delivery failed: {0}")]
    DeliveryFailed(#[from] DeliveryError),
    #[error("Parsing failed")]
    ParsingFailed,
    #[error("Too many 'Received' headers")]
    TooManyReceivedHeaders,
    #[error("DKIM validation failed: {0}")]
    DkimValidationFailed(String),
}

/// Error that might happen during SMTP exchange
#[derive(thiserror::Error, Clone, Debug, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ProtocolError {
    #[error("Invalid EHLO hostname: {0}")]
    InvalidEhloHostname(String),
    #[error("Invalid command sequence: {0}")]
    InvalidSequenceOfCommands(String),
    #[error("Sender validation failed: {0}")]
    SenderValidationFailed(String),
    #[error("Recipient validation failed: {0}")]
    RecipientValidationFailed(String),
    #[error("Reverse IP validation failed: {0}")]
    ReverseIpValidationFailed(String),
    #[error("SPF validation failed: {0}")]
    SpfValidationFailed(String),
    #[error("Message too big: {0}")]
    MessageTooBig(String),
    #[error("SMTP protocol error: {0}")]
    SmtpError(String),
}

/// Low-level E-Mail representation
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EmailMessage {
    pub id: Uuid,
    pub mail_from: EmailAddress,
    pub rcpt_to: Vec<EmailAddress>,
    pub body: Bytes,
}

impl Display for EmailMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, from: {}, to: {}, msg: {}",
            self.id,
            self.mail_from,
            self.rcpt_to.iter().map(|x| x.to_string()).join(", "),
            String::from_utf8_lossy(&self.body)
                .replace('\n', "\\n")
                .replace('\r', "\\r")
        )
    }
}

/// Looks up the given recipient & applies `RecipientPolicy` policy
#[async_trait]
pub trait ResolvesRecipient: Send + Sync + Debug {
    async fn resolve_recipient(
        &self,
        from: &EmailAddress,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError>;
}

/// Notifies about events
#[async_trait]
pub trait ReceivesNotifications: Send + Sync + Debug {
    /// Notify when the message is queued or the validation failed
    async fn notify_message(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
        error: Option<MessageError>,
    );
    /// Notify when the protocol error happens
    async fn notify_protocol_error(&self, meta: SessionMeta, error: ProtocolError);
    /// Notify when the session is finished
    async fn notify_session_finish(&self, meta: SessionMeta, error: Option<SessionError>);
}

/// Delivers the E-Mail message
#[async_trait]
pub trait DeliversMail: Send + Sync + Debug {
    async fn deliver_mail(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
    ) -> Result<(), DeliveryError>;
}

#[derive(Clone)]
pub struct Metrics {
    bytes_rx: IntCounterVec,
    bytes_tx: IntCounterVec,
    commands: IntCounterVec,
    replies: IntCounterVec,
    messages: IntCounterVec,
    protocol_errors: IntCounterVec,
    sessions_open: IntGaugeVec,
    sessions_processed: IntCounterVec,
    session_duration: HistogramVec,
    message_size: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const LABELS: &[&str] = &["ip_family", "tls_proto"];

        Self {
            bytes_rx: register_int_counter_vec_with_registry!(
                format!("smtp_bytes_rx"),
                format!("Number of bytes received"),
                LABELS,
                registry
            )
            .unwrap(),

            bytes_tx: register_int_counter_vec_with_registry!(
                format!("smtp_bytes_tx"),
                format!("Number of bytes sent"),
                LABELS,
                registry
            )
            .unwrap(),

            commands: register_int_counter_vec_with_registry!(
                format!("smtp_commands"),
                format!("Number of SMTP commands received"),
                &[LABELS[0], LABELS[1], "command"],
                registry
            )
            .unwrap(),

            replies: register_int_counter_vec_with_registry!(
                format!("smtp_replies"),
                format!("Number of SMTP replies sent"),
                &[LABELS[0], LABELS[1], "code", "ext"],
                registry
            )
            .unwrap(),

            messages: register_int_counter_vec_with_registry!(
                format!("smtp_messages"),
                format!("Number of SMTP messages submitted"),
                &[LABELS[0], LABELS[1], "error"],
                registry
            )
            .unwrap(),

            message_size: register_histogram_vec_with_registry!(
                format!("smtp_message_size"),
                format!("Size of the SMTP messages in bytes"),
                LABELS,
                vec![1024.0, 16384.0, 131072.0, 524288.0, 2097152.0],
                registry
            )
            .unwrap(),

            protocol_errors: register_int_counter_vec_with_registry!(
                format!("smtp_protocol_errors"),
                format!("Number of SMTP protocol errors"),
                &[LABELS[0], LABELS[1], "error"],
                registry
            )
            .unwrap(),

            sessions_open: register_int_gauge_vec_with_registry!(
                format!("smtp_sessions_open"),
                format!("Number of SMTP sessions currently open"),
                &[LABELS[0]],
                registry
            )
            .unwrap(),

            sessions_processed: register_int_counter_vec_with_registry!(
                format!("smtp_sessions_processed"),
                format!("Number of SMTP messages processed (already closed)"),
                &[LABELS[0], LABELS[1], "error"],
                registry
            )
            .unwrap(),

            session_duration: register_histogram_vec_with_registry!(
                format!("smtp_session_duration"),
                format!("Time in seconds that the session was open"),
                LABELS,
                vec![5.0, 10.0, 30.0, 60.0, 120.0],
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct DummyRecipientResolver;

#[async_trait]
impl ResolvesRecipient for DummyRecipientResolver {
    async fn resolve_recipient(
        &self,
        from: &EmailAddress,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError> {
        warn!("DummyRecipientResolver: from: {from}, to: {rcpt}");
        Ok(RecipientPolicy::Accept)
    }
}

#[derive(Debug)]
pub struct DummyDeliveryAgent;

#[async_trait]
impl DeliversMail for DummyDeliveryAgent {
    async fn deliver_mail(
        &self,
        _meta: SessionMeta,
        message: Arc<EmailMessage>,
    ) -> Result<(), DeliveryError> {
        warn!("DummyDeliveryAgent: {message}");
        Ok(())
    }
}
