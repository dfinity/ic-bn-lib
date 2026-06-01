use std::fmt::{Debug, Display};

use async_trait::async_trait;
use bytes::Bytes;
use itertools::Itertools;
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
#[derive(thiserror::Error, Debug)]
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
#[derive(thiserror::Error, Clone, Debug)]
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
        message: EmailMessage,
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
        message: EmailMessage,
    ) -> Result<(), DeliveryError>;
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
        message: EmailMessage,
    ) -> Result<(), DeliveryError> {
        warn!("DummyDeliveryAgent: {message}");
        Ok(())
    }
}
