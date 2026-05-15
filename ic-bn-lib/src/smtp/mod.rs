use std::fmt::{Debug, Display};

use async_trait::async_trait;
use fqdn::FQDN;
use itertools::Itertools;
use tracing::warn;
use uuid::Uuid;

use crate::smtp::address::EmailAddress;

pub mod address;
pub mod ic;
pub mod inbound;
pub mod server;

/// Recipient resolution policy
pub enum RecipientPolicy {
    Accept,
    Rewrite(EmailAddress),
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
    Other(String),
}

/// Delivery error
#[derive(thiserror::Error, Debug)]
pub enum DeliveryError {
    #[error("{0}")]
    Temporary(String),
    #[error("{0}")]
    Permanent(String),
}

/// Low-level E-Mail representation
#[derive(Debug)]
pub struct Message {
    pub id: Uuid,
    pub ehlo_hostname: FQDN,
    pub mail_from: EmailAddress,
    pub rcpt_to: Vec<EmailAddress>,
    pub body: Vec<u8>,
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ehlo: {}, from: {}, to: {}, msg: {}",
            self.ehlo_hostname,
            self.mail_from,
            self.rcpt_to.iter().map(|x| x.to_string()).join(", "),
            String::from_utf8_lossy(&self.body)
        )
    }
}

/// Looks up the given recipient & applies `RecipientPolicy` policy
#[async_trait]
pub trait ResolvesRecipient: Send + Sync + Debug {
    async fn resolve_recipient(
        &self,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError>;
}

/// Delivers the E-Mail message
#[async_trait]
pub trait DeliversMail: Send + Sync + Debug {
    async fn deliver_mail(&self, message: Message) -> Result<(), DeliveryError>;
}

#[derive(Debug)]
pub struct DummyRecipientResolver;

#[async_trait]
impl ResolvesRecipient for DummyRecipientResolver {
    async fn resolve_recipient(
        &self,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError> {
        warn!("DummyRecipientResolver: {rcpt}");
        Ok(RecipientPolicy::Accept)
    }
}

#[derive(Debug)]
pub struct DummyDeliveryAgent;

#[async_trait]
impl DeliversMail for DummyDeliveryAgent {
    async fn deliver_mail(&self, message: Message) -> Result<(), DeliveryError> {
        warn!("DummyDeliveryAgent: {message}");
        Ok(())
    }
}
