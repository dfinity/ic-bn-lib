use std::fmt::{Debug, Display};

use async_trait::async_trait;
use fqdn::FQDN;
use itertools::Itertools;
use strum::Display;
use tracing::warn;
use uuid::Uuid;

use crate::smtp::address::EmailAddress;

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

/// Low-level E-Mail representation
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EmailMessage {
    pub id: Uuid,
    pub ehlo_hostname: FQDN,
    pub mail_from: EmailAddress,
    pub rcpt_to: Vec<EmailAddress>,
    pub body: Vec<u8>,
}

impl Display for EmailMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, ehlo: {}, from: {}, to: {}, msg: {}",
            self.id,
            self.ehlo_hostname,
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

/// Delivers the E-Mail message
#[async_trait]
pub trait DeliversMail: Send + Sync + Debug {
    async fn deliver_mail(&self, message: EmailMessage) -> Result<(), DeliveryError>;
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
    async fn deliver_mail(&self, message: EmailMessage) -> Result<(), DeliveryError> {
        warn!("DummyDeliveryAgent: {message}");
        Ok(())
    }
}
