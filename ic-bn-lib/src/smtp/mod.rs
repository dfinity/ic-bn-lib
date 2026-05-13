use async_trait::async_trait;

use crate::smtp::address::EmailAddress;

pub mod address;
pub mod ic;
pub mod session;

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

/// Looks up the given recipient & applies `RecipientPolicy` policy
#[async_trait]
pub trait ResolvesRecipient: Send + Sync {
    async fn resolve_recipient(
        &self,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError>;
}
