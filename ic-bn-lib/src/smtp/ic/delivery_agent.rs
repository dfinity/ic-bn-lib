use std::{fmt::Display, str::FromStr, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use ic_agent::Agent;

use crate::{
    custom_domains::LooksupCustomDomain,
    smtp::{
        DeliversMail, DeliveryError, Message, RecipientPolicy, RecipientResolveError,
        ResolvesRecipient,
        address::EmailAddress,
        ic::candid::{SmtpRequest, SmtpResponse},
    },
};

#[derive(thiserror::Error, Debug)]
pub enum IcSmtpDeliveryAgentError {
    #[error("IC Agent error: {0}")]
    Agent(#[from] ic_agent::AgentError),
    #[error("Candid error: {0}")]
    Candid(#[from] candid::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug)]
pub struct IcSmtpDeliveryAgent {
    agent: Agent,
    custom_domains: Arc<dyn LooksupCustomDomain>,
}

impl Display for IcSmtpDeliveryAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IcSmtpDeliveryAgent")
    }
}

impl IcSmtpDeliveryAgent {
    fn resolve_canister(&self, address: &EmailAddress) -> Option<Principal> {
        // First check if the target domain has a canister as 1st label.
        // This covers addresses like "foo@qoctq-giaaa-aaaaa-aaaea-cai.icp0.io"
        let lbl = address.domain.labels().next()?;
        if let Ok(v) = Principal::from_str(lbl) {
            // If it's a valid principal - return it
            return Some(v);
        }

        // Otherwise try to look it up as a custom domain
        self.custom_domains
            .lookup_custom_domain(&address.domain)
            .map(|x| x.canister_id)
    }

    async fn canister_request(
        &self,
        canister_id: Principal,
        request: SmtpRequest,
        validate: bool,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
        let arg = Encode!(&request)?;

        let resp = if validate {
            self.agent
                .query(&canister_id, "smtp_request_validate")
                .with_arg(arg)
                .call()
                .await?
        } else {
            self.agent
                .update(&canister_id, "smtp_request")
                .with_arg(arg)
                .call_and_wait()
                .await?
        };

        let resp = Decode!(&resp, SmtpResponse)?;
        Ok(resp)
    }
}

#[async_trait]
impl DeliversMail for IcSmtpDeliveryAgent {
    async fn deliver_mail(&self, message: Message) -> Result<(), DeliveryError> {
        Ok(())
    }
}

#[async_trait]
impl ResolvesRecipient for IcSmtpDeliveryAgent {
    async fn resolve_recipient(
        &self,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError> {
        Ok(RecipientPolicy::Accept)
    }
}
