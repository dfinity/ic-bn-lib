use std::{fmt::Display, str::FromStr, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use derive_new::new;
use ic_agent::Agent;
use mail_parser::MessageParser;

use crate::{
    custom_domains::LooksupCustomDomain,
    smtp::{
        DeliversMail, DeliveryError, Message, RecipientPolicy, RecipientResolveError,
        ResolvesRecipient,
        address::EmailAddress,
        ic::candid::{Envelope, SmtpRequest, SmtpResponse},
    },
};

#[derive(thiserror::Error, Debug)]
pub enum IcSmtpDeliveryAgentError {
    #[error("IC Agent error: {0}")]
    Agent(#[from] ic_agent::AgentError),
    #[error("Unable to parse message: {0}")]
    Parser(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, new)]
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
        let arg = Encode!(&request).context("unable to encode SMTP request")?;

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

        let resp = Decode!(&resp, SmtpResponse).context("unable to decode SMTP response")?;
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
        from: &EmailAddress,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError> {
        // Figure out which canister we should talk to
        let canister_id = self
            .resolve_canister(rcpt)
            .ok_or(RecipientResolveError::UnknownDomain)?;

        let req = SmtpRequest {
            envelope: Some(Envelope {
                from: from.into(),
                to: vec![rcpt.into()],
            }),
            message: None,
            gateway_flags: None,
        };

        let resp = self
            .canister_request(canister_id, req, true)
            .await
            .map_err(|e| RecipientResolveError::Temporary(e.to_string()))?;

        if let SmtpResponse::Err(e) = resp {
            // Code 550 indicates that the recipient is unknown
            if e.code == 550 {
                return Err(RecipientResolveError::UnknownRecipient);
            }

            if e.code >= 500 && e.code < 599 {
                return Err(RecipientResolveError::Permanent(e.message));
            }

            return Err(RecipientResolveError::Temporary(e.message));
        }

        Ok(RecipientPolicy::Accept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ahash::HashMap;
    use fqdn::{FQDN, fqdn};
    use ic_bn_lib_common::{principal, types::CustomDomain};

    #[derive(Debug)]
    struct TestDomainResolver(HashMap<FQDN, CustomDomain>);

    impl LooksupCustomDomain for TestDomainResolver {
        fn lookup_custom_domain(&self, hostname: &fqdn::Fqdn) -> Option<CustomDomain> {
            self.0.get(hostname).cloned()
        }
    }

    #[test]
    fn test_canister_resolver() {
        let resolver = TestDomainResolver(HashMap::from_iter([
            (
                fqdn!("foo.bar"),
                CustomDomain {
                    name: fqdn!("foo.bar"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
            ),
            (
                fqdn!("dead.beef"),
                CustomDomain {
                    name: fqdn!("dead.beef"),
                    canister_id: principal!("uqzsh-gqaaa-aaaaq-qaada-cai"),
                    timestamp: 0,
                },
            ),
        ]));

        let ic_agent = Agent::builder().with_url("http://foo").build().unwrap();
        let delivery_agent = IcSmtpDeliveryAgent::new(ic_agent, Arc::new(resolver));

        for (email, canister_id) in [
            (
                "foo@foo.bar",
                Some(principal!("qoctq-giaaa-aaaaa-aaaea-cai")),
            ),
            (
                "foo@dead.beef",
                Some(principal!("uqzsh-gqaaa-aaaaq-qaada-cai")),
            ),
            (
                "foo@lusdn-iiaaa-aaaam-qivpa-cai.icp0.io",
                Some(principal!("lusdn-iiaaa-aaaam-qivpa-cai")),
            ),
            ("foo@some-random-domain.org", None),
        ] {
            assert_eq!(
                delivery_agent.resolve_canister(&EmailAddress::from_str(email).unwrap()),
                canister_id
            );
        }
    }
}
