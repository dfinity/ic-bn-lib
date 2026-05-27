use std::fmt::{Debug, Display};

use ::candid::{Decode, Encode, Principal};
use anyhow::Context as _;
use async_trait::async_trait;
use derive_new::new;
use ic_agent::Agent;
use mail_parser::MessageParser;
use tracing::debug;

use crate::smtp::ic::{
    candid::{Header, Message, SmtpRequest, SmtpResponse},
    delivery_agent::IcSmtpDeliveryAgentError,
};

pub mod candid;
pub mod delivery_agent;

/// Trait to execute IC SMTP Request
#[async_trait]
pub trait ExecutesIcSmtpRequest: Send + Sync + Debug {
    async fn canister_request(
        &self,
        canister_id: Principal,
        request: SmtpRequest,
        validate: bool,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError>;
}

/// Executes IC SMTP requests through IC Agent
#[derive(new, Debug)]
pub struct IcSmtpRequestExecutor(Agent);

#[async_trait]
impl ExecutesIcSmtpRequest for IcSmtpRequestExecutor {
    async fn canister_request(
        &self,
        canister_id: Principal,
        ic_smtp_request: SmtpRequest,
        validate: bool,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
        debug!("{self}: {canister_id}: sending IC SMTP request: '{ic_smtp_request:?}'");

        let arg = Encode!(&ic_smtp_request).context("unable to encode SMTP request")?;

        let resp = if validate {
            self.0
                .query(&canister_id, "smtp_request_validate")
                .with_arg(arg)
                .call()
                .await?
        } else {
            self.0
                .update(&canister_id, "smtp_request")
                .with_arg(arg)
                .call_and_wait()
                .await?
        };

        let ic_smtp_response =
            Decode!(&resp, SmtpResponse).context("unable to decode SMTP response")?;
        debug!("{self}: {canister_id}: got IC SMTP response: '{ic_smtp_response:?}'");

        Ok(ic_smtp_response)
    }
}

impl Display for IcSmtpRequestExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IcSmtpRequestExecutor")
    }
}

/// Parses raw MIME email into IC SMTP Message
pub fn parse_email(raw: &[u8]) -> Result<Message, IcSmtpDeliveryAgentError> {
    let parsed = MessageParser::new()
        .parse(raw)
        // Make sure there's at least one standard header present
        .filter(|p| p.headers().iter().any(|h| !h.name.is_other()))
        .ok_or(IcSmtpDeliveryAgentError::Parser(
            "No parsable message found".into(),
        ))?;

    let headers = parsed
        .headers_raw()
        .map(|(k, v)| Header {
            name: k.into(),
            value: v.into(),
        })
        .collect::<Vec<_>>();

    // Get the offset to the beginning of the body
    let body_offset = parsed.root_part().offset_body as usize;

    // In case of an empty body the offeset would be == len
    let body = if body_offset >= raw.len() {
        vec![]
    } else {
        raw[body_offset..].into()
    };

    Ok(Message { headers, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_parser() {
        let raw = indoc! {r#"
            From: Some One <someone@example.com>
            To: John Doe <john@doe.com>
            MIME-Version: 1.0
            Content-Type: multipart/mixed;
                    boundary="XXXXboundary text"
            DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
                d=newsletter2.foo.bar; s=elaine; t=1779173482;
                bh=P1hWhNvLxYPQvK4IuGO72BKkVgfo5OkCVlIHCyLXvmI=;
                h=Date:X-CSA-Complaints:To:From:Reply-To:Subject:Feedback-ID:
                 CFBL-Feedback-ID:CFBL-Address:List-Unsubscribe:
                 List-Unsubscribe-Post;
                b=Eh4/u+8dKXri3jwPO1s6Zk6PwV2h5H6y0PGPn/FLVo/LhwlJbfGStSFLBja4nll8f
                 J5xqDmnlbijjqjXMODiIXPTmqYrfGbbcS5WSCmOyFKhdwGqlAkOOlAXTRkju7QkbtO
                 E5MpnYd4kPHnRC0MuyetIMr6CuQxrR2BGKq4LWB0=

            This is a multipart message in MIME format.

            --XXXXboundary text
            Content-Type: text/plain

            this is the body text

            --XXXXboundary text
            Content-Type: text/plain;
            Content-Disposition: attachment;
                    filename="test.txt"

            this is the attachment text

            --XXXXboundary text--        
        "#};

        let msg = parse_email(raw.as_bytes()).unwrap();

        // Make sure all headers are in place
        assert!(
            msg.headers
                .iter()
                .any(|x| x.name == "From" && x.value == " Some One <someone@example.com>\n")
        );
        // Make sure all headers are in place
        assert!(
            msg.headers
                .iter()
                .any(|x| x.name == "To" && x.value == " John Doe <john@doe.com>\n")
        );
        assert!(
            msg.headers
                .iter()
                .any(|x| x.name == "MIME-Version" && x.value == " 1.0\n")
        );
        assert!(msg.headers.iter().any(|x| x.name == "Content-Type"
            && x.value == " multipart/mixed;\n        boundary=\"XXXXboundary text\"\n"));

        let dkim_header = [
            " v=1; a=rsa-sha256; c=relaxed/relaxed;",
            "    d=newsletter2.foo.bar; s=elaine; t=1779173482;",
            "    bh=P1hWhNvLxYPQvK4IuGO72BKkVgfo5OkCVlIHCyLXvmI=;",
            "    h=Date:X-CSA-Complaints:To:From:Reply-To:Subject:Feedback-ID:",
            "     CFBL-Feedback-ID:CFBL-Address:List-Unsubscribe:",
            "     List-Unsubscribe-Post;",
            "    b=Eh4/u+8dKXri3jwPO1s6Zk6PwV2h5H6y0PGPn/FLVo/LhwlJbfGStSFLBja4nll8f",
            "     J5xqDmnlbijjqjXMODiIXPTmqYrfGbbcS5WSCmOyFKhdwGqlAkOOlAXTRkju7QkbtO",
            "     E5MpnYd4kPHnRC0MuyetIMr6CuQxrR2BGKq4LWB0=\n",
        ]
        .join("\n");
        assert!(
            msg.headers
                .iter()
                .any(|x| { x.name == "DKIM-Signature" && x.value == dkim_header })
        );

        let body = indoc! {r#"
            This is a multipart message in MIME format.

            --XXXXboundary text
            Content-Type: text/plain

            this is the body text

            --XXXXboundary text
            Content-Type: text/plain;
            Content-Disposition: attachment;
                    filename="test.txt"

            this is the attachment text

            --XXXXboundary text--        
        "#};

        assert_eq!(msg.body, body.as_bytes());

        // Empty
        assert!(matches!(
            parse_email(&[]).unwrap_err(),
            IcSmtpDeliveryAgentError::Parser(_)
        ));

        // No standard headers
        let raw = indoc! {r#"
            X-Header-1: Foo
            X-Header-2: Bar

            This is a multipart message in MIME format.
        "#};
        assert!(matches!(
            parse_email(raw.as_bytes()).unwrap_err(),
            IcSmtpDeliveryAgentError::Parser(_)
        ));
    }

    #[test]
    fn test_empty_body() {
        let raw = indoc! {r#"
            From: Igor Novgorodov <igor@novg.net>
            Content-Type: text/plain
            Content-Transfer-Encoding: 7bit
            Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3864.600.51.1.1\))
            Subject: II-Recovery-ae3eb3c2fff5b256
            X-Universally-Unique-Identifier: 1096E119-BB3F-4C1C-B43F-CE5FD830D693
            Message-Id: <A05648D4-1996-4B72-8D18-FC5122445F27@novg.net>
            Date: Wed, 27 May 2026 12:10:22 +0200
            To: register@beta.id.ai

        "#};

        parse_email(raw.as_bytes()).unwrap();
    }
}
