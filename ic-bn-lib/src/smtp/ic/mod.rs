use mail_parser::MessageParser;

use crate::smtp::ic::{
    candid::{Header, Message},
    delivery_agent::IcSmtpDeliveryAgentError,
};

pub mod candid;
pub mod delivery_agent;

pub(crate) trait RequestsCanister {}

pub fn parse_email(raw: &[u8]) -> Result<Message, IcSmtpDeliveryAgentError> {
    let parsed = MessageParser::new()
        .parse(raw)
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

    let msg = Message {
        headers,
        body: raw[body_offset..].into(),
    };

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_parser() {
        let raw = indoc! {r#"
            From: Some One <someone@example.com>
            MIME-Version: 1.0
            Content-Type: multipart/mixed;
                    boundary="XXXXboundary text"
            DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
                d=newsletter2.louis.de; s=elaine; t=1779173482;
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

        let dkim_header = [
            " v=1; a=rsa-sha256; c=relaxed/relaxed;",
            "    d=newsletter2.louis.de; s=elaine; t=1779173482;",
            "    bh=P1hWhNvLxYPQvK4IuGO72BKkVgfo5OkCVlIHCyLXvmI=;",
            "    h=Date:X-CSA-Complaints:To:From:Reply-To:Subject:Feedback-ID:",
            "     CFBL-Feedback-ID:CFBL-Address:List-Unsubscribe:",
            "     List-Unsubscribe-Post;",
            "    b=Eh4/u+8dKXri3jwPO1s6Zk6PwV2h5H6y0PGPn/FLVo/LhwlJbfGStSFLBja4nll8f",
            "     J5xqDmnlbijjqjXMODiIXPTmqYrfGbbcS5WSCmOyFKhdwGqlAkOOlAXTRkju7QkbtO",
            "     E5MpnYd4kPHnRC0MuyetIMr6CuQxrR2BGKq4LWB0=\n",
        ]
        .join("\n");

        let msg = parse_email(raw.as_bytes()).unwrap();

        assert!(
            msg.headers
                .iter()
                .any(|x| x.name == "From" && x.value == " Some One <someone@example.com>\n")
        );
        assert!(
            msg.headers
                .iter()
                .any(|x| x.name == "MIME-Version" && x.value == " 1.0\n")
        );
        assert!(msg.headers.iter().any(|x| x.name == "Content-Type"
            && x.value == " multipart/mixed;\n        boundary=\"XXXXboundary text\"\n"));

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
    }
}
