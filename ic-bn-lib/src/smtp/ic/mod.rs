use std::{
    fmt::{Debug, Display},
    sync::Arc,
    time::Duration,
};

use ::candid::{Decode, Encode, Principal};
use anyhow::Context as _;
use async_trait::async_trait;
use bytes::Bytes;
use derive_new::new;
use ic_agent::{Agent, AgentError};
use mail_parser::MessageParser;
use prometheus::{
    HistogramVec, IntCounter, IntCounterVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_counter_with_registry,
};
use tracing::debug;

use crate::smtp::{
    DeliveryError, EmailMessage, SessionMeta,
    ic::{
        candid::{
            Header, Message, SmtpCapabilities, SmtpRequest, SmtpResponse, SmtpUploadChunk,
            SmtpUploadChunkResponse, SmtpUploadCommit, SmtpUploadId, SmtpUploadStatusResponse,
        },
        delivery_agent::IcSmtpDeliveryAgentError,
    },
};

pub mod candid;
pub mod delivery_agent;
pub mod upload;

/// Destination canisters of the mail.
/// SMTP canister is equal to the original one
/// if there's no dedicated SMTP canister.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct DestCanister {
    pub smtp: Principal,
    pub orig: Principal,
    pub custom_domain: bool,
}

/// Trait to execute IC SMTP Request
///
/// The chunked-upload methods all default to reporting that the canister does
/// not implement them for the sake of backwards compatibility.
#[async_trait]
pub trait ExecutesIcSmtpRequest: Send + Sync + Debug {
    /// Sends [`SmtpRequest`] to the specified canister
    async fn canister_request(
        &self,
        canister_id: Principal,
        request: SmtpRequest,
        validate: bool,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError>;

    /// Asks the canister what it is willing to accept
    async fn canister_capabilities(
        &self,
        _canister_id: Principal,
    ) -> Result<SmtpCapabilities, IcSmtpDeliveryAgentError> {
        Err(IcSmtpDeliveryAgentError::Unsupported("smtp_capabilities"))
    }

    /// Uploads one body slice
    async fn canister_upload_chunk(
        &self,
        _canister_id: Principal,
        _chunk: &SmtpUploadChunk,
    ) -> Result<SmtpUploadChunkResponse, IcSmtpDeliveryAgentError> {
        Err(IcSmtpDeliveryAgentError::Unsupported("smtp_upload_chunk"))
    }

    /// Finalizes an upload
    async fn canister_upload_commit(
        &self,
        _canister_id: Principal,
        _commit: SmtpUploadCommit,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
        Err(IcSmtpDeliveryAgentError::Unsupported("smtp_upload_commit"))
    }

    /// Reads back the state of an upload. Used only to check a commit whose
    /// outcome is unknown - retrying could deliver the mail twice.
    async fn canister_upload_status(
        &self,
        _canister_id: Principal,
        _upload: SmtpUploadId,
    ) -> Result<SmtpUploadStatusResponse, IcSmtpDeliveryAgentError> {
        Err(IcSmtpDeliveryAgentError::Unsupported("smtp_upload_status"))
    }

    /// Best-effort release of an abandoned upload.
    /// The canister should expire the upload on its own.
    async fn canister_upload_abort(
        &self,
        _canister_id: Principal,
        _upload: SmtpUploadId,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
        Err(IcSmtpDeliveryAgentError::Unsupported("smtp_upload_abort"))
    }
}

/// Gets notifications about IC SMTP messages
#[async_trait]
pub trait ReceivesIcSmtpNotifications: Send + Sync + Debug {
    /// Notify when the message is sent to the canister
    async fn notify_ic_message(
        &self,
        meta: Arc<SessionMeta>,
        message: Arc<EmailMessage>,
        dest: DestCanister,
        latency: Duration,
        error: Option<DeliveryError>,
    );
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
        debug!(
            "{self}: {canister_id}: sending IC SMTP request (validate: {validate}): {}",
            describe_request(&ic_smtp_request)
        );

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

    async fn canister_capabilities(
        &self,
        canister_id: Principal,
    ) -> Result<SmtpCapabilities, IcSmtpDeliveryAgentError> {
        let resp = self
            .0
            .query(&canister_id, "smtp_capabilities")
            .with_arg(Encode!().context("unable to encode capabilities request")?)
            .call()
            .await?;

        let caps = Decode!(&resp, SmtpCapabilities).context("unable to decode capabilities")?;
        debug!("{self}: {canister_id}: capabilities: '{caps:?}'");

        Ok(caps)
    }

    async fn canister_upload_chunk(
        &self,
        canister_id: Principal,
        chunk: &SmtpUploadChunk,
    ) -> Result<SmtpUploadChunkResponse, IcSmtpDeliveryAgentError> {
        debug!(
            "{self}: {canister_id}: uploading chunk {}/{} ({} bytes, message_id: {})",
            chunk.index + 1,
            chunk.total_chunks,
            chunk.payload.len(),
            chunk.message_id
        );

        let arg = Encode!(chunk).context("unable to encode upload chunk")?;
        let resp = self
            .0
            .update(&canister_id, "smtp_upload_chunk")
            .with_arg(arg)
            .call_and_wait()
            .await?;

        Ok(Decode!(&resp, SmtpUploadChunkResponse).context("unable to decode chunk response")?)
    }

    async fn canister_upload_commit(
        &self,
        canister_id: Principal,
        commit: SmtpUploadCommit,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
        debug!(
            "{self}: {canister_id}: committing upload {} ({} chunks)",
            commit.message_id, commit.total_chunks
        );

        let arg = Encode!(&commit).context("unable to encode upload commit")?;
        let resp = self
            .0
            .update(&canister_id, "smtp_upload_commit")
            .with_arg(arg)
            .call_and_wait()
            .await?;

        let ic_smtp_response =
            Decode!(&resp, SmtpResponse).context("unable to decode commit response")?;
        debug!("{self}: {canister_id}: commit response: '{ic_smtp_response:?}'");

        Ok(ic_smtp_response)
    }

    async fn canister_upload_status(
        &self,
        canister_id: Principal,
        upload: SmtpUploadId,
    ) -> Result<SmtpUploadStatusResponse, IcSmtpDeliveryAgentError> {
        let arg = Encode!(&upload).context("unable to encode upload ref")?;
        let resp = self
            .0
            .query(&canister_id, "smtp_upload_status")
            .with_arg(arg)
            .call()
            .await?;

        Ok(Decode!(&resp, SmtpUploadStatusResponse).context("unable to decode upload status")?)
    }

    async fn canister_upload_abort(
        &self,
        canister_id: Principal,
        upload: SmtpUploadId,
    ) -> Result<SmtpResponse, IcSmtpDeliveryAgentError> {
        let arg = Encode!(&upload).context("unable to encode upload ref")?;
        let resp = self
            .0
            .update(&canister_id, "smtp_upload_abort")
            .with_arg(arg)
            .call_and_wait()
            .await?;

        Ok(Decode!(&resp, SmtpResponse).context("unable to decode abort response")?)
    }
}

impl Display for IcSmtpRequestExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IcSmtpRequestExecutor")
    }
}

#[derive(Clone, Debug)]
pub struct Metrics {
    canister_id_lookups: IntCounterVec,
    canister_id_lookup_latency: HistogramVec,
    smtp_requests: IntCounterVec,
    smtp_request_latency: HistogramVec,

    // Chunked upload metrics
    deliveries: IntCounterVec,
    capability_lookups: IntCounterVec,
    upload_calls: IntCounterVec,
    upload_call_latency: HistogramVec,
    upload_duration: HistogramVec,
    upload_chunk_retries: IntCounterVec,
    upload_bytes: IntCounter,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const CANISTER_LABELS: &[&str] =
            &["success", "custom_domain", "is_smtp_canister", "cached"];
        const REQUEST_LABELS: &[&str] = &["validate", "error"];
        const UPLOAD_LABELS: &[&str] = &["method", "error"];

        Self {
            canister_id_lookups: register_int_counter_vec_with_registry!(
                format!("smtp_ic_agent_canister_id_lookups"),
                format!("Number of canister ID lookups"),
                CANISTER_LABELS,
                registry
            )
            .unwrap(),

            canister_id_lookup_latency: register_histogram_vec_with_registry!(
                format!("smtp_ic_agent_canister_id_lookup_latency"),
                format!("Time it took to resolve the canister ID"),
                CANISTER_LABELS,
                vec![0.01, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6],
                registry
            )
            .unwrap(),

            smtp_requests: register_int_counter_vec_with_registry!(
                format!("smtp_ic_agent_smtp_requests"),
                format!("Number of IC SMTP requests"),
                REQUEST_LABELS,
                registry
            )
            .unwrap(),

            smtp_request_latency: register_histogram_vec_with_registry!(
                format!("smtp_ic_agent_smtp_request_latency"),
                format!("Time it took to execute IC SMTP request"),
                REQUEST_LABELS,
                vec![0.2, 0.4, 0.8, 1.6, 3.2, 6.4, 12.8, 25.6, 51.2, 102.4],
                registry
            )
            .unwrap(),

            deliveries: register_int_counter_vec_with_registry!(
                format!("smtp_ic_agent_deliveries"),
                format!("Number of message deliveries by transfer mode"),
                &["mode", "error"],
                registry
            )
            .unwrap(),

            capability_lookups: register_int_counter_vec_with_registry!(
                format!("smtp_ic_agent_capability_lookups"),
                format!("Number of canister SMTP capability lookups"),
                &["cached", "chunking"],
                registry
            )
            .unwrap(),

            upload_calls: register_int_counter_vec_with_registry!(
                format!("smtp_ic_agent_upload_calls"),
                format!("Number of chunked upload protocol calls"),
                UPLOAD_LABELS,
                registry
            )
            .unwrap(),

            upload_call_latency: register_histogram_vec_with_registry!(
                format!("smtp_ic_agent_upload_call_latency"),
                format!("Time it took to execute a single chunked upload call"),
                UPLOAD_LABELS,
                vec![0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0],
                registry
            )
            .unwrap(),

            upload_duration: register_histogram_vec_with_registry!(
                format!("smtp_ic_agent_upload_duration"),
                format!("Time it took to upload & commit a whole message"),
                &["error"],
                vec![1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 80.0, 160.0],
                registry
            )
            .unwrap(),

            upload_chunk_retries: register_int_counter_vec_with_registry!(
                format!("smtp_ic_agent_upload_chunk_retries"),
                format!("Number of chunk upload retries"),
                &["error"],
                registry
            )
            .unwrap(),

            upload_bytes: register_int_counter_with_registry!(
                format!("smtp_ic_agent_upload_bytes"),
                format!("Number of body bytes uploaded in chunks"),
                registry
            )
            .unwrap(),
        }
    }
}

/// Renders an `SmtpRequest` for logging without dumping the message body
pub fn describe_request(r: &SmtpRequest) -> String {
    let msg = r.message.as_ref().map_or_else(
        || "none".to_string(),
        |m| format!("{} headers, {} body bytes", m.headers.len(), m.body.len()),
    );

    let rcpts = r.envelope.as_ref().map_or(0, |e| e.to.len());

    format!(
        "message_id: {}, envelope: {rcpts} rcpt(s), message: {msg}",
        r.message_id.as_deref().unwrap_or("none")
    )
}

/// Check if the error means "this canister does not export that method"
pub fn is_missing_method(e: &IcSmtpDeliveryAgentError) -> bool {
    match e {
        IcSmtpDeliveryAgentError::Agent(
            AgentError::CertifiedReject { reject, .. }
            | AgentError::UncertifiedReject { reject, .. },
        ) => reject.error_code.as_deref() == Some("IC0536"),

        // Kept as belt-and-braces even though the replica never produces it here.
        IcSmtpDeliveryAgentError::Agent(AgentError::InvalidMethodError(_)) => true,

        _ => false,
    }
}

/// Check if the replica refused the message because it was too large
pub const fn is_payload_too_large(e: &IcSmtpDeliveryAgentError) -> bool {
    matches!(
        e,
        IcSmtpDeliveryAgentError::Agent(AgentError::HttpError(p)) if p.status == 413
    )
}

/// Check if the replica is rate-limiting or temporarily unavailable
pub const fn is_rate_limited(e: &IcSmtpDeliveryAgentError) -> bool {
    matches!(
        e,
        IcSmtpDeliveryAgentError::Agent(AgentError::HttpError(p))
            if p.status == 429 || p.status == 503
    )
}

/// Check if an update call's outcome is unknown
pub const fn is_ambiguous(e: &IcSmtpDeliveryAgentError) -> bool {
    match e {
        // Explicit reject
        IcSmtpDeliveryAgentError::Agent(
            AgentError::CertifiedReject { .. } | AgentError::UncertifiedReject { .. },
        ) => false,

        // Local errors (encoding etc)
        IcSmtpDeliveryAgentError::Agent(
            AgentError::CandidError(_)
            | AgentError::InvalidCborData(_)
            | AgentError::SigningError(_)
            | AgentError::UrlParseError(_)
            | AgentError::InvalidReplicaUrl(_)
            | AgentError::InvalidMethodError(_)
            | AgentError::PrincipalError(_),
        ) => false,

        IcSmtpDeliveryAgentError::Parser(_) => false,

        // 413 is an explicit refusal, other HTTP codes - who knows...
        IcSmtpDeliveryAgentError::Agent(AgentError::HttpError(p)) => p.status != 413,

        // Timeouts, transport errors, everything else: unknown
        _ => true,
    }
}

/// A parsed message that shares the original buffer instead of copying it
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedEmail {
    pub headers: Vec<Header>,
    pub body: Bytes,
}

impl ParsedEmail {
    /// Creates the owned `Message`
    pub fn to_message(&self) -> Message {
        Message {
            headers: self.headers.clone(),
            body: self.body.to_vec(),
        }
    }
}

/// Splits a raw message into its headers and the offset of the body
fn split_email(raw: &[u8]) -> Result<(Vec<Header>, usize), IcSmtpDeliveryAgentError> {
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

    // Get the offset to the beginning of the body.
    // In case of an empty body the offset would be == len.
    let body_offset = parsed.root_part().offset_body as usize;
    if body_offset > raw.len() {
        // Should never happen, unless the parser is broken
        return Err(IcSmtpDeliveryAgentError::Parser(
            "Body offset incorrect".into(),
        ));
    }

    Ok((headers, body_offset))
}

/// Parses raw MIME email into IC SMTP Message
pub fn parse_email(raw: &[u8]) -> Result<Message, IcSmtpDeliveryAgentError> {
    let (headers, body_offset) = split_email(raw)?;

    Ok(Message {
        headers,
        body: raw[body_offset..].into(),
    })
}

/// Zero-copy version of [`parse_email`].
///
/// Gets the same headers and body bytes, but the body is a slice of
/// `raw` rather than a copy.
pub fn parse_email_bytes(raw: &Bytes) -> Result<ParsedEmail, IcSmtpDeliveryAgentError> {
    let (headers, body_offset) = split_email(raw)?;

    Ok(ParsedEmail {
        headers,
        body: raw.slice(body_offset..),
    })
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

        let r = parse_email(raw.as_bytes()).unwrap();
        assert!(r.body.is_empty());
    }

    /// The chunked path uses `parse_email_bytes` and the single-call path uses
    /// `parse_email`; they must agree exactly, or the same mail would arrive
    /// differently depending on its size.
    #[test]
    fn test_parse_email_and_parse_email_bytes_agree() {
        let cases: [&[u8]; 4] = [
            indoc! {r#"
                From: Some One <someone@example.com>
                To: John Doe <john@doe.com>
                Content-Type: text/plain

                body text here
            "#}
            .as_bytes(),
            // Empty body
            b"From: a@b.c\nSubject: x\n\n",
            // CRLF line endings, as they arrive over the wire
            b"From: a@b.c\r\nSubject: x\r\n\r\nbody\r\n",
            // Binary body
            b"From: a@b.c\nSubject: x\n\n\x00\xff\xfe\x0d\x0a",
        ];

        for raw in cases {
            let owned = parse_email(raw).unwrap();
            let shared = parse_email_bytes(&Bytes::copy_from_slice(raw)).unwrap();

            assert_eq!(owned.headers, shared.headers);
            assert_eq!(owned.body, shared.body.as_ref());
            assert_eq!(owned, shared.to_message());
        }

        // Both reject the same inputs
        assert!(parse_email(&[]).is_err());
        assert!(parse_email_bytes(&Bytes::new()).is_err());
    }

    /// The zero-copy variant must actually share the buffer rather than copy it.
    #[test]
    fn test_parse_email_bytes_is_zero_copy() {
        let raw = Bytes::from_static(
            b"From: a@b.c
Subject: x

the body",
        );
        let parsed = parse_email_bytes(&raw).unwrap();

        assert_eq!(parsed.body.as_ref(), b"the body");
        // A slice of the same allocation, not a fresh one
        assert!(
            parsed.body.as_ptr() >= raw.as_ptr()
                && parsed.body.as_ptr() <= unsafe { raw.as_ptr().add(raw.len()) }
        );
    }
}
