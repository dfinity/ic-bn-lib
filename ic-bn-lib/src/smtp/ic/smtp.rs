//! Candid types and submit logic for the SMTP gateway ↔ canister protocol.

use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_bn_lib::ic_agent::{Agent, AgentError};
use tracing::{debug, warn};

use crate::smtp::ReceivedMail;

/// Candid `Header`.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Candid `Message`.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Message {
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

/// Candid `Address`.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Address {
    pub user: String,
    pub domain: String,
}

/// Candid `Envelope`.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct Envelope {
    pub from: Address,
    pub to: Address,
}

/// Candid `SmtpRequest`.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpRequest {
    pub message: Option<Message>,
    pub envelope: Option<Envelope>,
    pub gateway_flags: Option<Vec<String>>,
}

/// Candid `SmtpRequestError` (`code` is `nat64` on the wire in typical canisters).
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpRequestError {
    pub code: u64,
    pub message: String,
}

/// Candid `SmtpResponse` — `Ok` carries an empty record.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub enum SmtpResponse {
    Ok(SmtpOk),
    Err(SmtpRequestError),
}

/// Empty record for variant `Ok`.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SmtpOk {}

fn address_from_smtp_path(path: &str) -> Address {
    let path = path.trim();
    if path.is_empty() {
        return Address {
            user: String::new(),
            domain: String::new(),
        };
    }
    match path.rsplit_once('@') {
        Some((user, domain)) => Address {
            user: user.to_string(),
            domain: domain.to_string(),
        },
        None => Address {
            user: path.to_string(),
            domain: String::new(),
        },
    }
}

/// Split RFC 5322 message into header block and body; parse headers with line unfolding.
pub fn parse_rfc5322_message(raw: &[u8]) -> Result<Message, String> {
    let (header_end, body_start) = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| {
            raw.windows(2)
                .position(|w| w == b"\n\n")
                .map(|i| (i, i + 2))
        })
        .ok_or_else(|| "message has no header/body separator".to_string())?;

    let headers_src = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "message headers are not valid UTF-8".to_string())?;
    let headers = parse_headers_unfolded(headers_src)?;
    let body = raw[body_start..].to_vec();
    Ok(Message { headers, body })
}

fn parse_headers_unfolded(block: &str) -> Result<Vec<Header>, String> {
    let lines = unfold_header_block(block);
    let mut out = Vec::new();
    for line in lines {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("bad header line: {line:?}"));
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err("empty header name".to_string());
        }
        let value = value.trim_start_matches([' ', '\t']).to_string();
        out.push(Header { name, value });
    }
    Ok(out)
}

/// RFC 5322 unfolding: continuation lines start with WSP.
fn unfold_header_block(block: &str) -> Vec<String> {
    let mut merged: Vec<String> = Vec::new();
    for raw_line in block.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        let first = line.chars().next();
        let is_continuation = matches!(first, Some(' ' | '\t'));
        if is_continuation && !merged.is_empty() {
            let last = merged.last_mut().expect("merged non-empty");
            last.push(' ');
            last.push_str(line.trim_start_matches([' ', '\t']));
        } else {
            merged.push(line.to_string());
        }
    }
    merged
}

/// Map canister SMTP-style error codes to an SMTP text reply (code + message for the client).
pub fn smtp_line_from_canister_err(e: &SmtpRequestError) -> (u16, String) {
    let c = e.code;
    let code = if (400..600).contains(&c) {
        c as u16
    } else if c < 400 {
        451
    } else {
        554
    };
    (code, e.message.clone())
}

fn agent_err_to_string(e: AgentError) -> String {
    e.to_string()
}

/// Failure from [`submit_mail`]: transport/parse errors or a canister rejection for one recipient.
#[derive(Debug)]
pub enum SubmitMailError {
    Other(String),
    Rejected {
        code: u16,
        message: String,
        failed_recipient: String,
    },
}

impl SubmitMailError {
    /// SMTP session reply text: `"<code> <message>"` for rejections (matches [`crate::smtp::session::handler_error_to_response`]).
    pub fn into_handler_error(self) -> String {
        match self {
            SubmitMailError::Other(s) => s,
            SubmitMailError::Rejected { code, message, .. } => format!("{code} {message}"),
        }
    }
}

impl From<String> for SubmitMailError {
    fn from(s: String) -> Self {
        SubmitMailError::Other(s)
    }
}

/// Submit mail: optional `smtp_request_validate` (query) per recipient, then `smtp_request` (update).
pub async fn submit_mail(
    agent: &Agent,
    canister_id: Principal,
    mail: &ReceivedMail,
    gateway_flags: &[String],
    validate_before_update: bool,
) -> Result<(), SubmitMailError> {
    if mail.rcpt_to.is_empty() {
        return Err(SubmitMailError::Other(
            "internal error: no recipients".to_string(),
        ));
    }

    let message = parse_rfc5322_message(&mail.raw_message).map_err(SubmitMailError::Other)?;
    let from_addr = address_from_smtp_path(&mail.mail_from);
    let flags = if gateway_flags.is_empty() {
        None
    } else {
        Some(gateway_flags.to_vec())
    };

    for to_path in &mail.rcpt_to {
        let to_addr = address_from_smtp_path(to_path);
        let envelope = Envelope {
            from: from_addr.clone(),
            to: to_addr,
        };

        if validate_before_update {
            let validate_req = SmtpRequest {
                message: None,
                envelope: Some(envelope.clone()),
                gateway_flags: flags.clone(),
            };
            let arg = Encode!(&validate_req).map_err(|e| SubmitMailError::Other(e.to_string()))?;
            let out = agent
                .query(&canister_id, "smtp_request_validate")
                .with_arg(arg)
                .call()
                .await
                .map_err(|e| SubmitMailError::Other(agent_err_to_string(e)))?;
            let resp = Decode!(&out, SmtpResponse).map_err(|e| SubmitMailError::Other(e.to_string()))?;
            match resp {
                SmtpResponse::Ok(_) => {}
                SmtpResponse::Err(err) => {
                    let (code, msg) = smtp_line_from_canister_err(&err);
                    warn!(%canister_id, %to_path, canister_code = %err.code, "smtp_request_validate rejected");
                    return Err(SubmitMailError::Rejected {
                        code,
                        message: msg,
                        failed_recipient: to_path.clone(),
                    });
                }
            }
        }

        let full = SmtpRequest {
            message: Some(message.clone()),
            envelope: Some(envelope),
            gateway_flags: flags.clone(),
        };
        let arg = Encode!(&full).map_err(|e| SubmitMailError::Other(e.to_string()))?;
        let out = agent
            .update(&canister_id, "smtp_request")
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(|e| SubmitMailError::Other(agent_err_to_string(e)))?;
        let resp = Decode!(&out, SmtpResponse).map_err(|e| SubmitMailError::Other(e.to_string()))?;
        match resp {
            SmtpResponse::Ok(_) => {
                debug!(%canister_id, %to_path, "smtp_request accepted");
            }
            SmtpResponse::Err(err) => {
                let (code, msg) = smtp_line_from_canister_err(&err);
                warn!(%canister_id, %to_path, canister_code = %err.code, "smtp_request rejected");
                return Err(SubmitMailError::Rejected {
                    code,
                    message: msg,
                    failed_recipient: to_path.clone(),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_message() {
        let raw = b"From: a@b\r\nTo: c@d\r\n\r\nhello";
        let m = parse_rfc5322_message(raw).unwrap();
        assert_eq!(m.headers.len(), 2);
        assert_eq!(m.body, b"hello");
    }

    #[test]
    fn unfold_continuation() {
        let block = "Subject: very\r\n long\r\n line";
        let lines = unfold_header_block(block);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("very long line"));
    }
}
