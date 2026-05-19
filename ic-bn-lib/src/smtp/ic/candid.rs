//! Candid types for an IC SMTP Protocol

use candid::{CandidType, Deserialize};

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
