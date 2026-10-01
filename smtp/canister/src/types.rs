//! Candid types for the IC SMTP protocol.
//!
//! These are **independent copies** of the types in
//! `ic_bn_lib::smtp::ic::candid`, not a shared crate. Two reasons:
//!
//!  * a canister cannot depend on `ic-bn-lib` - its `smtp` feature pulls in
//!    reqwest/rustls/tokio through the custom-domains and ACME chain, none of
//!    which builds for `wasm32-unknown-unknown`;
//!  * `crate-type = ["cdylib"]` means the gateway's tests cannot `use` this
//!    crate either, so a shared definition would not help them.
//!
//! Independence is what makes the E2E test meaningful: it compares two
//! separately-written definitions over the wire, rather than checking that one
//! definition agrees with itself. The repo already mirrors canister types for
//! this reason - see `BenchMethod` in `custom_domains/tests/instruction_scaling_test.rs`.
//!
//! Keep the field names, field order-independence and integer widths exactly as
//! the gateway declares them. `ic_bn_lib::smtp::ic::candid`'s own test module
//! pins the traps: `code` is `nat64` (a `nat32` does not decode), variant labels
//! are `Ok`/`Err` and case-sensitive, and the upload types use required - not
//! `opt` - fields so a malformed payload fails loudly.

use candid::{CandidType, Deserialize, Principal};

/// Version of the chunked-upload protocol this canister implements.
pub const SMTP_UPLOAD_PROTOCOL_VERSION: u32 = 1;

/// Length of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Message {
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Address {
    pub user: String,
    pub domain: String,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Envelope {
    pub from: Address,
    pub to: Vec<Address>,
}

/// Every field is `opt`, which makes this record a Candid supertype of *any*
/// record - an unrelated payload decodes into an all-`None` request instead of
/// being rejected. The canister must therefore validate the fields itself.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpRequest {
    pub message: Option<Message>,
    pub envelope: Option<Envelope>,
    pub gateway_flags: Option<Vec<String>>,
    pub message_id: Option<String>,
}

/// `code` carries an SMTP reply code and is `nat64` on the wire.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpRequestError {
    pub code: u64,
    pub message: String,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum SmtpResponse {
    Ok(SmtpOk),
    Err(SmtpRequestError),
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpOk {}

#[derive(Clone, Debug, Default, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpCapabilities {
    pub upload_protocol_version: Option<u32>,
    pub max_message_size: Option<u64>,
}

/// One chunk of the message body.
///
/// Fields are required rather than `opt` by design, so a partial or unrelated
/// payload fails to decode instead of becoming an empty upload.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadChunk {
    pub version: u32,
    pub message_id: String,
    pub envelope: Envelope,
    pub index: u32,
    pub total_chunks: u32,
    pub chunk_size: u64,
    pub body_size: u64,
    pub payload_sha256: Vec<u8>,
    pub payload: Vec<u8>,
    pub headers: Option<Vec<Header>>,
    pub gateway_flags: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadChunkOk {
    pub chunks_received: u32,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum SmtpUploadChunkResponse {
    Ok(SmtpUploadChunkOk),
    Err(SmtpRequestError),
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadCommit {
    pub version: u32,
    pub message_id: String,
    /// `SHA256(d_0 || .. || d_{n-1})` where `d_i = SHA256(payload_i)`.
    pub body_sha256: Vec<u8>,
    pub total_chunks: u32,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadId {
    pub message_id: String,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadStatus {
    pub known: bool,
    pub committed: bool,
    pub result: Option<SmtpResponse>,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum SmtpUploadStatusResponse {
    Ok(SmtpUploadStatus),
    Err(SmtpRequestError),
}

// ---------------------------------------------------------------------------
// Installation & introspection. Not part of the SMTP protocol.
// ---------------------------------------------------------------------------

/// Fields are deliberately required rather than `opt`: a rename then fails at
/// install time instead of silently arriving as `None`.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArg {
    /// The only principal allowed to call the SMTP methods.
    pub authorized: Principal,
    /// Local parts this canister accepts mail for, e.g. `["jane", "john"]`.
    pub mailboxes: Vec<String>,
    /// Advertised via `smtp_capabilities` and enforced on arrival.
    pub max_message_size: u64,
    pub max_open_uploads: u32,
    pub max_buffered_bytes: u64,
    pub upload_ttl_secs: u64,
}

/// Which path a delivered message arrived by.
#[derive(Clone, Copy, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum DeliveryPath {
    SingleShot,
    Chunked,
}

/// What the canister actually received, as reported by `poc_delivered`.
///
/// `body_sha256` is a plain `SHA256` over the reassembled body, computed here -
/// it is deliberately NOT an echo of `SmtpUploadCommit::body_sha256` (which
/// hashes the chunk digests). Echoing that value would only assert that the
/// gateway agrees with itself; hashing the body independently is what makes the
/// test end to end.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Delivered {
    pub envelope: Envelope,
    pub headers: Vec<Header>,
    pub gateway_flags: Option<Vec<String>>,
    pub body_len: u64,
    pub body_sha256: Vec<u8>,
    /// First/last 64 bytes, so a digest mismatch is debuggable: "prefix matches,
    /// suffix does not" points straight at a truncated final chunk.
    pub body_prefix: Vec<u8>,
    pub body_suffix: Vec<u8>,
    pub chunks_seen: u32,
    pub via: DeliveryPath,
}

#[derive(Clone, Copy, Debug, Default, CandidType, Deserialize, Eq, PartialEq)]
pub struct Stats {
    pub delivered: u64,
    pub open_uploads: u64,
    pub reserved_bytes: u64,
    pub rejected: u64,
}
