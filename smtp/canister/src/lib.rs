//! Proof-of-concept canister implementing the IC SMTP protocol.
//!
//! **This is a test fixture, not production code.** It exists so the gateway's
//! chunked upload protocol can be exercised end to end against a real canister
//! on PocketIC instead of against an in-process mock. It keeps everything on
//! the heap, has no stable storage and no upgrade hooks - in-flight uploads are
//! inherently transient, and a real canister would stream chunks into stable
//! memory instead.
//!
//! It aims to be a *faithful* reference for the protocol's obligations, which
//! are subtler than they look:
//!
//!  * **Reply codes are the interface.** The gateway maps `500..600` to a
//!    permanent failure (a bounce) and everything else to a temporary one (a
//!    retry). A code outside 5xx for a deterministic error therefore produces
//!    an infinite retry loop. `550` in particular is reserved: the gateway
//!    special-cases it as "unknown mailbox" when probing recipients.
//!  * **Commit must be idempotent.** If the reply to `smtp_upload_commit` is
//!    lost, the gateway cannot tell whether the message was delivered. It asks
//!    `smtp_upload_status`, and the sending MTA may also retry the whole
//!    message. Both need the terminal verdict to still be there, so it is
//!    memoized per `(caller, message_id)`.
//!  * **Validate before storing.** A chunk's digest is checked before the
//!    payload is kept, so a corrupt transfer costs one chunk rather than the
//!    whole upload.
//!
//! Authorization returns `530` rather than trapping. A trap produces reject
//! code `IC0516`, which the gateway classifies as a *temporary* failure - an
//! unauthorized gateway would retry forever. A production canister would add
//! `#[inspect_message]` on top to reject unauthorized ingress before consensus
//! and save the cycles, but it must keep this check as the authoritative one.
//!
//! Every endpoint is a plain `fn`. In a canister any `await` is an interleaving
//! point where a concurrent chunk could observe half-updated upload state.

use std::{cell::RefCell, collections::HashMap};

use candid::Principal;
use ic_cdk::{
    api::{msg_caller, time},
    init, query, update,
};
use sha2::{Digest, Sha256};

mod types;
pub use types::*;

/// Upper bound on chunk count, so a malformed `total_chunks` cannot make the
/// canister allocate an enormous index.
const MAX_CHUNKS: u32 = 4096;

/// Bytes of the body echoed back by `poc_delivered` at each end.
const EDGE_BYTES: usize = 64;

/// Largest slice `poc_body_range` will return in one call.
const MAX_RANGE: u64 = 1024 * 1024;

/// An upload in progress.
struct Upload {
    envelope: Envelope,
    headers: Option<Vec<Header>>,
    gateway_flags: Option<Vec<String>>,
    total_chunks: u32,
    chunk_size: u64,
    body_size: u64,
    /// Pre-sized once; chunks are written at `index * chunk_size`. Reassembling
    /// into a second buffer at commit would double peak memory for nothing.
    buf: Vec<u8>,
    /// Digest of each chunk as it arrived, so commit can re-derive the chain
    /// without re-hashing the body.
    digests: Vec<Option<[u8; SHA256_LEN]>>,
    received: u32,
    created_secs: u64,
}

/// A terminal outcome, retained so a repeated call is idempotent.
struct Completed {
    verdict: SmtpResponse,
    delivered: Option<(Delivered, Vec<u8>)>,
    at_secs: u64,
}

#[derive(Default)]
struct State {
    cfg: Option<InitArg>,
    uploads: HashMap<(Principal, String), Upload>,
    completed: HashMap<(Principal, String), Completed>,
    reserved_bytes: u64,
    delivered_count: u64,
    rejected: u64,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::default();
}

fn with_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with_borrow(f)
}

fn with_state_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with_borrow_mut(f)
}

fn now_secs() -> u64 {
    time() / 1_000_000_000
}

const fn smtp_err(code: u64, message: String) -> SmtpRequestError {
    SmtpRequestError { code, message }
}

/// Records a rejection for `poc_stats` and returns the response.
///
/// Takes `&mut State` rather than re-entering `with_state_mut`: these are
/// called from inside an existing borrow, and a second one panics. In a
/// canister that panic is a trap, which the gateway classifies as a
/// *temporary* failure - so an error path that traps retries forever instead
/// of bouncing. That is precisely what returning a 5xx code is meant to avoid.
fn reject<T>(state: &mut State, resp: T) -> T {
    state.rejected += 1;
    resp
}

fn err_response(state: &mut State, code: u64, message: &str) -> SmtpResponse {
    reject(
        state,
        SmtpResponse::Err(smtp_err(code, message.to_string())),
    )
}

fn err_chunk(state: &mut State, code: u64, message: &str) -> SmtpUploadChunkResponse {
    reject(
        state,
        SmtpUploadChunkResponse::Err(smtp_err(code, message.to_string())),
    )
}

/// The only principal allowed to drive the protocol.
///
/// Returns `530` rather than trapping - see the module docs.
fn check_caller(state: &State) -> Result<Principal, SmtpRequestError> {
    let caller = msg_caller();
    let cfg = state.cfg.as_ref().expect("canister not initialized");

    if cfg.authorized == caller {
        Ok(caller)
    } else {
        Err(smtp_err(530, "unauthorized caller".to_string()))
    }
}

/// Whether this canister accepts mail for the address.
///
/// PoC simplification: only the local part is matched, case-insensitively. The
/// domain already routed the message here.
fn mailbox_known(cfg: &InitArg, addr: &Address) -> bool {
    cfg.mailboxes
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&addr.user))
}

/// `Ok` if every recipient is deliverable here.
fn check_envelope(cfg: &InitArg, envelope: &Envelope) -> Result<(), SmtpRequestError> {
    if envelope.to.is_empty() {
        return Err(smtp_err(501, "envelope has no recipients".to_string()));
    }

    for addr in &envelope.to {
        if !mailbox_known(cfg, addr) {
            return Err(smtp_err(
                550,
                format!("no such mailbox: {}@{}", addr.user, addr.domain),
            ));
        }
    }

    Ok(())
}

/// Drops uploads whose TTL has passed.
///
/// Swept when admission control is about to refuse rather than only on access,
/// so an idle canister does not hold buffers forever. A production canister
/// would also run this from a timer.
fn sweep_expired(state: &mut State, now: u64) {
    let ttl = state.cfg.as_ref().map_or(0, |c| c.upload_ttl_secs);
    if ttl == 0 {
        return;
    }

    let mut freed = 0;
    state.uploads.retain(|_, up| {
        let keep = now.saturating_sub(up.created_secs) < ttl;
        if !keep {
            freed += up.body_size;
        }
        keep
    });
    state.reserved_bytes = state.reserved_bytes.saturating_sub(freed);

    state
        .completed
        .retain(|_, c| now.saturating_sub(c.at_secs) < ttl);
}

/// A fully-received message, ready to be recorded.
struct Incoming {
    envelope: Envelope,
    headers: Vec<Header>,
    gateway_flags: Option<Vec<String>>,
    body: Vec<u8>,
    chunks_seen: u32,
    via: DeliveryPath,
}

/// Builds the record `poc_delivered` returns, hashing the body independently.
fn record_delivery(state: &mut State, key: (Principal, String), msg: Incoming) -> SmtpResponse {
    let Incoming {
        envelope,
        headers,
        gateway_flags,
        body,
        chunks_seen,
        via,
    } = msg;

    let digest: [u8; SHA256_LEN] = Sha256::digest(&body).into();
    let edge = EDGE_BYTES.min(body.len());

    let info = Delivered {
        envelope,
        headers,
        gateway_flags,
        body_len: body.len() as u64,
        body_sha256: digest.to_vec(),
        body_prefix: body[..edge].to_vec(),
        body_suffix: body[body.len() - edge..].to_vec(),
        chunks_seen,
        via,
    };

    let verdict = SmtpResponse::Ok(SmtpOk {});
    state.delivered_count += 1;
    state.completed.insert(
        key,
        Completed {
            verdict: verdict.clone(),
            delivered: Some((info, body)),
            at_secs: now_secs(),
        },
    );

    verdict
}

#[init]
fn init(init_arg: InitArg) {
    with_state_mut(|s| s.cfg = Some(init_arg));
}

// ---------------------------------------------------------------------------
// Base protocol
// ---------------------------------------------------------------------------

/// Delivers a message that fits into a single ingress message.
///
/// Deduplicated by `(caller, message_id)` for the same reason commit is: the
/// gateway has no ambiguity handling on this path, so a lost reply would
/// otherwise become a duplicate delivery when the sending MTA retries.
#[update]
fn smtp_request(req: SmtpRequest) -> SmtpResponse {
    with_state_mut(|state| {
        let caller = match check_caller(state) {
            Ok(v) => v,
            Err(e) => return reject(state, SmtpResponse::Err(e)),
        };
        let cfg = state.cfg.clone().expect("canister not initialized");

        // Every `SmtpRequest` field is `opt`, so an unrelated record decodes to
        // all-`None` rather than failing. Validate rather than unwrap.
        let (Some(envelope), Some(message), Some(message_id)) =
            (req.envelope, req.message, req.message_id)
        else {
            return err_response(state, 501, "envelope, message and message_id are required");
        };

        if let Err(e) = check_envelope(&cfg, &envelope) {
            return reject(state, SmtpResponse::Err(e));
        }

        if message.body.len() as u64 > cfg.max_message_size {
            return err_response(state, 552, "message exceeds the advertised maximum size");
        }

        let key = (caller, message_id);
        if let Some(done) = state.completed.get(&key) {
            return done.verdict.clone();
        }

        record_delivery(
            state,
            key,
            Incoming {
                envelope,
                headers: message.headers,
                gateway_flags: req.gateway_flags,
                body: message.body,
                chunks_seen: 1,
                via: DeliveryPath::SingleShot,
            },
        )
    })
}

/// Probes whether a recipient is deliverable, during RCPT TO.
///
/// Must be a query - the gateway calls it as one.
///
/// Note the gateway sends `message: None` and `message_id: None` here, so this
/// must not require them. Code `550` means "unknown mailbox" specifically; the
/// gateway turns it into `550 5.1.2` for that recipient alone.
#[query]
fn smtp_request_validate(req: SmtpRequest) -> SmtpResponse {
    with_state(|state| {
        let cfg = match check_caller(state) {
            Ok(_) => state.cfg.as_ref().expect("canister not initialized"),
            Err(e) => return SmtpResponse::Err(e),
        };

        let Some(envelope) = req.envelope else {
            return SmtpResponse::Err(smtp_err(501, "envelope is required".to_string()));
        };

        check_envelope(cfg, &envelope)
            .map_or_else(SmtpResponse::Err, |()| SmtpResponse::Ok(SmtpOk {}))
    })
}

// ---------------------------------------------------------------------------
// Chunked upload protocol
// ---------------------------------------------------------------------------

#[query]
fn smtp_capabilities() -> SmtpCapabilities {
    with_state(|s| {
        let cfg = s.cfg.as_ref().expect("canister not initialized");

        SmtpCapabilities {
            upload_protocol_version: Some(SMTP_UPLOAD_PROTOCOL_VERSION),
            max_message_size: Some(cfg.max_message_size),
        }
    })
}

#[update]
#[allow(clippy::too_many_lines)]
fn smtp_upload_chunk(chunk: SmtpUploadChunk) -> SmtpUploadChunkResponse {
    let now = now_secs();

    with_state_mut(|state| {
        let caller = match check_caller(state) {
            Ok(v) => v,
            Err(e) => return reject(state, SmtpUploadChunkResponse::Err(e)),
        };
        let cfg = state.cfg.clone().expect("canister not initialized");

        if chunk.version != SMTP_UPLOAD_PROTOCOL_VERSION {
            return err_chunk(state, 504, "unsupported upload protocol version");
        }

        if chunk.payload_sha256.len() != SHA256_LEN {
            return err_chunk(state, 554, "payload_sha256 must be 32 bytes");
        }

        // Verify BEFORE storing, so a corrupt transfer costs one chunk rather
        // than the whole upload.
        let digest: [u8; SHA256_LEN] = Sha256::digest(&chunk.payload).into();
        if digest.as_slice() != chunk.payload_sha256.as_slice() {
            return err_chunk(state, 554, "chunk digest mismatch");
        }

        // Layout. `total_chunks` must follow from `body_size`/`chunk_size`,
        // otherwise a caller could declare chunk_size=1, total_chunks=4e9 and
        // make us allocate an enormous index.
        if chunk.chunk_size == 0
            || chunk.total_chunks == 0
            || chunk.total_chunks > MAX_CHUNKS
            || chunk.body_size.div_ceil(chunk.chunk_size) != u64::from(chunk.total_chunks)
            || chunk.index >= chunk.total_chunks
        {
            return err_chunk(state, 554, "malformed chunk layout");
        }

        // The index is bounded above, so this cannot underflow - but use
        // checked arithmetic anyway: release builds have overflow checks off,
        // and a `[profile.release]` in a non-root workspace member is ignored.
        let expected = u64::from(chunk.index)
            .checked_mul(chunk.chunk_size)
            .and_then(|offset| chunk.body_size.checked_sub(offset))
            .map(|left| chunk.chunk_size.min(left));

        if expected != Some(chunk.payload.len() as u64) {
            return err_chunk(state, 554, "chunk payload has the wrong length");
        }

        // Headers ride on the first chunk. Chunks arrive out of order, so this
        // can only be required positionally, not temporally. Headers on a later
        // chunk are accepted and ignored rather than rejected - the gateway
        // never sends them, but that is a sender-side convention, not a rule.
        if chunk.index == 0 && chunk.headers.is_none() {
            return err_chunk(state, 554, "the first chunk must carry the headers");
        }

        if chunk.body_size > cfg.max_message_size {
            return err_chunk(state, 552, "message exceeds the advertised maximum size");
        }

        // `usize` is 32 bits on wasm32, so converting explicitly rather than
        // casting: a silent truncation here would allocate a short buffer and
        // then panic on the write below, and a trap reads as a *temporary*
        // failure to the gateway - an infinite retry rather than a bounce.
        let (Ok(body_size), Ok(chunk_span)) = (
            usize::try_from(chunk.body_size),
            usize::try_from(chunk.chunk_size),
        ) else {
            return err_chunk(state, 552, "message is too large for this canister");
        };

        let Some(offset) = (chunk.index as usize).checked_mul(chunk_span) else {
            return err_chunk(state, 554, "chunk offset overflows");
        };

        // Re-checked on every chunk so an unknown recipient costs one call
        // rather than the whole upload.
        if let Err(e) = check_envelope(&cfg, &chunk.envelope) {
            return reject(state, SmtpUploadChunkResponse::Err(e));
        }

        let key = (caller, chunk.message_id.clone());

        // Already finished: report it as complete rather than reopening.
        if state.completed.contains_key(&key) {
            return SmtpUploadChunkResponse::Ok(SmtpUploadChunkOk {
                chunks_received: chunk.total_chunks,
            });
        }

        if !state.uploads.contains_key(&key) {
            sweep_expired(state, now);

            let open = state.uploads.len() as u64;
            if open >= u64::from(cfg.max_open_uploads) {
                return err_chunk(state, 452, "too many uploads in progress");
            }
            if state.reserved_bytes.saturating_add(chunk.body_size) > cfg.max_buffered_bytes {
                return err_chunk(state, 452, "upload buffer is full");
            }

            state.reserved_bytes = state.reserved_bytes.saturating_add(chunk.body_size);
            state.uploads.insert(
                key.clone(),
                Upload {
                    envelope: chunk.envelope.clone(),
                    headers: None,
                    gateway_flags: None,
                    total_chunks: chunk.total_chunks,
                    chunk_size: chunk.chunk_size,
                    body_size: chunk.body_size,
                    buf: vec![0; body_size],
                    digests: vec![None; chunk.total_chunks as usize],
                    received: 0,
                    created_secs: now,
                },
            );
        }

        let up = state.uploads.get_mut(&key).expect("just inserted");

        // Two different messages sharing one message_id. Temporary, not
        // permanent: the gateway should retry rather than bounce.
        if up.total_chunks != chunk.total_chunks
            || up.chunk_size != chunk.chunk_size
            || up.body_size != chunk.body_size
            || up.envelope != chunk.envelope
        {
            return err_chunk(state, 450, "chunk does not match the upload in progress");
        }

        if chunk.index == 0 {
            up.headers.clone_from(&chunk.headers);
            up.gateway_flags.clone_from(&chunk.gateway_flags);
        }

        let Some(end) = offset
            .checked_add(chunk.payload.len())
            .filter(|e| *e <= up.buf.len())
        else {
            // Unreachable given the layout checks above, but writing out of
            // bounds would trap, so fail with a verdict instead.
            return err_chunk(state, 554, "chunk does not fit the declared body");
        };
        up.buf[offset..end].copy_from_slice(&chunk.payload);

        // Idempotent: re-sending a chunk overwrites identical bytes.
        if up.digests[chunk.index as usize].is_none() {
            up.received += 1;
        }
        up.digests[chunk.index as usize] = Some(digest);

        SmtpUploadChunkResponse::Ok(SmtpUploadChunkOk {
            chunks_received: up.received,
        })
    })
}

#[update]
fn smtp_upload_commit(commit: SmtpUploadCommit) -> SmtpResponse {
    with_state_mut(|state| {
        let caller = match check_caller(state) {
            Ok(v) => v,
            Err(e) => return reject(state, SmtpResponse::Err(e)),
        };

        if commit.version != SMTP_UPLOAD_PROTOCOL_VERSION {
            return err_response(state, 504, "unsupported upload protocol version");
        }

        let key = (caller, commit.message_id.clone());

        // Idempotent. Without this a lost reply becomes a duplicate delivery:
        // the gateway reports a temporary failure, the sending MTA retries the
        // whole message, and the canister accepts it a second time.
        if let Some(done) = state.completed.get(&key) {
            return done.verdict.clone();
        }

        let Some(up) = state.uploads.get(&key) else {
            return err_response(state, 450, "unknown upload");
        };

        // Incomplete is temporary and must NOT discard the upload - the missing
        // chunks may still arrive.
        if up.received != commit.total_chunks || up.total_chunks != commit.total_chunks {
            return err_response(state, 450, "upload is incomplete");
        }

        // Re-derive the chain from the digests verified on arrival. Hashing
        // `32 * total_chunks` bytes rather than re-reading the whole body is
        // the point of defining it this way.
        let mut rolling = Sha256::new();
        for d in &up.digests {
            rolling.update(d.expect("every chunk is present"));
        }
        let derived: [u8; SHA256_LEN] = rolling.finalize().into();

        if derived.as_slice() != commit.body_sha256.as_slice() {
            // Terminal: the body the gateway described is not the body we hold.
            let resp = err_response(state, 554, "body digest mismatch");
            let up = state.uploads.remove(&key).expect("checked above");
            state.reserved_bytes = state.reserved_bytes.saturating_sub(up.body_size);
            state.completed.insert(
                key,
                Completed {
                    verdict: resp.clone(),
                    delivered: None,
                    at_secs: now_secs(),
                },
            );
            return resp;
        }

        let Some(headers) = up.headers.clone() else {
            return err_response(state, 554, "upload has no headers");
        };

        let up = state.uploads.remove(&key).expect("checked above");
        state.reserved_bytes = state.reserved_bytes.saturating_sub(up.body_size);

        record_delivery(
            state,
            key,
            Incoming {
                envelope: up.envelope,
                headers,
                gateway_flags: up.gateway_flags,
                body: up.buf,
                chunks_seen: up.total_chunks,
                via: DeliveryPath::Chunked,
            },
        )
    })
}

#[query]
fn smtp_upload_status(upload: SmtpUploadId) -> SmtpUploadStatusResponse {
    with_state(|state| {
        let caller = match check_caller(state) {
            Ok(v) => v,
            Err(e) => return SmtpUploadStatusResponse::Err(e),
        };

        let key = (caller, upload.message_id);

        // A committed upload keeps its verdict, so the gateway can resolve a
        // commit whose reply it never saw without risking a second delivery.
        if let Some(done) = state.completed.get(&key) {
            return SmtpUploadStatusResponse::Ok(SmtpUploadStatus {
                known: true,
                committed: true,
                result: Some(done.verdict.clone()),
            });
        }

        SmtpUploadStatusResponse::Ok(SmtpUploadStatus {
            known: state.uploads.contains_key(&key),
            committed: false,
            result: None,
        })
    })
}

#[update]
fn smtp_upload_abort(upload: SmtpUploadId) -> SmtpResponse {
    with_state_mut(|state| {
        let caller = match check_caller(state) {
            Ok(v) => v,
            Err(e) => return reject(state, SmtpResponse::Err(e)),
        };

        if let Some(up) = state.uploads.remove(&(caller, upload.message_id)) {
            state.reserved_bytes = state.reserved_bytes.saturating_sub(up.body_size);
        }

        // Idempotent by design - aborting something already gone is fine.
        SmtpResponse::Ok(SmtpOk {})
    })
}

// ---------------------------------------------------------------------------
// Introspection for tests. Not part of the protocol.
// ---------------------------------------------------------------------------

/// What was delivered under `message_id`, as the canister saw it.
#[query]
fn poc_delivered(message_id: String) -> Option<Delivered> {
    let caller = msg_caller();
    with_state(|s| {
        s.completed
            .get(&(caller, message_id))
            .and_then(|c| c.delivered.as_ref())
            .map(|(info, _)| info.clone())
    })
}

/// Raw bytes of a delivered body, for comparing directly when a digest fails.
#[query]
fn poc_body_range(message_id: String, offset: u64, len: u64) -> Option<Vec<u8>> {
    let caller = msg_caller();
    with_state(|s| {
        let (_, body) = s
            .completed
            .get(&(caller, message_id))
            .and_then(|c| c.delivered.as_ref())?;

        let start = usize::try_from(offset).ok()?.min(body.len());
        let len = usize::try_from(len.min(MAX_RANGE)).ok()?;
        let end = start.saturating_add(len).min(body.len());

        Some(body[start..end].to_vec())
    })
}

#[query]
fn poc_stats() -> Stats {
    with_state(|s| Stats {
        delivered: s.delivered_count,
        open_uploads: s.uploads.len() as u64,
        reserved_bytes: s.reserved_bytes,
        rejected: s.rejected,
    })
}

#[cfg(test)]
mod tests {
    use std::{env, fs::read_to_string, path::PathBuf};

    use candid_parser::utils::{CandidSource, service_equal};

    use super::*;

    fn source_to_str(source: &CandidSource) -> String {
        match source {
            CandidSource::File(f) => read_to_string(f).unwrap_or_default(),
            CandidSource::Text(t) => (*t).to_string(),
        }
    }

    fn check_service_equal(new_name: &str, new: CandidSource, old_name: &str, old: CandidSource) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);

        match service_equal(new, old) {
            Ok(()) => {}
            Err(e) => {
                eprintln!(
                    "{new_name} is not compatible with {old_name}!\n\n\
                    {new_name}:\n{new_str}\n\n\
                    {old_name}:\n{old_str}\n"
                );
                panic!("Candid interface mismatch: {e:?}");
            }
        }
    }

    /// The checked-in `.did` is the protocol's machine-checked specification.
    /// `service_equal` is bidirectional, so the two must match exactly.
    #[test]
    fn check_candid_interface_compatibility() {
        candid::export_service!();

        let new_interface = __export_service();

        let canister_did = "ic_smtp_poc.did";
        let old_interface =
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(canister_did);

        check_service_equal(
            "actual candid interface",
            CandidSource::Text(&new_interface),
            &format!("declared candid interface in {canister_did}"),
            CandidSource::File(old_interface.as_path()),
        );
    }
}
