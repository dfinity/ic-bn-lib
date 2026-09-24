use bytes::Bytes;
use candid::Encode;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::smtp::ic::candid::{
    Envelope, Header, Message, SHA256_LEN, SMTP_UPLOAD_PROTOCOL_VERSION, SmtpRequest,
    SmtpUploadChunk, SmtpUploadCommit,
};

/// Errors from planning an upload
#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq)]
pub enum UploadPlanError {
    #[error("unable to encode the message for size measurement: {0}")]
    Encode(String),
    #[error(
        "header block is too large to upload: {overhead} bytes of overhead leaves \
        only {available} bytes per chunk, need at least {needed}"
    )]
    HeadersTooLarge {
        overhead: usize,
        available: usize,
        needed: usize,
    },
    #[error("cannot chunk an empty body")]
    EmptyBody,
    #[error("no envelope to measure the chunk size against")]
    NoEnvelopes,
}

/// Config for the chunked upload
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcSmtpUploadConfig {
    /// Subnet `max_ingress_bytes_per_message`.
    /// 2MB is the safe value.
    pub max_ingress_size: usize,
    /// Preferred body bytes per chunk
    pub chunk_size: usize,
    /// How many payload bytes may be in flight to one destination at once.
    /// Concurrency is derived from this.
    pub max_inflight_bytes: usize,
    /// Max concurrencty across every session and destination.
    /// Should be lower than the Agent's `max_concurrent_requests` (50 by
    /// default) so that the capability and validate queries
    /// aren't queued due to chunk uploads.
    pub global_concurrency: usize,
    /// Retries for one chunk that failed. Chunks are idempotent so retrying is safe.
    pub chunk_retries: usize,
    /// Timeout for delivering one message to all of its destinations.
    pub delivery_timeout: Duration,
    /// How long to cache a canister's advertised capabilities.
    pub capabilities_cache_ttl: Duration,
}

impl Default for IcSmtpUploadConfig {
    fn default() -> Self {
        Self {
            max_ingress_size: crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE,
            chunk_size: 1024 * 1024,
            max_inflight_bytes: 2 * 1024 * 1024,
            global_concurrency: 16,
            chunk_retries: 2,
            delivery_timeout: Duration::from_secs(90),
            capabilities_cache_ttl: Duration::from_secs(600),
        }
    }
}

impl IcSmtpUploadConfig {
    /// How many chunks to keep in flight to one destination.
    pub const fn concurrency(&self, chunk_size: usize) -> usize {
        if chunk_size == 0 {
            return 1;
        }

        let n = self.max_inflight_bytes / chunk_size;
        if n == 0 { 1 } else { n }
    }
}

/// Chunking layout and digests for one message
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadPlan {
    /// Size of the chunk,
    /// except the last one which can be smaller
    pub chunk_size: usize,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Total body length
    pub body_size: usize,
    /// SHA-256 of each chunk's payload, in index order
    pub payload_sha256: Vec<[u8; SHA256_LEN]>,
    /// `SHA256(payload_sha256[0] || .. || payload_sha256[n-1])`.
    /// Travels to the canister in [`SmtpUploadCommit`], never in a chunk -
    /// see that field's docs for why.
    pub body_sha256: [u8; SHA256_LEN],
}

impl UploadPlan {
    /// Byte range of chunk `index` within the body.
    pub const fn range(&self, index: u32) -> (usize, usize) {
        let start = (index as usize) * self.chunk_size;
        let end = start.saturating_add(self.chunk_size);

        (
            if start > self.body_size {
                self.body_size
            } else {
                start
            },
            if end > self.body_size {
                self.body_size
            } else {
                end
            },
        )
    }
}

/// LEB128-encoded length of `n` bytes
const fn leb128_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

/// Encoded length of the `SmtpRequest` for this message
pub fn single_shot_encoded_len(
    headers: &[Header],
    envelope: &Envelope,
    message_id: &str,
    body_len: usize,
) -> Result<usize, UploadPlanError> {
    let probe = SmtpRequest {
        message: Some(Message {
            headers: headers.to_vec(),
            body: vec![],
        }),
        envelope: Some(envelope.clone()),
        gateway_flags: None,
        message_id: Some(message_id.to_string()),
    };

    let base = Encode!(&probe)
        .map_err(|e| UploadPlanError::Encode(e.to_string()))?
        .len();

    Ok(base - leb128_len(0) + leb128_len(body_len) + body_len)
}

/// Calculates the Candid overhead of the largest chunk (chunk 0 with headers)
fn chunk_overhead(
    headers: &[Header],
    envelope: &Envelope,
    message_id: &str,
) -> Result<usize, UploadPlanError> {
    let probe = SmtpUploadChunk {
        version: SMTP_UPLOAD_PROTOCOL_VERSION,
        message_id: message_id.to_string(),
        envelope: envelope.clone(),
        index: 0,
        total_chunks: 0,
        chunk_size: 0,
        body_size: 0,
        payload_sha256: vec![0; SHA256_LEN],
        payload: vec![],
        headers: Some(headers.to_vec()),
        gateway_flags: None,
    };

    Ok(Encode!(&probe)
        .map_err(|e| UploadPlanError::Encode(e.to_string()))?
        .len())
}

/// Smallest share of the ingress budget a chunk payload may be reduced to.
/// This bounds the chunk count if the headers are too big and there's not
/// a lot of space for body left.
const MIN_PAYLOAD_SHARE: usize = 8;

/// Computes the chunk layout and all digests for a message.
///
/// `envelopes` are all the envelopes this plan has to serve - one per
/// destination canister.
pub fn plan_chunks(
    headers: &[Header],
    envelopes: &[&Envelope],
    message_id: &str,
    body: &Bytes,
    max_ingress_size: usize,
    max_payload: usize,
) -> Result<UploadPlan, UploadPlanError> {
    if body.is_empty() {
        return Err(UploadPlanError::EmptyBody);
    }

    // Without an envelope there is nothing to measure
    if envelopes.is_empty() {
        return Err(UploadPlanError::NoEnvelopes);
    }

    // Compute how many bytes are available for the payload
    // after accounting for the chunk overhead.
    // 64 is a framing overhead (LEB128 etc, with some allowance on top)
    let mut overhead = 0;
    for envelope in envelopes {
        overhead = overhead.max(chunk_overhead(headers, envelope, message_id)?);
    }
    let overhead = overhead.saturating_add(64);
    let available = max_ingress_size.saturating_sub(overhead);

    // Oversized headers would leave so little room per chunk that the message
    // would need an absurd number of calls - refuse instead.
    let needed = (max_ingress_size / MIN_PAYLOAD_SHARE).max(1);
    if available < needed {
        return Err(UploadPlanError::HeadersTooLarge {
            overhead,
            available,
            needed,
        });
    }

    let chunk_size = max_payload.min(available).max(1);
    let total_chunks = body.len().div_ceil(chunk_size) as u32;

    // Calculate the hashes
    let mut payload_sha256 = Vec::with_capacity(total_chunks as usize);
    let mut body_sha256 = Sha256::new();
    for i in 0..total_chunks as usize {
        let start = i * chunk_size;
        let end = (start + chunk_size).min(body.len());
        let digest: [u8; SHA256_LEN] = Sha256::digest(&body[start..end]).into();

        body_sha256.update(digest);
        payload_sha256.push(digest);
    }

    Ok(UploadPlan {
        chunk_size,
        total_chunks,
        body_size: body.len(),
        payload_sha256,
        body_sha256: body_sha256.finalize().into(),
    })
}

/// Builds the commit that finalizes an upload
pub fn build_commit(plan: &UploadPlan, message_id: &str) -> SmtpUploadCommit {
    SmtpUploadCommit {
        version: SMTP_UPLOAD_PROTOCOL_VERSION,
        message_id: message_id.to_string(),
        body_sha256: plan.body_sha256.to_vec(),
        total_chunks: plan.total_chunks,
    }
}

/// Builds chunk `index`
pub fn build_chunk(
    plan: &UploadPlan,
    index: u32,
    body: &Bytes,
    headers: &[Header],
    envelope: &Envelope,
    message_id: &str,
) -> SmtpUploadChunk {
    let (start, end) = plan.range(index);

    SmtpUploadChunk {
        version: SMTP_UPLOAD_PROTOCOL_VERSION,
        message_id: message_id.to_string(),
        envelope: envelope.clone(),
        index,
        total_chunks: plan.total_chunks,
        chunk_size: plan.chunk_size as u64,
        body_size: plan.body_size as u64,
        payload_sha256: plan.payload_sha256[index as usize].to_vec(),
        payload: body[start..end].to_vec(),
        // Headers are on the first chunk only
        headers: (index == 0).then(|| headers.to_vec()),
        // Always `None`: `chunk_overhead`'s probe does not measure this field,
        // so setting it would silently break the ingress bound. See there.
        gateway_flags: None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::smtp::ic::candid::Address;

    fn envelope(n: usize) -> Envelope {
        Envelope {
            from: Address {
                user: "sender".into(),
                domain: "example.com".into(),
            },
            to: (0..n)
                .map(|i| Address {
                    user: format!("rcpt{i}"),
                    domain: "qoctq-giaaa-aaaaa-aaaea-cai.icp0.io".into(),
                })
                .collect(),
        }
    }

    fn headers(n: usize) -> Vec<Header> {
        (0..n)
            .map(|i| Header {
                name: format!("X-Header-{i}"),
                value: format!(" value number {i} with some padding\n"),
            })
            .collect()
    }

    const MID: &str = "0193f0a1-2b3c-7d4e-8f90-a1b2c3d4e5f6";

    #[test]
    fn test_leb128_len() {
        assert_eq!(leb128_len(0), 1);
        assert_eq!(leb128_len(127), 1);
        assert_eq!(leb128_len(128), 2);
        assert_eq!(leb128_len(16383), 2);
        assert_eq!(leb128_len(16384), 3);
        assert_eq!(leb128_len(2_097_152), 4);
    }

    /// The single-call size estimate decides whether a message takes the legacy
    /// path, so it has to be exact rather than approximately right.
    #[test]
    fn test_single_shot_encoded_len_is_exact() {
        let env = envelope(3);
        let hdrs = headers(12);

        for body_len in [0, 1, 127, 128, 255, 16383, 16384, 100_000] {
            let predicted = single_shot_encoded_len(&hdrs, &env, MID, body_len).unwrap();

            let actual = Encode!(&SmtpRequest {
                message: Some(Message {
                    headers: hdrs.clone(),
                    body: vec![0xab; body_len],
                }),
                envelope: Some(env.clone()),
                gateway_flags: None,
                message_id: Some(MID.to_string()),
            })
            .unwrap()
            .len();

            assert_eq!(predicted, actual, "body_len {body_len}");
        }
    }

    /// The whole point of measuring rather than guessing the overhead: no chunk
    /// the planner produces may exceed the ingress budget.
    #[test]
    fn test_every_built_chunk_fits_the_ingress_budget() {
        let env = envelope(10);
        let budget = crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE;

        // A fat header block is the adversarial case - chunk 0 carries all of it.
        for header_count in [1, 50, 500, 2000] {
            let hdrs = headers(header_count);
            let body = Bytes::from(vec![0x5a; 9_000_000]);

            let plan = plan_chunks(&hdrs, &[&env], MID, &body, budget, usize::MAX).unwrap();

            for i in 0..plan.total_chunks {
                let chunk = build_chunk(&plan, i, &body, &hdrs, &env, MID);
                let encoded = Encode!(&chunk).unwrap().len();
                assert!(
                    encoded <= budget,
                    "header_count {header_count}, chunk {i}: {encoded} > {budget}"
                );
            }
        }
    }

    #[test]
    fn test_chunk_boundaries() {
        let env = envelope(1);
        let hdrs = headers(2);
        let budget = crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE;

        // Exact multiple of the chunk size
        let body = Bytes::from(vec![1u8; 300_000]);
        let plan = plan_chunks(&hdrs, &[&env], MID, &body, budget, 100_000).unwrap();
        assert_eq!(plan.total_chunks, 3);
        assert_eq!(plan.range(0), (0, 100_000));
        assert_eq!(plan.range(2), (200_000, 300_000));

        // Partial last chunk
        let body = Bytes::from(vec![1u8; 250_001]);
        let plan = plan_chunks(&hdrs, &[&env], MID, &body, budget, 100_000).unwrap();
        assert_eq!(plan.total_chunks, 3);
        assert_eq!(plan.range(2), (200_000, 250_001));
        let last = build_chunk(&plan, 2, &body, &hdrs, &env, MID);
        assert_eq!(last.payload.len(), 50_001);

        // Body smaller than one chunk
        let body = Bytes::from(vec![1u8; 10]);
        let plan = plan_chunks(&hdrs, &[&env], MID, &body, budget, 100_000).unwrap();
        assert_eq!(plan.total_chunks, 1);
        assert_eq!(plan.range(0), (0, 10));

        // Exactly one full chunk
        let body = Bytes::from(vec![1u8; 100_000]);
        let plan = plan_chunks(&hdrs, &[&env], MID, &body, budget, 100_000).unwrap();
        assert_eq!(plan.total_chunks, 1);
    }

    /// Reassembling every chunk must reproduce the body byte for byte, and the
    /// digest chain must match what the canister will re-derive at commit.
    #[test]
    fn test_reassembly_and_digest_chain() {
        let env = envelope(2);
        let hdrs = headers(5);
        let body = Bytes::from((0..250_003u32).map(|i| (i % 251) as u8).collect::<Vec<_>>());

        let plan = plan_chunks(
            &hdrs,
            &[&env],
            MID,
            &body,
            crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE,
            70_000,
        )
        .unwrap();

        let mut reassembled = vec![0u8; plan.body_size];
        let mut rolling = Sha256::new();
        for i in 0..plan.total_chunks {
            let chunk = build_chunk(&plan, i, &body, &hdrs, &env, MID);

            // Per-chunk digest, as the canister verifies it on arrival
            let d: [u8; SHA256_LEN] = Sha256::digest(&chunk.payload).into();
            assert_eq!(d.to_vec(), chunk.payload_sha256, "chunk {i}");
            rolling.update(d);

            let off = (chunk.index as usize) * (chunk.chunk_size as usize);
            reassembled[off..off + chunk.payload.len()].copy_from_slice(&chunk.payload);

            // Metadata is identical in every chunk
            assert_eq!(chunk.total_chunks, plan.total_chunks);
            assert_eq!(chunk.body_size, plan.body_size as u64);
            // Headers ride on the first chunk only
            assert_eq!(chunk.headers.is_some(), i == 0);
        }

        assert_eq!(reassembled, body.as_ref());
        let derived: [u8; SHA256_LEN] = rolling.finalize().into();
        assert_eq!(derived, plan.body_sha256);
    }

    /// Two different bodies must not share a `body_sha256`, so two messages
    /// that collide on `message_id` cannot commit as one.
    #[test]
    fn test_body_digest_distinguishes_messages() {
        let env = envelope(1);
        let hdrs = headers(1);
        let budget = crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE;

        let a = Bytes::from(vec![0u8; 200_000]);
        let mut b_vec = vec![0u8; 200_000];
        b_vec[199_999] = 1;
        let b = Bytes::from(b_vec);

        let pa = plan_chunks(&hdrs, &[&env], MID, &a, budget, 100_000).unwrap();
        let pb = plan_chunks(&hdrs, &[&env], MID, &b, budget, 100_000).unwrap();
        assert_ne!(pa.body_sha256, pb.body_sha256);
    }

    #[test]
    fn test_empty_body_is_rejected() {
        assert_eq!(
            plan_chunks(
                &headers(1),
                &[&envelope(1)],
                MID,
                &Bytes::new(),
                crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE,
                100_000,
            )
            .unwrap_err(),
            UploadPlanError::EmptyBody
        );
    }

    /// A header block that leaves no room for a payload must fail loudly rather
    /// than produce a huge number of tiny chunks.
    #[test]
    fn test_headers_too_large() {
        let env = envelope(1);
        // ~2 MiB of headers against a 2 MiB budget
        let hdrs = (0..20_000)
            .map(|i| Header {
                name: format!("X-Pad-{i}"),
                value: "x".repeat(100),
            })
            .collect::<Vec<_>>();

        let err = plan_chunks(
            &hdrs,
            &[&env],
            MID,
            &Bytes::from(vec![0u8; 10_000_000]),
            crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE,
            usize::MAX,
        )
        .unwrap_err();

        assert!(
            matches!(err, UploadPlanError::HeadersTooLarge { .. }),
            "got {err:?}"
        );
    }

    /// The canister-advertised chunk size must clamp our configured one down,
    /// never up.
    #[test]
    fn test_max_payload_clamps_chunk_size() {
        let plan = plan_chunks(
            &headers(1),
            &[&envelope(1)],
            MID,
            &Bytes::from(vec![0u8; 1_000_000]),
            crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE,
            64 * 1024,
        )
        .unwrap();

        assert_eq!(plan.chunk_size, 64 * 1024);
        assert_eq!(plan.total_chunks, 1_000_000u32.div_ceil(65_536));
    }

    #[test]
    fn test_concurrency_derivation() {
        let cfg = IcSmtpUploadConfig::default();
        // 2 MiB in flight over 1 MiB chunks
        assert_eq!(cfg.concurrency(1024 * 1024), 2);
        assert_eq!(cfg.concurrency(256 * 1024), 8);
        // A chunk larger than the whole budget still gets one in flight
        assert_eq!(cfg.concurrency(8 * 1024 * 1024), 1);
        assert_eq!(cfg.concurrency(0), 1);
    }

    /// With `max_payload` unbounded the measured budget is what sets the chunk
    /// size, so pin the absolute value rather than an inequality that a large
    /// slack would satisfy no matter what.
    #[test]
    fn test_chunk_size_equals_the_measured_budget_when_it_binds() {
        let hdrs = headers(20);
        let env = envelope(3);
        let body = Bytes::from(vec![0u8; 2_000_000]);
        let budget = 256 * 1024;

        let plan = plan_chunks(&hdrs, &[&env], MID, &body, budget, usize::MAX).unwrap();

        let overhead = chunk_overhead(&hdrs, &env, MID).unwrap() + 64;
        assert_eq!(plan.chunk_size, budget - overhead);

        // ...and the chunk that comes out of it really does fit
        let encoded = Encode!(&build_chunk(&plan, 0, &body, &hdrs, &env, MID))
            .unwrap()
            .len();
        assert!(encoded <= budget, "{encoded} > {budget}");
    }

    /// One plan serves every destination, so it has to be sized against the
    /// envelope that leaves the least room - not the first, and not the widest
    /// by some other measure.
    #[test]
    fn test_chunk_size_is_measured_against_the_tightest_envelope() {
        let hdrs = headers(5);
        let body = Bytes::from(vec![0u8; 2_000_000]);
        let budget = 256 * 1024;

        let narrow = envelope(1);
        let wide = envelope(10);

        let plan = |envs: &[&Envelope]| {
            plan_chunks(&hdrs, envs, MID, &body, budget, usize::MAX)
                .unwrap()
                .chunk_size
        };

        let narrow_only = plan(&[&narrow]);
        let wide_only = plan(&[&wide]);
        assert!(
            wide_only < narrow_only,
            "a wider envelope must leave less payload: {wide_only} vs {narrow_only}"
        );

        // Serving both means serving the tighter of the two, either way round
        assert_eq!(plan(&[&narrow, &wide]), wide_only);
        assert_eq!(plan(&[&wide, &narrow]), wide_only);
    }

    /// The floor rejects a header block that leaves a technically-usable but
    /// absurd payload - exactly the case an "is there any room at all" guard
    /// sails straight past.
    #[test]
    fn test_headers_leaving_a_tiny_payload_are_rejected() {
        let budget = crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE;
        let env = envelope(1);

        // ~1.9 MB of headers: room is left, but only a sliver of it
        let hdrs = (0..950)
            .map(|i| Header {
                name: format!("X-Pad-{i}"),
                value: "x".repeat(2000),
            })
            .collect::<Vec<_>>();

        let available = budget - (chunk_overhead(&hdrs, &env, MID).unwrap() + 64);
        assert!(
            available > 0,
            "precondition: the old guard would allow this"
        );
        assert!(available < budget / MIN_PAYLOAD_SHARE);

        let err = plan_chunks(
            &hdrs,
            &[&env],
            MID,
            &Bytes::from(vec![0u8; 10_000_000]),
            budget,
            usize::MAX,
        )
        .unwrap_err();

        assert!(
            matches!(err, UploadPlanError::HeadersTooLarge { .. }),
            "got {err:?}"
        );
    }

    /// An empty envelope list would leave nothing to measure against, so the
    /// chunk size would be bounded only by the slack. Refuse instead.
    #[test]
    fn test_no_envelopes_is_rejected() {
        assert_eq!(
            plan_chunks(
                &headers(1),
                &[],
                MID,
                &Bytes::from(vec![0u8; 1000]),
                crate::ic::DEFAULT_MAX_INGRESS_MESSAGE_SIZE,
                1024,
            )
            .unwrap_err(),
            UploadPlanError::NoEnvelopes
        );
    }
}
