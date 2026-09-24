//! Candid types for an IC SMTP Protocol

use candid::{CandidType, Deserialize};

/// Candid `Header`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Candid `Message`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Message {
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

/// Candid `Address`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Address {
    pub user: String,
    pub domain: String,
}

/// Candid `Envelope`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Envelope {
    pub from: Address,
    pub to: Vec<Address>,
}

/// Candid `SmtpRequest`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpRequest {
    pub message: Option<Message>,
    pub envelope: Option<Envelope>,
    pub gateway_flags: Option<Vec<String>>,
    pub message_id: Option<String>,
}

/// Candid `SmtpRequestError` (`code` is `nat64` on the wire in typical canisters).
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpRequestError {
    pub code: u64,
    pub message: String,
}

/// Candid `SmtpResponse` — `Ok` carries an empty record.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum SmtpResponse {
    Ok(SmtpOk),
    Err(SmtpRequestError),
}

/// Empty record for variant `Ok`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpOk {}

// Chunked upload protocol.
//
// A message that does not fit into one IC ingress message is uploaded as a
// series of body parts (`smtp_upload_chunk`) and then finalized with
// (`smtp_upload_commit`). The gateway only uses this protocol with a canister
// that has advertised support via `smtp_capabilities`
//
// service : {
//   // base methods
//   smtp_request          : (SmtpRequest)       -> (SmtpResponse);
//   smtp_request_validate : (SmtpRequest)       -> (SmtpResponse) query;
//   // chunked upload protocol methods
//   smtp_capabilities     : ()                  -> (SmtpCapabilities) query;
//   smtp_upload_chunk     : (SmtpUploadChunk)   -> (SmtpUploadChunkResponse);
//   smtp_upload_commit    : (SmtpUploadCommit)  -> (SmtpResponse);
//   smtp_upload_status    : (SmtpUploadRef)     -> (SmtpUploadStatusResponse) query;
//   smtp_upload_abort     : (SmtpUploadRef)     -> (SmtpResponse);   // optional
// };

/// Version of the chunked-upload protocol implemented.
///
/// A canister must reject an `SmtpUploadChunk` or `SmtpUploadCommit` with a
/// `version` it does not implement
pub const SMTP_UPLOAD_PROTOCOL_VERSION: u32 = 1;

/// Length of SHA-256 hash
pub const SHA256_LEN: usize = 32;

/// What a canister is willing to accept.
/// Returned by `smtp_capabilities`.
#[derive(Clone, Debug, Default, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpCapabilities {
    /// Highest upload-protocol version implemented
    pub upload_protocol_version: Option<u32>,
    /// Largest raw message (header block plus body) accepted, in bytes
    pub max_message_size: Option<u64>,
}

impl SmtpCapabilities {
    /// Whether chunked upload can be used with this canister
    pub fn supports_chunked(&self) -> bool {
        self.upload_protocol_version
            .is_some_and(|v| v >= SMTP_UPLOAD_PROTOCOL_VERSION)
            && self.max_message_size.is_some_and(|v| v > 0)
    }
}

/// One chunk of the message body.
///
/// Every field except `headers` and `gateway_flags` is repeated in every chunk,
/// which makes the chunk idempotent and lets the canister build the upload from
/// whichever chunk arrives first.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadChunk {
    /// Must be `SMTP_UPLOAD_PROTOCOL_VERSION`.
    pub version: u32,
    /// Assembly key.
    /// Uses the same value as `SmtpRequest::message_id` (UUID).
    pub message_id: String,
    /// SMTP envelope.
    /// Identical in every chunk of one upload
    pub envelope: Envelope,
    /// Index of this chunk
    pub index: u32,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Payload length of every chunk except the last. Identical in every chunk,
    /// so the canister can derive `offset = index * chunk_size`.
    pub chunk_size: u64,
    /// Total body length
    pub body_size: u64,
    /// SHA-256 of the `payload` field, 32 bytes
    pub payload_sha256: Vec<u8>,
    /// Chunk payload
    pub payload: Vec<u8>,
    /// Message headers - filled only in the first chunk
    pub headers: Option<Vec<Header>>,
    /// Gateway flags, also only in the first chunk
    pub gateway_flags: Option<Vec<String>>,
}

/// Reply payload for an accepted chunk
#[derive(Clone, Debug, Default, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadChunkOk {
    /// Number of total chunks received so far.
    pub chunks_received: u32,
}

/// Response to `smtp_upload_chunk` request
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum SmtpUploadChunkResponse {
    Ok(SmtpUploadChunkOk),
    Err(SmtpRequestError),
}

/// Finalizes an upload
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadCommit {
    /// Must be `SMTP_UPLOAD_PROTOCOL_VERSION`
    pub version: u32,
    pub message_id: String,
    /// SHA-256 over the concatenation of every chunk's payload digest in index
    /// order: `SHA256(d_0 || d_1 || .. || d_{n-1})` where `d_i = SHA256(payload_i)`.
    ///
    /// A poor-man's Merkle tree: it lets the canister verify the whole body by
    /// hashing `32 * total_chunks` bytes instead of re-reading the message.
    pub body_sha256: Vec<u8>,
    pub total_chunks: u32,
}

/// Identifies an existing upload.
/// Used by `smtp_upload_status` and `smtp_upload_abort`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadId {
    pub message_id: String,
}

/// State of an upload, as reported by `smtp_upload_status`.
#[derive(Clone, Debug, Default, CandidType, Deserialize, Eq, PartialEq)]
pub struct SmtpUploadStatus {
    /// An open upload exists for message_id
    pub known: bool,
    /// The upload was committed,
    /// `result` holds the outcome.
    pub committed: bool,
    /// `Some` only if `committed`
    pub result: Option<SmtpResponse>,
}

/// Response to `smtp_upload_status`.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum SmtpUploadStatusResponse {
    Ok(SmtpUploadStatus),
    Err(SmtpRequestError),
}

#[cfg(test)]
mod test {
    use candid::{CandidType, Decode, Deserialize, Encode};

    use super::*;

    /// Same wire shape as `SmtpRequest`, but with the fields declared in a
    /// different order. Candid records are keyed by field-name hash, so this
    /// must be interchangeable with `SmtpRequest`.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    struct SmtpRequestReordered {
        message_id: Option<String>,
        envelope: Option<Envelope>,
        gateway_flags: Option<Vec<String>>,
        message: Option<Message>,
    }

    /// A caller that only knows about `message_id`. Since every `SmtpRequest`
    /// field is `opt`, this must still decode into a full `SmtpRequest`.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    struct SmtpRequestPartial {
        message_id: Option<String>,
    }

    /// `SmtpRequestError` with `code` as `nat32` instead of `nat64`.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    struct SmtpRequestErrorNat32 {
        code: u32,
        message: String,
    }

    /// Mirror of `SmtpResponse` with the variants declared in reverse order.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    enum SmtpResponseReordered {
        Err(SmtpRequestError),
        Ok(SmtpOk),
    }

    /// Mirror of `SmtpResponse` with lower-cased variant labels - the labels
    /// are part of the wire format, so this must NOT be compatible.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    #[allow(non_camel_case_types)]
    enum SmtpResponseLowercase {
        ok(SmtpOk),
        err(SmtpRequestError),
    }

    fn address(user: &str, domain: &str) -> Address {
        Address {
            user: user.into(),
            domain: domain.into(),
        }
    }

    fn request() -> SmtpRequest {
        SmtpRequest {
            message: Some(Message {
                headers: vec![
                    Header {
                        name: "From".into(),
                        value: " foo@bar.com\n".into(),
                    },
                    Header {
                        name: "Subject".into(),
                        value: " ünïcödé ✉\n".into(),
                    },
                ],
                body: vec![0x00, 0x0a, 0x0d, 0xff, b'h', b'i'],
            }),
            envelope: Some(Envelope {
                from: address("foo", "bar.com"),
                to: vec![address("baz", "quux.com"), address("", "")],
            }),
            gateway_flags: Some(vec!["tls".into(), "spf".into()]),
            message_id: Some("deadbeef".into()),
        }
    }

    #[test]
    fn test_header_roundtrip() {
        let h = Header {
            name: "X-Foo".into(),
            value: String::new(),
        };
        let b = Encode!(&h).unwrap();
        assert_eq!(Decode!(&b, Header).unwrap(), h);

        // Non-ASCII values survive the round trip
        let h = Header {
            name: "Subject".into(),
            value: " ünïcödé ✉\r\n".into(),
        };
        let b = Encode!(&h).unwrap();
        assert_eq!(Decode!(&b, Header).unwrap(), h);
    }

    #[test]
    fn test_message_roundtrip() {
        // Empty message
        let m = Message {
            headers: vec![],
            body: vec![],
        };
        let b = Encode!(&m).unwrap();
        assert_eq!(Decode!(&b, Message).unwrap(), m);

        // Body is a byte blob, so all 256 byte values must round-trip intact
        let m = Message {
            headers: vec![Header {
                name: "To".into(),
                value: " a@b.c\n".into(),
            }],
            body: (0..=255u8).collect(),
        };
        let b = Encode!(&m).unwrap();
        let decoded = Decode!(&b, Message).unwrap();
        assert_eq!(decoded, m);
        assert_eq!(decoded.body.len(), 256);
        assert_eq!(decoded.body[255], 255);
    }

    #[test]
    fn test_address_and_envelope_roundtrip() {
        let a = address("foo+bar", "baz.com");
        let b = Encode!(&a).unwrap();
        assert_eq!(Decode!(&b, Address).unwrap(), a);

        // Empty user/domain are not validated at this layer
        let e = Envelope {
            from: address("", ""),
            to: vec![],
        };
        let b = Encode!(&e).unwrap();
        assert_eq!(Decode!(&b, Envelope).unwrap(), e);

        let e = Envelope {
            from: address("foo", "bar.com"),
            to: vec![address("a", "b.c"), address("d", "e.f")],
        };
        let b = Encode!(&e).unwrap();
        let decoded = Decode!(&b, Envelope).unwrap();
        assert_eq!(decoded, e);
        // Recipient order is significant
        assert_eq!(decoded.to[0].user, "a");
        assert_eq!(decoded.to[1].user, "d");
    }

    #[test]
    fn test_request_roundtrip() {
        let r = request();
        let b = Encode!(&r).unwrap();
        assert_eq!(Decode!(&b, SmtpRequest).unwrap(), r);

        // All-empty request
        let r = SmtpRequest {
            message: None,
            envelope: None,
            gateway_flags: None,
            message_id: None,
        };
        let b = Encode!(&r).unwrap();
        assert_eq!(Decode!(&b, SmtpRequest).unwrap(), r);
    }

    #[test]
    fn test_request_field_order_irrelevant() {
        let r = request();
        let b = Encode!(&r).unwrap();

        // Decoding into a struct with the same fields in a different order works
        let reordered = Decode!(&b, SmtpRequestReordered).unwrap();
        assert_eq!(reordered.message_id, r.message_id);
        assert_eq!(reordered.message, r.message);
        assert_eq!(reordered.envelope, r.envelope);
        assert_eq!(reordered.gateway_flags, r.gateway_flags);

        // ...and back again
        let b = Encode!(&reordered).unwrap();
        assert_eq!(Decode!(&b, SmtpRequest).unwrap(), r);
    }

    #[test]
    fn test_request_fields_are_optional_on_the_wire() {
        // Every field of `SmtpRequest` is `opt`, so a caller that provides only
        // a subset still produces a decodable request.
        let partial = SmtpRequestPartial {
            message_id: Some("abc".into()),
        };
        let b = Encode!(&partial).unwrap();
        let decoded = Decode!(&b, SmtpRequest).unwrap();
        assert_eq!(
            decoded,
            SmtpRequest {
                message: None,
                envelope: None,
                gateway_flags: None,
                message_id: Some("abc".into()),
            }
        );
    }

    #[test]
    fn test_request_decoding_edge_cases() {
        // Every `SmtpRequest` field is `opt`, which makes the record a Candid
        // supertype of *any* record. So an unrelated record payload decodes
        // into an all-`None` request instead of being rejected - the canister
        // side has to validate the fields itself.
        let b = Encode!(&Message {
            headers: vec![],
            body: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(
            Decode!(&b, SmtpRequest).unwrap(),
            SmtpRequest {
                message: None,
                envelope: None,
                gateway_flags: None,
                message_id: None,
            }
        );

        // A non-record payload is not a record, so that one does fail
        let b = Encode!(&"just a string").unwrap();
        assert!(Decode!(&b, SmtpRequest).is_err());
        let b = Encode!(&42u64).unwrap();
        assert!(Decode!(&b, SmtpRequest).is_err());

        // Truncated & empty payloads
        let b = Encode!(&request()).unwrap();
        assert!(Decode!(&b[..b.len() / 2], SmtpRequest).is_err());
        assert!(Decode!(&[] as &[u8], SmtpRequest).is_err());

        // Extra trailing arguments are ignored (Candid forward compatibility) -
        // only the first one is decoded
        let b = Encode!(&request(), &42u64).unwrap();
        assert_eq!(Decode!(&b, SmtpRequest).unwrap(), request());

        // Asking for more arguments than were encoded is an error, though
        let b = Encode!(&request()).unwrap();
        assert!(Decode!(&b, SmtpRequest, SmtpRequest).is_err());
    }

    #[test]
    fn test_request_error_code_is_nat64() {
        let e = SmtpRequestError {
            code: u64::MAX,
            message: "boom".into(),
        };
        let b = Encode!(&e).unwrap();
        assert_eq!(Decode!(&b, SmtpRequestError).unwrap(), e);

        // `code` is `nat64` on the wire: a `nat32` is not a subtype of it
        let b = Encode!(&SmtpRequestErrorNat32 {
            code: 550,
            message: "nope".into(),
        })
        .unwrap();
        assert!(Decode!(&b, SmtpRequestError).is_err());
    }

    #[test]
    fn test_response_roundtrip() {
        let r = SmtpResponse::Ok(SmtpOk {});
        let b = Encode!(&r).unwrap();
        assert_eq!(Decode!(&b, SmtpResponse).unwrap(), r);

        let r = SmtpResponse::Err(SmtpRequestError {
            code: 550,
            message: "Unknown recipient".into(),
        });
        let b = Encode!(&r).unwrap();
        let decoded = Decode!(&b, SmtpResponse).unwrap();
        assert_eq!(decoded, r);
        let SmtpResponse::Err(e) = decoded else {
            panic!("expected Err variant");
        };
        assert_eq!(e.code, 550);
        assert_eq!(e.message, "Unknown recipient");
    }

    #[test]
    fn test_response_variant_labels() {
        // Variant declaration order doesn't matter...
        for r in [
            SmtpResponse::Ok(SmtpOk {}),
            SmtpResponse::Err(SmtpRequestError {
                code: 1,
                message: "x".into(),
            }),
        ] {
            let b = Encode!(&r).unwrap();
            let reordered = Decode!(&b, SmtpResponseReordered).unwrap();
            match (&r, &reordered) {
                (SmtpResponse::Ok(_), SmtpResponseReordered::Ok(_)) => {}
                (SmtpResponse::Err(a), SmtpResponseReordered::Err(b)) => assert_eq!(a, b),
                _ => panic!("variant mismatch: {r:?} vs {reordered:?}"),
            }

            // ...but the labels themselves do: `Ok`/`Err`, not `ok`/`err`
            assert!(Decode!(&b, SmtpResponseLowercase).is_err());
        }
    }

    #[test]
    fn test_ok_is_empty_record() {
        // `Ok` carries an empty record, so it's interchangeable with any other
        // empty record and decoding it yields no fields.
        #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
        struct OtherEmpty {}

        let b = Encode!(&SmtpOk {}).unwrap();
        assert!(Decode!(&b, OtherEmpty).is_ok());
        assert_eq!(Decode!(&b, SmtpOk).unwrap(), SmtpOk {});
    }

    // -----------------------------------------------------------------------
    // Chunked upload protocol
    // -----------------------------------------------------------------------

    /// `SmtpUploadChunk` with `index` widened to `nat64`. The field is not
    /// wrapped in `opt`, so this must be a hard decode failure rather than a
    /// silently-recovered `None` - that is the whole reason the upload types
    /// use required fields.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    struct SmtpUploadChunkWideIndex {
        version: u32,
        message_id: String,
        envelope: Envelope,
        index: u64,
        total: u32,
        chunk_size: u64,
        body_size: u64,
        payload_sha256: Vec<u8>,
        payload: Vec<u8>,
        headers: Option<Vec<Header>>,
        gateway_flags: Option<Vec<String>>,
    }

    /// A caller that only knows about `message_id`, as `SmtpRequestPartial` is
    /// for `SmtpRequest`. Unlike there, this must NOT decode.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    struct SmtpUploadChunkPartial {
        message_id: String,
    }

    /// Mirror of `SmtpUploadChunkResponse` with lower-cased labels - the labels
    /// are part of the wire format, so this must NOT be compatible.
    #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
    #[allow(non_camel_case_types)]
    enum SmtpUploadChunkResponseLowercase {
        ok(SmtpUploadChunkOk),
        err(SmtpRequestError),
    }

    fn chunk() -> SmtpUploadChunk {
        SmtpUploadChunk {
            version: SMTP_UPLOAD_PROTOCOL_VERSION,
            message_id: "0193f0a1-2b3c-7d4e-8f90-a1b2c3d4e5f6".into(),
            envelope: Envelope {
                from: address("foo", "bar.com"),
                to: vec![address("baz", "quux.com")],
            },
            index: 3,
            total_chunks: 7,
            chunk_size: 1024,
            body_size: 6500,
            payload_sha256: vec![0xaa; SHA256_LEN],
            payload: (0..=255u8).collect(),
            headers: None,
            gateway_flags: None,
        }
    }

    #[test]
    fn test_capabilities_roundtrip() {
        let c = SmtpCapabilities {
            upload_protocol_version: Some(1),
            max_message_size: Some(25 * 1024 * 1024),
        };
        let b = Encode!(&c).unwrap();
        assert_eq!(Decode!(&b, SmtpCapabilities).unwrap(), c);
        assert!(c.supports_chunked());
    }

    /// A canister that does not implement the protocol answers with an empty
    /// record (or nothing at all). That must read as "legacy", never as
    /// "supports chunking with unknown limits".
    #[test]
    fn test_capabilities_empty_record_is_legacy() {
        let b = Encode!(&SmtpOk {}).unwrap();
        let caps = Decode!(&b, SmtpCapabilities).unwrap();

        assert_eq!(caps, SmtpCapabilities::default());
        assert!(!caps.supports_chunked());
        assert!(!SmtpCapabilities::default().supports_chunked());
    }

    /// `supports_chunked` is fail-closed: every part must be present & usable.
    #[test]
    fn test_supports_chunked_is_fail_closed() {
        let full = SmtpCapabilities {
            upload_protocol_version: Some(1),
            max_message_size: Some(1024),
        };
        assert!(full.supports_chunked());

        // A newer canister is still usable by us
        assert!(
            SmtpCapabilities {
                upload_protocol_version: Some(2),
                ..full
            }
            .supports_chunked()
        );

        for broken in [
            SmtpCapabilities {
                upload_protocol_version: None,
                ..full.clone()
            },
            SmtpCapabilities {
                upload_protocol_version: Some(0),
                ..full.clone()
            },
            SmtpCapabilities {
                max_message_size: None,
                ..full.clone()
            },
            SmtpCapabilities {
                max_message_size: Some(0),
                ..full
            },
        ] {
            assert!(!broken.supports_chunked(), "{broken:?}");
        }
    }

    #[test]
    fn test_upload_chunk_roundtrip() {
        let c = chunk();
        let b = Encode!(&c).unwrap();
        let decoded = Decode!(&b, SmtpUploadChunk).unwrap();
        assert_eq!(decoded, c);
        // The payload is a blob, so every byte value survives
        assert_eq!(decoded.payload.len(), 256);
        assert_eq!(decoded.payload[255], 255);

        // First chunk, carrying the header block
        let c = SmtpUploadChunk {
            index: 0,
            headers: Some(vec![Header {
                name: "Subject".into(),
                value: " ünïcödé ✉\n".into(),
            }]),
            gateway_flags: Some(vec!["tls".into()]),
            ..chunk()
        };
        let b = Encode!(&c).unwrap();
        assert_eq!(Decode!(&b, SmtpUploadChunk).unwrap(), c);
    }

    /// The upload types deliberately do NOT use the all-`opt` style of
    /// `SmtpRequest`: a partial or unrelated payload must fail loudly instead
    /// of decoding into a meaningless empty chunk.
    #[test]
    fn test_upload_chunk_rejects_partial_and_unrelated_payloads() {
        // Compare with `test_request_fields_are_optional_on_the_wire`, where the
        // equivalent payload decodes happily.
        let b = Encode!(&SmtpUploadChunkPartial {
            message_id: "abc".into(),
        })
        .unwrap();
        assert!(Decode!(&b, SmtpUploadChunk).is_err());

        // An unrelated record - this is what silently becomes an all-`None`
        // `SmtpRequest` in `test_request_decoding_edge_cases`.
        let b = Encode!(&Message {
            headers: vec![],
            body: vec![1, 2, 3],
        })
        .unwrap();
        assert!(Decode!(&b, SmtpUploadChunk).is_err());

        // ...and the usual malformed payloads
        let b = Encode!(&chunk()).unwrap();
        assert!(Decode!(&b[..b.len() / 2], SmtpUploadChunk).is_err());
        assert!(Decode!(&[] as &[u8], SmtpUploadChunk).is_err());
        assert!(Decode!(&Encode!(&42u64).unwrap(), SmtpUploadChunk).is_err());
    }

    /// Because the counters are not wrapped in `opt`, a width mismatch is a
    /// decode error. Inside an `opt` it would be recovered to `None` instead,
    /// and the canister would silently see a chunk with no index.
    #[test]
    fn test_upload_chunk_counter_widths_are_exact() {
        let c = chunk();
        let wide = SmtpUploadChunkWideIndex {
            version: c.version,
            message_id: c.message_id.clone(),
            envelope: c.envelope.clone(),
            index: u64::from(c.index),
            total: c.total_chunks,
            chunk_size: c.chunk_size,
            body_size: c.body_size,
            payload_sha256: c.payload_sha256.clone(),
            payload: c.payload,
            headers: None,
            gateway_flags: None,
        };

        let b = Encode!(&wide).unwrap();
        assert!(
            Decode!(&b, SmtpUploadChunk).is_err(),
            "nat64 index must not decode as nat32"
        );
    }

    #[test]
    fn test_upload_responses_roundtrip_and_labels() {
        let r = SmtpUploadChunkResponse::Ok(SmtpUploadChunkOk { chunks_received: 4 });
        let b = Encode!(&r).unwrap();
        assert_eq!(Decode!(&b, SmtpUploadChunkResponse).unwrap(), r);
        // Labels are part of the wire format
        assert!(Decode!(&b, SmtpUploadChunkResponseLowercase).is_err());

        let r = SmtpUploadChunkResponse::Err(SmtpRequestError {
            code: 452,
            message: "too many open uploads".into(),
        });
        let b = Encode!(&r).unwrap();
        assert_eq!(Decode!(&b, SmtpUploadChunkResponse).unwrap(), r);
    }

    #[test]
    fn test_upload_commit_and_ref_roundtrip() {
        let c = SmtpUploadCommit {
            version: SMTP_UPLOAD_PROTOCOL_VERSION,
            message_id: "deadbeef".into(),
            body_sha256: vec![0x11; SHA256_LEN],
            total_chunks: 21,
        };
        let b = Encode!(&c).unwrap();
        assert_eq!(Decode!(&b, SmtpUploadCommit).unwrap(), c);

        let r = SmtpUploadId {
            message_id: "deadbeef".into(),
        };
        let b = Encode!(&r).unwrap();
        assert_eq!(Decode!(&b, SmtpUploadId).unwrap(), r);
    }

    #[test]
    fn test_upload_status_roundtrip() {
        // Committed, carrying the terminal verdict
        let st = SmtpUploadStatus {
            known: true,
            committed: true,
            result: Some(SmtpResponse::Ok(SmtpOk {})),
        };
        let b = Encode!(&SmtpUploadStatusResponse::Ok(st.clone())).unwrap();
        assert_eq!(
            Decode!(&b, SmtpUploadStatusResponse).unwrap(),
            SmtpUploadStatusResponse::Ok(st)
        );

        // Still open, with holes
        let st = SmtpUploadStatus {
            known: true,
            committed: false,
            result: None,
        };
        let b = Encode!(&SmtpUploadStatusResponse::Ok(st.clone())).unwrap();
        let SmtpUploadStatusResponse::Ok(decoded) = Decode!(&b, SmtpUploadStatusResponse).unwrap()
        else {
            panic!("expected Ok variant");
        };
        assert_eq!(decoded, st);

        // Unknown upload - the default is the safe reading
        assert_eq!(
            SmtpUploadStatus::default(),
            SmtpUploadStatus {
                known: false,
                committed: false,
                result: None,
            }
        );
    }

    /// Documented sharp edge: `SmtpUploadRef` is a Candid subtype of
    /// `SmtpRequest`, because `text <: opt text` and record width subtyping
    /// drops the rest. Harmless - they live on different methods - but it is
    /// exactly the class of hazard `test_request_decoding_edge_cases` exists to
    /// flag, so it is pinned here rather than discovered later.
    #[test]
    fn test_upload_ref_is_a_subtype_of_request() {
        let b = Encode!(&SmtpUploadId {
            message_id: "abc".into(),
        })
        .unwrap();
        assert_eq!(
            Decode!(&b, SmtpRequest).unwrap(),
            SmtpRequest {
                message: None,
                envelope: None,
                gateway_flags: None,
                message_id: Some("abc".into()),
            }
        );

        // The reverse does not hold: `opt text` is not a subtype of `text`.
        let b = Encode!(&SmtpRequest {
            message: None,
            envelope: None,
            gateway_flags: None,
            message_id: None,
        })
        .unwrap();
        assert!(Decode!(&b, SmtpUploadId).is_err());
    }

    /// Records are keyed by field-name hash, so the upload types tolerate a
    /// canister declaring their fields in a different order - just like
    /// `test_request_field_order_irrelevant` pins for `SmtpRequest`.
    #[test]
    fn test_upload_commit_field_order_irrelevant() {
        #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
        struct Reordered {
            total_chunks: u32,
            body_sha256: Vec<u8>,
            message_id: String,
            version: u32,
        }

        let c = SmtpUploadCommit {
            version: 1,
            message_id: "x".into(),
            body_sha256: vec![7; SHA256_LEN],
            total_chunks: 3,
        };
        let b = Encode!(&c).unwrap();
        let r = Decode!(&b, Reordered).unwrap();
        assert_eq!(r.total_chunks, 3);
        assert_eq!(r.message_id, "x");

        assert_eq!(Decode!(&Encode!(&r).unwrap(), SmtpUploadCommit).unwrap(), c);
    }

    /// Dropping a required field is only safe before anyone implements the
    /// protocol, because the compatibility is one-way. Pin both directions so
    /// the next person can see why the removal had to precede adoption.
    #[test]
    fn test_chunk_decode_asymmetry_after_dropping_body_sha256() {
        /// The shape `SmtpUploadChunk` had while it still carried the body digest.
        #[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
        struct SmtpUploadChunkV0 {
            version: u32,
            message_id: String,
            envelope: Envelope,
            index: u32,
            total_chunks: u32,
            chunk_size: u64,
            body_size: u64,
            payload_sha256: Vec<u8>,
            body_sha256: Vec<u8>,
            payload: Vec<u8>,
            headers: Option<Vec<Header>>,
            gateway_flags: Option<Vec<String>>,
        }

        let c = chunk();
        let old = SmtpUploadChunkV0 {
            version: c.version,
            message_id: c.message_id.clone(),
            envelope: c.envelope.clone(),
            index: c.index,
            total_chunks: c.total_chunks,
            chunk_size: c.chunk_size,
            body_size: c.body_size,
            payload_sha256: c.payload_sha256.clone(),
            body_sha256: vec![0xbb; SHA256_LEN],
            payload: c.payload.clone(),
            headers: c.headers.clone(),
            gateway_flags: c.gateway_flags.clone(),
        };

        // A sender still carrying the field is fine: record width subtyping
        // drops what the receiver does not declare.
        let b = Encode!(&old).unwrap();
        assert_eq!(Decode!(&b, SmtpUploadChunk).unwrap(), c);

        // A receiver that still REQUIRES it is not fine - which is exactly why
        // this could not be done after a canister had shipped.
        let b = Encode!(&c).unwrap();
        assert!(Decode!(&b, SmtpUploadChunkV0).is_err());
    }
}
