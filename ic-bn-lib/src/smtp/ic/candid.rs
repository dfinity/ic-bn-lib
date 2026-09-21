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
}
