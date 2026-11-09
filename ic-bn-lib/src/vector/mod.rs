use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, anyhow};
use bytes::BytesMut;
use prost::Message;
use url::Url;
use vrl::value::{ObjectMap, Value};

use crate::vector::cli::VectorCli;

pub mod cli;
pub mod client;
#[allow(warnings, clippy::all, clippy::pedantic)]
mod event;

/// Vector options
#[derive(Clone, Debug)]
pub struct VectorOptions {
    pub url: Url,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub batch_size: usize,
    pub batch_queue: usize,
    pub batch_flush_interval: Duration,
    pub buffer: usize,
    pub flushers: usize,
    pub flush_timeout: Duration,
    pub retry_interval: Duration,
    pub retry_count: usize,
    pub zstd_level: usize,
}

impl TryFrom<&VectorCli> for VectorOptions {
    type Error = anyhow::Error;

    fn try_from(v: &VectorCli) -> Result<Self, Self::Error> {
        let url = v
            .log_vector_url
            .clone()
            .ok_or_else(|| anyhow!("URL is required"))?;

        Ok(Self {
            url,
            user: v.log_vector_user.clone(),
            pass: v.log_vector_pass.clone(),
            batch_size: v.log_vector_batch,
            batch_queue: v.log_vector_batch_queue,
            batch_flush_interval: v.log_vector_interval,
            buffer: v.log_vector_buffer,
            flushers: v.log_vector_flushers,
            flush_timeout: v.log_vector_timeout,
            retry_interval: v.log_vector_retry_interval,
            retry_count: v.log_vector_retry_count,
            zstd_level: v.log_vector_zstd_level,
        })
    }
}

pub fn encode_map(fields: ObjectMap) -> event::ValueMap {
    event::ValueMap {
        fields: fields
            .into_iter()
            .map(|(key, value)| (key.into(), encode_value(value)))
            .collect(),
    }
}

pub fn encode_array(items: Vec<Value>) -> event::ValueArray {
    event::ValueArray {
        items: items.into_iter().map(encode_value).collect(),
    }
}

pub fn encode_value(value: Value) -> event::Value {
    event::Value {
        kind: match value {
            Value::String(s) => Some(event::value::Kind::RawBytes(s.into_bytes())),
            Value::Bytes(b) => Some(event::value::Kind::RawBytes(b)),
            Value::Regex(regex) => Some(event::value::Kind::RawBytes(regex.as_bytes())),
            Value::Timestamp(ts) => Some(event::value::Kind::Timestamp(prost_types::Timestamp {
                seconds: ts.timestamp(),
                nanos: ts.timestamp_subsec_nanos() as i32,
            })),
            Value::Integer(value) => Some(event::value::Kind::Integer(value)),
            Value::Float(value) => Some(event::value::Kind::Float(value.into_inner())),
            Value::Boolean(value) => Some(event::value::Kind::Boolean(value)),
            Value::Object(fields) => Some(event::value::Kind::Map(encode_map(fields))),
            Value::Array(items) => Some(event::value::Kind::Array(encode_array(items))),
            Value::Null => Some(event::value::Kind::Null(event::ValueNull::NullValue as i32)),
        },
    }
}

pub fn prepare_event(event: serde_json::Value) -> event::EventArray {
    let event = Value::from(event);

    // Dummy fields required by Vector
    let fields = BTreeMap::from_iter([(".".to_owned(), encode_value(Value::Null))]);

    // Wonderful chain of wrapping...
    #[allow(deprecated)]
    let event = event::Log {
        fields,
        value: Some(encode_value(event)),
        metadata: None,
        metadata_full: None,
    };
    let event = event::LogArray { logs: vec![event] };
    let event = event::event_array::Events::Logs(event);
    event::EventArray {
        events: Some(event),
    }
}

pub fn encode_event(event: serde_json::Value, buf: &mut BytesMut) -> Result<(), crate::Error> {
    let event = prepare_event(event);
    event.encode(buf).context("unable to encode to Protobuf")?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use vrl::value::ValueRegex;

    use super::{
        event::{
            EventArray, Log, ValueArray, ValueMap, ValueNull, event_array::Events, value::Kind,
        },
        *,
    };

    fn kind(v: Value) -> Kind {
        encode_value(v)
            .kind
            .expect("encode_value must always set the kind")
    }

    fn null() -> Kind {
        Kind::Null(ValueNull::NullValue as i32)
    }

    fn raw(b: &[u8]) -> Kind {
        Kind::RawBytes(Bytes::copy_from_slice(b))
    }

    fn wrap(kind: Kind) -> event::Value {
        event::Value { kind: Some(kind) }
    }

    /// Decodes an `EventArray` and returns its only log entry
    fn decode_single_log(buf: &[u8]) -> Log {
        let ev = EventArray::decode(buf).expect("unable to decode the event");
        let Some(Events::Logs(mut logs)) = ev.events else {
            panic!("expected a log array, got {:?}", ev.events);
        };
        assert_eq!(logs.logs.len(), 1, "expected exactly one log entry");
        logs.logs.remove(0)
    }

    /// Checks the parts of the log entry that don't depend on the event
    fn assert_envelope(log: &Log) {
        assert_eq!(log.fields.len(), 1, "only the dummy field is expected");
        assert_eq!(log.fields["."], wrap(null()));
        #[allow(deprecated)]
        let metadata = &log.metadata;
        assert_eq!(metadata, &None);
        assert_eq!(log.metadata_full, None);
    }

    /// Converts an encoded value back to JSON.
    /// Panics on anything that a JSON input must not produce.
    fn to_json(v: &event::Value) -> serde_json::Value {
        match v.kind.as_ref().expect("value has no kind") {
            Kind::RawBytes(b) => String::from_utf8(b.to_vec())
                .expect("strings must stay valid UTF-8")
                .into(),
            Kind::Integer(i) => (*i).into(),
            Kind::Float(f) => serde_json::Number::from_f64(*f)
                .expect("JSON floats are finite")
                .into(),
            Kind::Boolean(b) => (*b).into(),
            Kind::Null(n) => {
                assert_eq!(*n, ValueNull::NullValue as i32);
                serde_json::Value::Null
            }
            Kind::Map(m) => m
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), to_json(v)))
                .collect::<serde_json::Map<_, _>>()
                .into(),
            Kind::Array(a) => a.items.iter().map(to_json).collect::<Vec<_>>().into(),
            Kind::Timestamp(ts) => panic!("JSON can't produce a timestamp, got {ts:?}"),
        }
    }

    /// What a JSON value looks like after it went through the encoder.
    /// Integers above `i64::MAX` don't fit into `int64` and are sent as strings,
    /// everything else must be unchanged.
    fn expected_json(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Number(n) if n.as_u64().is_some_and(|x| x > i64::MAX as u64) => {
                n.to_string().into()
            }
            serde_json::Value::Array(a) => {
                a.into_iter().map(expected_json).collect::<Vec<_>>().into()
            }
            serde_json::Value::Object(o) => o
                .into_iter()
                .map(|(k, v)| (k, expected_json(v)))
                .collect::<serde_json::Map<_, _>>()
                .into(),
            x => x,
        }
    }

    /// Runs the event through `encode_event`, decodes it back and returns the value as JSON
    fn json_roundtrip(event: serde_json::Value) -> serde_json::Value {
        let mut buf = BytesMut::new();
        encode_event(event, &mut buf).unwrap();
        let log = decode_single_log(&buf);
        assert_envelope(&log);
        to_json(log.value.as_ref().expect("log has no value"))
    }

    fn assert_json_roundtrip(event: serde_json::Value) {
        let expected = expected_json(event.clone());
        assert_eq!(json_roundtrip(event.clone()), expected, "input: {event}");
    }

    /// Minimal xorshift64* PRNG to generate reproducible inputs without extra dependencies
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn pick<T: Copy>(&mut self, items: &[T]) -> T {
            items[self.below(items.len())]
        }

        fn string(&mut self) -> String {
            const CHARS: &[char] = &[
                'a',
                'Z',
                '0',
                ' ',
                '.',
                '"',
                '\\',
                '\n',
                '\0',
                '\u{7f}',
                'é',
                'ß',
                '中',
                '🌍',
                '\u{10FFFF}',
            ];
            (0..self.below(8)).map(|_| self.pick(CHARS)).collect()
        }

        fn float(&mut self) -> f64 {
            const EDGES: &[f64] = &[
                0.0,
                -0.0,
                1.0,
                -1.5,
                1e100,
                f64::MIN_POSITIVE,
                5e-324,
                f64::MAX,
                f64::MIN,
                i64::MAX as f64,
            ];
            if self.below(2) == 0 {
                return self.pick(EDGES);
            }
            Some(f64::from_bits(self.next()))
                .filter(|f| f.is_finite())
                .unwrap_or(0.25)
        }

        fn json(&mut self, depth: u32) -> serde_json::Value {
            match self.below(if depth == 0 { 7 } else { 9 }) {
                0 => serde_json::Value::Null,
                1 => (self.below(2) == 1).into(),
                2 => (self.next() as i64).into(),
                3 => self.pick(&[0, 1, -1, i64::MIN, i64::MAX]).into(),
                // Above i64::MAX
                4 => (self.next() | 1 << 63).into(),
                5 => serde_json::Number::from_f64(self.float()).unwrap().into(),
                6 => self.string().into(),
                7 => (0..self.below(5))
                    .map(|_| self.json(depth - 1))
                    .collect::<Vec<_>>()
                    .into(),
                _ => (0..self.below(5))
                    .map(|_| (self.string(), self.json(depth - 1)))
                    .collect::<serde_json::Map<_, _>>()
                    .into(),
            }
        }
    }

    #[test]
    fn test_encode_value_string() {
        let v = Value::from("héllo 🌍");
        // Make sure we're really testing the `String` variant and not `Bytes`
        assert!(matches!(v, Value::String(_)), "{v:?}");
        assert_eq!(kind(v), raw("héllo 🌍".as_bytes()));

        // Empty string must still be sent as an (empty) value, not as a missing one
        let v = Value::from("");
        assert!(matches!(v, Value::String(_)), "{v:?}");
        assert_eq!(kind(v), raw(b""));

        // Control characters and NUL are passed through as-is
        assert_eq!(kind(Value::from("a\0b\n\t")), raw(b"a\0b\n\t"));

        // Strings and bytes are indistinguishable on the wire
        for s in ["", "foo", "héllo 🌍", "\0"] {
            let as_string = encode_value(Value::from(s)).encode_to_vec();
            let as_bytes =
                encode_value(Value::Bytes(Bytes::copy_from_slice(s.as_bytes()))).encode_to_vec();
            assert_eq!(as_string, as_bytes, "{s:?}");
        }
    }

    #[test]
    fn test_encode_value_bytes() {
        // Non-UTF-8 bytes are passed through as-is
        let b = Bytes::from_static(b"\x00\xff\xfe\x80");
        assert_eq!(kind(Value::Bytes(b.clone())), Kind::RawBytes(b));
        assert_eq!(kind(Value::Bytes(Bytes::new())), raw(b""));
    }

    #[test]
    fn test_encode_value_regex() {
        // A regex is sent as its source text, flags included
        for src in [r"(?i)^héllo\s+🌍$", r"\d{1,3}", ""] {
            let rx = ValueRegex::new(Arc::new(crate::regex!(src)));
            assert_eq!(kind(Value::Regex(rx)), raw(src.as_bytes()));
        }
    }

    #[test]
    fn test_encode_value_integer() {
        for i in [0, 1, -1, i64::MIN, i64::MAX] {
            assert_eq!(kind(Value::Integer(i)), Kind::Integer(i));
        }
    }

    #[test]
    fn test_encode_value_float() {
        for f in [
            0.0,
            -0.0,
            1.5,
            -1.5,
            f64::MIN_POSITIVE,
            // Smallest subnormal
            5e-324,
            f64::MAX,
            f64::MIN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let Kind::Float(got) = kind(Value::from_f64_or_zero(f)) else {
                panic!("{f} wasn't encoded as a float");
            };
            // Compare bits to catch e.g. a lost sign of -0.0
            assert_eq!(got.to_bits(), f.to_bits(), "{f}");
        }
    }

    #[test]
    fn test_encode_value_boolean_and_null() {
        assert_eq!(kind(Value::Boolean(true)), Kind::Boolean(true));
        assert_eq!(kind(Value::Boolean(false)), Kind::Boolean(false));
        assert_eq!(kind(Value::Null), null());
    }

    #[test]
    fn test_encode_value_timestamp_edges() {
        let cases = [
            DateTime::from_timestamp(0, 999_999_999).unwrap(),
            DateTime::from_timestamp(-1, 999_999_999).unwrap(),
            DateTime::from_timestamp(i32::MAX as i64 + 1, 1).unwrap(),
            DateTime::<Utc>::MIN_UTC,
            DateTime::<Utc>::MAX_UTC,
        ];

        for ts in cases {
            let Kind::Timestamp(got) = kind(Value::Timestamp(ts)) else {
                panic!("{ts} wasn't encoded as a timestamp");
            };
            assert!((0..1_000_000_000).contains(&got.nanos), "{ts}: {got:?}");
            assert_eq!(
                DateTime::from_timestamp(got.seconds, got.nanos as u32),
                Some(ts),
                "{ts} can't be restored from {got:?}"
            );
        }
    }

    #[test]
    fn test_encode_map() {
        assert_eq!(encode_map(ObjectMap::new()), ValueMap::default());
        assert_eq!(
            kind(Value::Object(ObjectMap::new())),
            Kind::Map(ValueMap::default())
        );

        let map = ObjectMap::from([
            // Keys are copied verbatim: no path splitting, unescaping or trimming
            ("".into(), Value::Integer(1)),
            (".".into(), Value::Integer(2)),
            ("a.b".into(), Value::Integer(3)),
            ("a[0]".into(), Value::Integer(4)),
            (" spaced ".into(), Value::Integer(5)),
            ("ключ 🌍".into(), Value::Integer(6)),
            // Values are encoded recursively
            ("str".into(), Value::from("v")),
            ("null".into(), Value::Null),
            (
                "nested".into(),
                Value::Object(ObjectMap::from([(
                    "inner".into(),
                    Value::Array(vec![Value::Boolean(true)]),
                )])),
            ),
        ]);

        let expected = BTreeMap::from([
            ("".to_owned(), wrap(Kind::Integer(1))),
            (".".to_owned(), wrap(Kind::Integer(2))),
            ("a.b".to_owned(), wrap(Kind::Integer(3))),
            ("a[0]".to_owned(), wrap(Kind::Integer(4))),
            (" spaced ".to_owned(), wrap(Kind::Integer(5))),
            ("ключ 🌍".to_owned(), wrap(Kind::Integer(6))),
            ("str".to_owned(), wrap(raw(b"v"))),
            ("null".to_owned(), wrap(null())),
            (
                "nested".to_owned(),
                wrap(Kind::Map(ValueMap {
                    fields: BTreeMap::from([(
                        "inner".to_owned(),
                        wrap(Kind::Array(ValueArray {
                            items: vec![wrap(Kind::Boolean(true))],
                        })),
                    )]),
                })),
            ),
        ]);

        assert_eq!(encode_map(map.clone()).fields, expected);
        assert_eq!(
            kind(Value::Object(map)),
            Kind::Map(ValueMap { fields: expected })
        );
    }

    #[test]
    fn test_encode_array() {
        assert_eq!(encode_array(vec![]), ValueArray::default());
        assert_eq!(
            kind(Value::Array(vec![])),
            Kind::Array(ValueArray::default())
        );

        // Order and duplicates are kept, mixed types are fine
        let items = vec![
            Value::Integer(3),
            Value::Integer(1),
            Value::Integer(3),
            Value::Null,
            Value::from("s"),
            Value::Array(vec![Value::Array(vec![]), Value::Integer(-1)]),
            Value::Object(ObjectMap::from([("k".into(), Value::Boolean(false))])),
        ];

        let expected = vec![
            wrap(Kind::Integer(3)),
            wrap(Kind::Integer(1)),
            wrap(Kind::Integer(3)),
            wrap(null()),
            wrap(raw(b"s")),
            wrap(Kind::Array(ValueArray {
                items: vec![
                    wrap(Kind::Array(ValueArray::default())),
                    wrap(Kind::Integer(-1)),
                ],
            })),
            wrap(Kind::Map(ValueMap {
                fields: BTreeMap::from([("k".to_owned(), wrap(Kind::Boolean(false)))]),
            })),
        ];

        assert_eq!(encode_array(items.clone()).items, expected);
        assert_eq!(
            kind(Value::Array(items)),
            Kind::Array(ValueArray { items: expected })
        );
    }

    #[test]
    fn test_prepare_event_envelope() {
        // A user-provided "." key must end up in the value and not clash with the dummy field
        let ev = prepare_event(json!({".": "user", "foo": 1}));
        let Some(Events::Logs(logs)) = &ev.events else {
            panic!("expected a log array, got {:?}", ev.events);
        };
        assert_eq!(logs.logs.len(), 1);

        let log = &logs.logs[0];
        assert_envelope(log);
        assert_eq!(
            log.value,
            Some(wrap(Kind::Map(ValueMap {
                fields: BTreeMap::from([
                    (".".to_owned(), wrap(raw(b"user"))),
                    ("foo".to_owned(), wrap(Kind::Integer(1))),
                ])
            })))
        );

        // Empty object is still sent as a map
        let log = decode_single_log(&prepare_event(json!({})).encode_to_vec());
        assert_envelope(&log);
        assert_eq!(log.value, Some(wrap(Kind::Map(ValueMap::default()))));
    }

    #[test]
    fn test_prepare_event_non_object_root() {
        // Non-object events are wrapped as-is, the envelope stays the same
        let cases = [
            (json!(null), null()),
            (json!("str"), raw(b"str")),
            (json!(-5), Kind::Integer(-5)),
            (json!(0.5), Kind::Float(0.5)),
            (json!(true), Kind::Boolean(true)),
            (
                json!([1, "a"]),
                Kind::Array(ValueArray {
                    items: vec![wrap(Kind::Integer(1)), wrap(raw(b"a"))],
                }),
            ),
        ];

        for (input, expected) in cases {
            let log = decode_single_log(&prepare_event(input.clone()).encode_to_vec());
            assert_envelope(&log);
            assert_eq!(log.value, Some(wrap(expected)), "{input}");
        }
    }

    #[test]
    fn test_prepare_event_json_numbers() {
        let log = decode_single_log(
            &prepare_event(json!({
                "int": 1,
                "float_integral": 1.0,
                "float_exp": 1e2,
                "neg_zero": -0.0,
                "i64_min": i64::MIN,
                "i64_max": i64::MAX,
                "i64_max_plus_one": i64::MAX as u64 + 1,
                "u64_max": u64::MAX,
            }))
            .encode_to_vec(),
        );

        let Some(Kind::Map(map)) = log.value.and_then(|x| x.kind) else {
            panic!("expected a map");
        };
        let f = |k: &str| map.fields[k].kind.clone().unwrap();

        // JSON integers and floats stay distinguishable even if numerically equal
        assert_eq!(f("int"), Kind::Integer(1));
        assert_eq!(f("float_integral"), Kind::Float(1.0));
        assert_eq!(f("float_exp"), Kind::Float(100.0));
        let Kind::Float(neg_zero) = f("neg_zero") else {
            panic!("expected a float");
        };
        assert_eq!(neg_zero.to_bits(), (-0.0f64).to_bits());

        assert_eq!(f("i64_min"), Kind::Integer(i64::MIN));
        assert_eq!(f("i64_max"), Kind::Integer(i64::MAX));
        // Anything above i64::MAX becomes a decimal string
        assert_eq!(f("i64_max_plus_one"), raw(b"9223372036854775808"));
        assert_eq!(f("u64_max"), raw(b"18446744073709551615"));
    }

    #[test]
    fn test_prepare_event_json_strings() {
        // JSON escapes are already resolved by serde, the raw UTF-8 is sent
        let event: serde_json::Value =
            serde_json::from_str(r#"{"s": "q\"b\\n\n\u0000\u00e9\ud83c\udf0d"}"#).unwrap();
        let log = decode_single_log(&prepare_event(event).encode_to_vec());

        let Some(Kind::Map(map)) = log.value.and_then(|x| x.kind) else {
            panic!("expected a map");
        };
        assert_eq!(map.fields["s"], wrap(raw("q\"b\\n\n\0é🌍".as_bytes())));
    }

    #[test]
    fn test_encode_event() {
        let event = serde_json::json!({
            "foo": "bar",
        });

        let mut buf = BytesMut::new();
        assert!(encode_event(event, &mut buf).is_ok());

        assert_eq!(
            &buf.freeze().to_vec(),
            &[
                10, 29, 10, 27, 10, 7, 10, 1, 46, 18, 2, 72, 0, 18, 16, 58, 14, 10, 12, 10, 3, 102,
                111, 111, 18, 5, 10, 3, 98, 97, 114
            ]
        );
    }

    #[test]
    fn test_encode_event_appends_to_buffer() {
        let ev1 = json!({"foo": "bar", "n": [1, 2.5, null]});
        let ev2 = json!({"baz": {"x": true}});
        let enc1 = prepare_event(ev1.clone()).encode_to_vec();
        let enc2 = prepare_event(ev2.clone()).encode_to_vec();

        // Existing content must be left intact
        let mut buf = BytesMut::from(&b"prefix"[..]);
        encode_event(ev1.clone(), &mut buf).unwrap();
        assert_eq!(&buf[..6], b"prefix");
        assert_eq!(&buf[6..], enc1);
        assert_eq!(buf.len() - 6, prepare_event(ev1.clone()).encoded_len());

        // A second event is appended right after the first one
        encode_event(ev2.clone(), &mut buf).unwrap();
        assert_eq!(&buf[6..6 + enc1.len()], enc1);
        assert_eq!(&buf[6 + enc1.len()..], enc2);

        // Each part decodes back to its own event
        assert_eq!(
            to_json(decode_single_log(&enc1).value.as_ref().unwrap()),
            ev1
        );
        assert_eq!(
            to_json(decode_single_log(&enc2).value.as_ref().unwrap()),
            ev2
        );

        // Buffer without spare capacity grows as needed
        let mut buf = BytesMut::with_capacity(0);
        encode_event(ev1, &mut buf).unwrap();
        assert_eq!(&buf[..], enc1);
    }

    #[test]
    fn test_encode_event_is_deterministic() {
        // Object key order in the input doesn't matter, the output is sorted by key
        let a: serde_json::Value =
            serde_json::from_str(r#"{"b": 1, "a": {"y": 2, "x": 3}}"#).unwrap();
        let b: serde_json::Value =
            serde_json::from_str(r#"{"a": {"x": 3, "y": 2}, "b": 1}"#).unwrap();

        let mut buf_a = BytesMut::new();
        let mut buf_b = BytesMut::new();
        encode_event(a.clone(), &mut buf_a).unwrap();
        encode_event(b, &mut buf_b).unwrap();
        assert_eq!(buf_a, buf_b);

        let mut buf_a2 = BytesMut::new();
        encode_event(a, &mut buf_a2).unwrap();
        assert_eq!(buf_a, buf_a2);
    }

    #[test]
    fn test_encode_event_deep_nesting() {
        // Alternate objects and arrays.
        // Encoding has no depth limit, but prost's default decoding recursion limit (100)
        // caps what a receiver can read back: each object level takes 3 messages
        // (Value, ValueMap, map entry) and each array level 2 (Value, ValueArray),
        // which allows at most 32 levels of objects only or 48 levels of arrays only.
        let mut event = json!("leaf");
        for i in 0..24 {
            event = if i % 2 == 0 {
                json!({ format!("k{i}"): event })
            } else {
                json!([i, event])
            };
        }

        assert_json_roundtrip(event);
    }

    #[test]
    fn test_encode_event_random_roundtrip() {
        let mut rng = Rng(0x5EED_1234_ABCD_9876);

        for _ in 0..2000 {
            // Vector events are always objects at the root
            let event = (0..rng.below(6))
                .map(|_| (rng.string(), rng.json(4)))
                .collect::<serde_json::Map<_, _>>()
                .into();
            assert_json_roundtrip(event);

            // But other roots must survive as well
            assert_json_roundtrip(rng.json(3));
        }
    }
}
