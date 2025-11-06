use std::collections::BTreeMap;

use anyhow::Context;
use bytes::BytesMut;
use prost::Message;
use vrl::value::{ObjectMap, Value};

pub mod client;
#[allow(warnings, clippy::all, clippy::pedantic)]
mod event;

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
    use super::*;

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
}
