// This file is @generated by prost-build.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventArray {
    #[prost(oneof = "event_array::Events", tags = "1, 2, 3")]
    pub events: ::core::option::Option<event_array::Events>,
}
/// Nested message and enum types in `EventArray`.
pub mod event_array {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Events {
        #[prost(message, tag = "1")]
        Logs(super::LogArray),
        #[prost(message, tag = "2")]
        Metrics(super::MetricArray),
        #[prost(message, tag = "3")]
        Traces(super::TraceArray),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LogArray {
    #[prost(message, repeated, tag = "1")]
    pub logs: ::prost::alloc::vec::Vec<Log>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetricArray {
    #[prost(message, repeated, tag = "1")]
    pub metrics: ::prost::alloc::vec::Vec<Metric>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TraceArray {
    #[prost(message, repeated, tag = "1")]
    pub traces: ::prost::alloc::vec::Vec<Trace>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventWrapper {
    #[prost(oneof = "event_wrapper::Event", tags = "1, 2, 3")]
    pub event: ::core::option::Option<event_wrapper::Event>,
}
/// Nested message and enum types in `EventWrapper`.
pub mod event_wrapper {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Event {
        #[prost(message, tag = "1")]
        Log(super::Log),
        #[prost(message, tag = "2")]
        Metric(super::Metric),
        #[prost(message, tag = "3")]
        Trace(super::Trace),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Log {
    /// Deprecated, use value instead
    #[prost(btree_map = "string, message", tag = "1")]
    pub fields: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, Value>,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<Value>,
    #[deprecated]
    #[prost(message, optional, tag = "3")]
    pub metadata: ::core::option::Option<Value>,
    #[prost(message, optional, tag = "4")]
    pub metadata_full: ::core::option::Option<Metadata>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Trace {
    #[prost(btree_map = "string, message", tag = "1")]
    pub fields: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, Value>,
    #[deprecated]
    #[prost(message, optional, tag = "2")]
    pub metadata: ::core::option::Option<Value>,
    #[prost(message, optional, tag = "3")]
    pub metadata_full: ::core::option::Option<Metadata>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValueMap {
    #[prost(btree_map = "string, message", tag = "1")]
    pub fields: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, Value>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValueArray {
    #[prost(message, repeated, tag = "1")]
    pub items: ::prost::alloc::vec::Vec<Value>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Value {
    #[prost(oneof = "value::Kind", tags = "1, 2, 4, 5, 6, 7, 8, 9")]
    pub kind: ::core::option::Option<value::Kind>,
}
/// Nested message and enum types in `Value`.
pub mod value {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(bytes, tag = "1")]
        RawBytes(::prost::bytes::Bytes),
        #[prost(message, tag = "2")]
        Timestamp(::prost_types::Timestamp),
        #[prost(int64, tag = "4")]
        Integer(i64),
        #[prost(double, tag = "5")]
        Float(f64),
        #[prost(bool, tag = "6")]
        Boolean(bool),
        #[prost(message, tag = "7")]
        Map(super::ValueMap),
        #[prost(message, tag = "8")]
        Array(super::ValueArray),
        #[prost(enumeration = "super::ValueNull", tag = "9")]
        Null(i32),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DatadogOriginMetadata {
    #[prost(uint32, optional, tag = "1")]
    pub origin_product: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub origin_category: ::core::option::Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub origin_service: ::core::option::Option<u32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Secrets {
    #[prost(btree_map = "string, string", tag = "1")]
    pub entries: ::prost::alloc::collections::BTreeMap<
        ::prost::alloc::string::String,
        ::prost::alloc::string::String,
    >,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputId {
    #[prost(string, tag = "1")]
    pub component: ::prost::alloc::string::String,
    #[prost(string, optional, tag = "2")]
    pub port: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Metadata {
    #[prost(message, optional, tag = "1")]
    pub value: ::core::option::Option<Value>,
    #[prost(message, optional, tag = "2")]
    pub datadog_origin_metadata: ::core::option::Option<DatadogOriginMetadata>,
    #[prost(string, optional, tag = "3")]
    pub source_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "4")]
    pub source_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "5")]
    pub upstream_id: ::core::option::Option<OutputId>,
    #[prost(message, optional, tag = "6")]
    pub secrets: ::core::option::Option<Secrets>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Metric {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub timestamp: ::core::option::Option<::prost_types::Timestamp>,
    #[prost(btree_map = "string, string", tag = "3")]
    pub tags_v1: ::prost::alloc::collections::BTreeMap<
        ::prost::alloc::string::String,
        ::prost::alloc::string::String,
    >,
    #[prost(btree_map = "string, message", tag = "20")]
    pub tags_v2: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, TagValues>,
    #[prost(enumeration = "metric::Kind", tag = "4")]
    pub kind: i32,
    #[prost(string, tag = "11")]
    pub namespace: ::prost::alloc::string::String,
    #[prost(uint32, tag = "18")]
    pub interval_ms: u32,
    #[deprecated]
    #[prost(message, optional, tag = "19")]
    pub metadata: ::core::option::Option<Value>,
    #[prost(message, optional, tag = "21")]
    pub metadata_full: ::core::option::Option<Metadata>,
    #[prost(
        oneof = "metric::Value",
        tags = "5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17"
    )]
    pub value: ::core::option::Option<metric::Value>,
}
/// Nested message and enum types in `Metric`.
pub mod metric {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Kind {
        Incremental = 0,
        Absolute = 1,
    }
    impl Kind {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Kind::Incremental => "Incremental",
                Kind::Absolute => "Absolute",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "Incremental" => Some(Self::Incremental),
                "Absolute" => Some(Self::Absolute),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "5")]
        Counter(super::Counter),
        #[prost(message, tag = "6")]
        Gauge(super::Gauge),
        #[prost(message, tag = "7")]
        Set(super::Set),
        #[prost(message, tag = "8")]
        Distribution1(super::Distribution1),
        #[prost(message, tag = "9")]
        AggregatedHistogram1(super::AggregatedHistogram1),
        #[prost(message, tag = "10")]
        AggregatedSummary1(super::AggregatedSummary1),
        #[prost(message, tag = "12")]
        Distribution2(super::Distribution2),
        #[prost(message, tag = "13")]
        AggregatedHistogram2(super::AggregatedHistogram2),
        #[prost(message, tag = "14")]
        AggregatedSummary2(super::AggregatedSummary2),
        #[prost(message, tag = "15")]
        Sketch(super::Sketch),
        #[prost(message, tag = "16")]
        AggregatedHistogram3(super::AggregatedHistogram3),
        #[prost(message, tag = "17")]
        AggregatedSummary3(super::AggregatedSummary3),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagValues {
    #[prost(message, repeated, tag = "1")]
    pub values: ::prost::alloc::vec::Vec<TagValue>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TagValue {
    #[prost(string, optional, tag = "1")]
    pub value: ::core::option::Option<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Counter {
    #[prost(double, tag = "1")]
    pub value: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gauge {
    #[prost(double, tag = "1")]
    pub value: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Set {
    #[prost(string, repeated, tag = "1")]
    pub values: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Distribution1 {
    #[prost(double, repeated, tag = "1")]
    pub values: ::prost::alloc::vec::Vec<f64>,
    #[prost(uint32, repeated, tag = "2")]
    pub sample_rates: ::prost::alloc::vec::Vec<u32>,
    #[prost(enumeration = "StatisticKind", tag = "3")]
    pub statistic: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Distribution2 {
    #[prost(message, repeated, tag = "1")]
    pub samples: ::prost::alloc::vec::Vec<DistributionSample>,
    #[prost(enumeration = "StatisticKind", tag = "2")]
    pub statistic: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DistributionSample {
    #[prost(double, tag = "1")]
    pub value: f64,
    #[prost(uint32, tag = "2")]
    pub rate: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatedHistogram1 {
    #[prost(double, repeated, tag = "1")]
    pub buckets: ::prost::alloc::vec::Vec<f64>,
    #[prost(uint32, repeated, tag = "2")]
    pub counts: ::prost::alloc::vec::Vec<u32>,
    #[prost(uint32, tag = "3")]
    pub count: u32,
    #[prost(double, tag = "4")]
    pub sum: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatedHistogram2 {
    #[prost(message, repeated, tag = "1")]
    pub buckets: ::prost::alloc::vec::Vec<HistogramBucket>,
    #[prost(uint32, tag = "2")]
    pub count: u32,
    #[prost(double, tag = "3")]
    pub sum: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatedHistogram3 {
    #[prost(message, repeated, tag = "1")]
    pub buckets: ::prost::alloc::vec::Vec<HistogramBucket3>,
    #[prost(uint64, tag = "2")]
    pub count: u64,
    #[prost(double, tag = "3")]
    pub sum: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HistogramBucket {
    #[prost(double, tag = "1")]
    pub upper_limit: f64,
    #[prost(uint32, tag = "2")]
    pub count: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HistogramBucket3 {
    #[prost(double, tag = "1")]
    pub upper_limit: f64,
    #[prost(uint64, tag = "2")]
    pub count: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatedSummary1 {
    #[prost(double, repeated, tag = "1")]
    pub quantiles: ::prost::alloc::vec::Vec<f64>,
    #[prost(double, repeated, tag = "2")]
    pub values: ::prost::alloc::vec::Vec<f64>,
    #[prost(uint32, tag = "3")]
    pub count: u32,
    #[prost(double, tag = "4")]
    pub sum: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatedSummary2 {
    #[prost(message, repeated, tag = "1")]
    pub quantiles: ::prost::alloc::vec::Vec<SummaryQuantile>,
    #[prost(uint32, tag = "2")]
    pub count: u32,
    #[prost(double, tag = "3")]
    pub sum: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatedSummary3 {
    #[prost(message, repeated, tag = "1")]
    pub quantiles: ::prost::alloc::vec::Vec<SummaryQuantile>,
    #[prost(uint64, tag = "2")]
    pub count: u64,
    #[prost(double, tag = "3")]
    pub sum: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SummaryQuantile {
    #[prost(double, tag = "1")]
    pub quantile: f64,
    #[prost(double, tag = "2")]
    pub value: f64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Sketch {
    #[prost(oneof = "sketch::Sketch", tags = "1")]
    pub sketch: ::core::option::Option<sketch::Sketch>,
}
/// Nested message and enum types in `Sketch`.
pub mod sketch {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AgentDdSketch {
        /// Summary statistics for the samples in this sketch.
        #[prost(uint32, tag = "1")]
        pub count: u32,
        #[prost(double, tag = "2")]
        pub min: f64,
        #[prost(double, tag = "3")]
        pub max: f64,
        #[prost(double, tag = "4")]
        pub sum: f64,
        #[prost(double, tag = "5")]
        pub avg: f64,
        /// The bins (buckets) of this sketch, where `k` and `n` are unzipped pairs.
        /// `k` is the list of bin indexes that are populated, and `n` is the count of samples
        /// within the given bin.
        #[prost(sint32, repeated, tag = "6")]
        pub k: ::prost::alloc::vec::Vec<i32>,
        #[prost(uint32, repeated, tag = "7")]
        pub n: ::prost::alloc::vec::Vec<u32>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Sketch {
        #[prost(message, tag = "1")]
        AgentDdSketch(AgentDdSketch),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ValueNull {
    NullValue = 0,
}
impl ValueNull {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ValueNull::NullValue => "NULL_VALUE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NULL_VALUE" => Some(Self::NullValue),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum StatisticKind {
    Histogram = 0,
    Summary = 1,
}
impl StatisticKind {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            StatisticKind::Histogram => "Histogram",
            StatisticKind::Summary => "Summary",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "Histogram" => Some(Self::Histogram),
            "Summary" => Some(Self::Summary),
            _ => None,
        }
    }
}
