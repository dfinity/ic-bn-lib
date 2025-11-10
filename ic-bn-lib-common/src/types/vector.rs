use std::time::Duration;

use clap::Args;
use humantime::parse_duration;
use url::Url;

use crate::parse_size_decimal_usize;

#[derive(Args, Clone)]
pub struct VectorCli {
    /// Setting this enables logging of HTTP requests to Vector using native protocol
    #[clap(env, long)]
    pub log_vector_url: Option<Url>,

    /// Vector username
    #[clap(env, long)]
    pub log_vector_user: Option<String>,

    /// Vector password
    #[clap(env, long)]
    pub log_vector_pass: Option<String>,

    /// Vector batch size in number of events.
    /// When it's exceeded then the batch is closed & queued for sending.
    #[clap(env, long, default_value = "100k", value_parser = parse_size_decimal_usize)]
    pub log_vector_batch: usize,

    /// Number of batches to store in the queue for the Flushers to consume.
    #[clap(env, long, default_value = "64")]
    pub log_vector_batch_queue: usize,

    /// Vector batch flush interval
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub log_vector_interval: Duration,

    /// Vector buffer size (in number of events) to account for ingest problems.
    /// If the buffer is full then new events will be dropped.
    #[clap(env, long, default_value = "500k", value_parser = parse_size_decimal_usize)]
    pub log_vector_buffer: usize,

    /// Number of batch flusher tasks to spawn.
    /// If there's a big event volume - increasing this number might help.
    /// Each task is flushing a single batch which contains time-ordered events.
    #[clap(env, long, default_value = "32")]
    pub log_vector_flushers: usize,

    /// Vector HTTP request timeout for a batch flush.
    /// With each retry it will be linearly increased until it reaches 10x.
    /// E.g. for 30s the timeouts will be 30s/1m/1m30s/.../5m
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub log_vector_timeout: Duration,

    /// Vector HTTP request retry interval
    /// With each retry it will be linearly increased until it reaches 5x.
    /// E.g. for 2s the retry intervals will be 2s/4s/6s/8s/10s/10s/10s...
    #[clap(env, long, default_value = "2s", value_parser = parse_duration)]
    pub log_vector_retry_interval: Duration,

    /// Retry count when flushing a batch.
    /// It is taken into account only when shutting down.
    #[clap(env, long, default_value = "5")]
    pub log_vector_retry_count: usize,

    /// ZSTD compression level to use when sending data
    #[clap(env, long, default_value = "3")]
    pub log_vector_zstd_level: usize,
}
