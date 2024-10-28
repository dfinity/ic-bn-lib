pub mod cli;
pub mod ewma;
pub mod little;
pub mod sharded;
pub mod system;

use std::{fmt::Debug, future::Future, pin::Pin};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Reason for shedding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShedReason {
    CPU,
    Memory,
    LoadAvg,
    Latency,
}

/// Either an error from the wrapped service or message that the request was shed
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShedResponse<T> {
    /// A response from the inner service.
    Inner(T),
    /// The request was shed due to overload.
    Overload(ShedReason),
}
