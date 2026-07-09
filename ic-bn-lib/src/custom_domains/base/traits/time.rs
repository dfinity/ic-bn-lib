/// Timestamp representing seconds in UTC since the UNIX epoch (January 1, 1970).
pub type UtcTimestamp = u64;

/// Trait for getting the current timestamp in UTC seconds since UNIX epoch.
///
/// This abstraction allows for both real system time and mock time in tests.
pub trait UtcTimestampProvider: Send + Sync + std::fmt::Debug {
    /// Returns the current UTC timestamp as seconds since UNIX epoch.
    fn unix_timestamp(&self) -> UtcTimestamp;
}
