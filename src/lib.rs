#![warn(clippy::nursery)]
#![warn(tail_expr_drop_order)]

pub mod http;
pub mod tasks;
pub mod tls;
pub mod types;
#[cfg(feature = "vector")]
pub mod vector;

/// Generic error
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

/// Parses size string as a binary (1k = 1024 etc) in u64
pub fn parse_size(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().with_binary().parse_size(s)
}

/// Parses size string as a binary (1k = 1024 etc) in usize
pub fn parse_size_usize(s: &str) -> Result<usize, parse_size::Error> {
    parse_size(s).map(|x| x as usize)
}

/// Parses size string as a decimal (1k = 1000 etc) in u64
pub fn parse_size_decimal(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().parse_size(s)
}

/// Parses size string as a decimal (1k = 1000 etc) in usize
pub fn parse_size_decimal_usize(s: &str) -> Result<usize, parse_size::Error> {
    parse_size(s).map(|x| x as usize)
}
