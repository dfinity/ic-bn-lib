#![warn(clippy::nursery)]

pub mod http;
pub mod tasks;
pub mod tls;
pub mod types;
pub mod vector;

/// Generic error
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}

pub fn parse_size(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::Config::new().with_binary().parse_size(s)
}

pub fn parse_size_usize(s: &str) -> Result<usize, parse_size::Error> {
    parse_size(s).map(|x| x as usize)
}
