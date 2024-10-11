#![warn(clippy::nursery)]

pub mod http;
pub mod tasks;
pub mod tls;
pub mod vector;

/// Generic error
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Generic(#[from] anyhow::Error),
}
