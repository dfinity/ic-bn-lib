use std::{
    fmt::{self, Debug},
    hash::Hash,
};

use async_trait::async_trait;
use http::Request;

use crate::types::http::{CacheError, Error};

/// Generic HTTP client trait that is using Reqwest types
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Client: Send + Sync + fmt::Debug {
    async fn execute(&self, req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error>;
}

/// Generic HTTP client trait that is using HTTP types
#[async_trait]
pub trait ClientHttp<B1, B2 = axum::body::Body>: Send + Sync + fmt::Debug {
    async fn execute(&self, req: http::Request<B1>) -> Result<http::Response<B2>, Error>;
}

/// Trait to extract the caching key from the given HTTP request
pub trait KeyExtractor: Clone + Send + Sync + Debug + 'static {
    /// The type of the key.
    type Key: Clone + Send + Sync + Debug + Hash + Eq + 'static;

    /// Extraction method, will return [`Error`] response when the extraction failed
    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, CacheError>;
}

pub trait CustomBypassReason:
    Debug + Clone + std::fmt::Display + Into<&'static str> + PartialEq + Eq + Send + Sync + 'static
{
}

/// Trait to decide if we need to bypass caching of the given request
pub trait Bypasser: Clone + Send + Sync + Debug + 'static {
    /// Custom bypass reason
    type BypassReason: CustomBypassReason;

    /// Checks if we should bypass the given request
    fn bypass<T>(&self, req: &Request<T>) -> Result<Option<Self::BypassReason>, CacheError>;
}
