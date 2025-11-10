use std::fmt::Debug;

use async_trait::async_trait;

use crate::Error;

#[async_trait]
pub trait GetsSystemInfo: Send + Sync + Clone + 'static {
    async fn cpu_usage(&self) -> Result<f64, Error>;
    fn memory_usage(&self) -> Result<f64, Error>;
    fn load_avg(&self) -> Result<(f64, f64, f64), Error>;
}

/// Trait to extract the shedding key from the given request
pub trait TypeExtractor: Clone + Debug + Send + Sync + 'static {
    /// The type of the request.
    type Type: Clone + Debug + Send + Sync + Ord + 'static;
    type Request: Send;

    /// Extraction method, should return None response when the extraction failed
    fn extract(&self, req: &Self::Request) -> Option<Self::Type>;
}
