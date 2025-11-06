pub mod ewma;
pub mod little;
pub mod sharded;
pub mod system;

use std::{future::Future, pin::Pin};

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
