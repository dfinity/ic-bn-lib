use std::hash::Hash;

/// Trait that a topic ID should implement
pub trait TopicId: Hash + Eq + Clone + Send + Sync + 'static {}
impl<T: Hash + Eq + Clone + Send + Sync + 'static> TopicId for T {}

/// Trait that a message should implement
pub trait Message: Clone + Send + Sync + 'static {}
impl<T: Clone + Send + Sync + 'static> Message for T {}
