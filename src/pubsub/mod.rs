use std::{hash::Hash, marker::PhantomData, sync::Arc, time::Duration};

use ahash::RandomState;
use moka::sync::{Cache, CacheBuilder};
use prometheus::{
    IntCounter, IntGauge, Registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};
use tokio::sync::broadcast::{Receiver, Sender, error::RecvError};

/// Trait that a topic ID should implement
pub trait TopicId: Hash + Eq + Clone + Send + Sync + 'static {}
impl<T: Hash + Eq + Clone + Send + Sync + 'static> TopicId for T {}

/// Trait that a message should implement
pub trait Message: Clone + Send + Sync + 'static {}
impl<T: Clone + Send + Sync + 'static> Message for T {}

/// Broker options
#[derive(Clone, Debug)]
pub struct Opts {
    /// How many topics maximum we will support.
    /// Oldest topic will be evicted if this number is exceeded.
    pub max_topics: u64,
    /// If the topic doesn't get messages or subscribers for that long, then it will be deleted.
    pub idle_timeout: Duration,
    /// Maximum buffer size of the publishing queue (per-topic).
    /// When it's exceeded (due to slow consumers) - the slow consumers lose the oldest messages
    pub buffer_size: usize,
    /// Maximum number of subscribers (per-topic).
    /// No new subscribers can be created if this number is exceeded.
    pub max_subscribers: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            max_topics: 1_000_000,
            idle_timeout: Duration::from_secs(600),
            buffer_size: 10_000,
            max_subscribers: 10_000,
        }
    }
}

/// Result of a publish operation
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum PublishError {
    #[error("Topic does not exist")]
    TopicDoesNotExist,
    #[error("Topic has no subscribers")]
    NoSubscribers,
}

/// Result of a subscribe operation
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum SubscribeError {
    #[error("Too many subscribers")]
    TooManySubscribers,
}

/// Metrics for a Broker
#[derive(Debug, Clone)]
pub struct Metrics {
    topics: IntGauge,
    subscribers: IntGauge,
    msgs_sent: IntCounter,
    msgs_dropped: IntCounter,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            topics: register_int_gauge_with_registry!(
                format!("pubsub_topics"),
                format!("Number of topics currently active"),
                registry
            )
            .unwrap(),

            msgs_sent: register_int_counter_with_registry!(
                format!("pubsub_msgs_published"),
                format!("Number of messages published"),
                registry
            )
            .unwrap(),

            msgs_dropped: register_int_counter_with_registry!(
                format!("pubsub_msgs_dropped"),
                format!("Number of messages dropped"),
                registry
            )
            .unwrap(),

            subscribers: register_int_gauge_with_registry!(
                format!("pubsub_subscribers"),
                format!("Number of subscribers currently active"),
                registry
            )
            .unwrap(),
        }
    }
}

/// Subscriber to receive messages
#[derive(Debug)]
pub struct Subscriber<M: Message> {
    rx: Receiver<M>,
    metrics: Arc<Metrics>,
}

impl<M: Message> Subscriber<M> {
    /// Receive the next message from the topic
    pub async fn recv(&mut self) -> Result<M, RecvError> {
        self.rx.recv().await
    }
}

impl<M: Message> Drop for Subscriber<M> {
    fn drop(&mut self) {
        // Decrement subscriber count
        self.metrics.subscribers.dec();
    }
}

/// Topic to manage subscribers
#[derive(Debug, Clone)]
pub struct Topic<M: Message> {
    tx: Sender<M>,
    max_subscribers: usize,
    metrics: Arc<Metrics>,
}

impl<M: Message> Topic<M> {
    fn new(capacity: usize, metrics: Arc<Metrics>, max_subscribers: usize) -> Self {
        metrics.topics.inc();

        Self {
            tx: Sender::new(capacity),
            max_subscribers,
            metrics,
        }
    }

    /// Returns the number of subscribers on this topic
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Subscribes to this topic.
    /// Fails if there are already too many subscirbers.
    pub fn subscribe(&self) -> Result<Subscriber<M>, SubscribeError> {
        // Check if we're at the limit already
        if self.tx.receiver_count() >= self.max_subscribers {
            return Err(SubscribeError::TooManySubscribers);
        }

        self.metrics.subscribers.inc();
        Ok(Subscriber {
            rx: self.tx.subscribe(),
            metrics: self.metrics.clone(),
        })
    }

    /// Publishes the message to this topic
    pub fn publish(&self, message: M) -> Result<usize, PublishError> {
        self.tx.send(message).map_or_else(
            |_| {
                self.metrics.msgs_dropped.inc();
                Err(PublishError::NoSubscribers)
            },
            |v| {
                self.metrics.msgs_sent.inc();
                Ok(v)
            },
        )
    }
}

impl<M: Message> Drop for Topic<M> {
    fn drop(&mut self) {
        // Decrement topic count
        self.metrics.topics.dec();
    }
}

/// Broker that manages topics
#[derive(Debug, Clone)]
pub struct Broker<M: Message, T: TopicId> {
    opts: Opts,
    topics: Cache<T, Arc<Topic<M>>, RandomState>,
    metrics: Arc<Metrics>,
}

impl<M: Message, T: TopicId> Broker<M, T> {
    /// Create a new Broker
    pub fn new(opts: Opts, metrics: Metrics) -> Self {
        let metrics = Arc::new(metrics);

        let topics = CacheBuilder::new(opts.max_topics)
            .time_to_idle(opts.idle_timeout)
            .build_with_hasher(RandomState::new());

        Self {
            opts,
            topics,
            metrics,
        }
    }

    /// Fetches the given topic if it exists
    pub fn topic_get(&self, topic: &T) -> Option<Arc<Topic<M>>> {
        self.topics.get(topic)
    }

    /// Fetches or creates the given topic
    pub fn topic_get_or_create(&self, topic: &T) -> Arc<Topic<M>> {
        self.topics.get_with_by_ref(topic, || {
            Arc::new(Topic::new(
                self.opts.buffer_size,
                self.metrics.clone(),
                self.opts.max_subscribers,
            ))
        })
    }

    /// Tells if the given topic exists
    pub fn topic_exists(&self, topic: &T) -> bool {
        self.topics.contains_key(topic)
    }

    /// Removes the given topic.
    /// If there are subscribers - they will get a RecvError.
    pub fn topic_remove(&self, topic: &T) {
        self.topics.invalidate(topic);
        self.topics.run_pending_tasks();
    }

    /// Shorthand for topic_get_or_create().subscribe(topic)
    pub fn subscribe(&self, topic: &T) -> Result<Subscriber<M>, SubscribeError> {
        let topic = self.topic_get_or_create(topic);
        topic.subscribe()
    }

    /// Shorthand for topic_get().publish(message)
    pub fn publish(&self, topic: &T, message: M) -> Result<usize, PublishError> {
        // Check if the topic exists
        let Some(topic) = self.topic_get(topic) else {
            self.metrics.msgs_dropped.inc();
            return Err(PublishError::TopicDoesNotExist);
        };

        topic.publish(message)
    }
}

/// Builder to build a Broker
pub struct BrokerBuilder<M, T> {
    opts: Opts,
    metrics: Metrics,
    _m: PhantomData<M>,
    _t: PhantomData<T>,
}

impl<M: Message, T: TopicId> Default for BrokerBuilder<M, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: Message, T: TopicId> BrokerBuilder<M, T> {
    /// Create a new BrokerBuilder
    pub fn new() -> Self {
        Self {
            opts: Opts::default(),
            metrics: Metrics::new(&Registry::new()),
            _m: PhantomData,
            _t: PhantomData,
        }
    }

    /// Set the max number of topics supported. Default is 1 million.
    pub const fn with_max_topics(mut self, max_topics: u64) -> Self {
        self.opts.max_topics = max_topics;
        self
    }

    /// Set the idle timeout when an inactive topic is removed. Default it 10min.
    pub const fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.opts.idle_timeout = idle_timeout;
        self
    }

    /// Set per-topic buffer size. Default is 10k.
    pub const fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.opts.buffer_size = buffer_size;
        self
    }

    /// Set per-topic max subscriber limit. Default is 10k.
    pub const fn with_max_subscribers(mut self, max_subscribers: usize) -> Self {
        self.opts.max_subscribers = max_subscribers;
        self
    }

    /// Set Metrics to use
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Set Prometheus registry to use
    pub fn with_metric_registry(mut self, registry: &Registry) -> Self {
        self.metrics = Metrics::new(registry);
        self
    }

    /// Build the Broker
    pub fn build(self) -> Broker<M, T> {
        Broker::new(self.opts, self.metrics)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_pubsub() {
        let b: Broker<String, String> = BrokerBuilder::new()
            .with_buffer_size(3)
            .with_max_subscribers(1)
            .build();

        let topic1 = "foo".to_string();
        let topic2 = "dead".to_string();

        // No subscribers
        assert_eq!(
            b.publish(&topic1, "".into()),
            Err(PublishError::TopicDoesNotExist)
        );
        assert_eq!(
            b.publish(&topic2, "".into()),
            Err(PublishError::TopicDoesNotExist)
        );
        assert_eq!(b.metrics.topics.get(), 0);
        assert_eq!(b.metrics.msgs_dropped.get(), 2);

        // Subscribe
        let mut t1_sub = b.subscribe(&topic1).unwrap();
        let mut t2_sub = b.subscribe(&topic2).unwrap();
        assert!(b.topic_exists(&topic1));
        assert!(b.topic_exists(&topic2));
        assert_eq!(b.metrics.topics.get(), 2);

        // Make sure we hit the subscriber limit
        assert_eq!(
            b.subscribe(&topic1).unwrap_err(),
            SubscribeError::TooManySubscribers
        );
        assert_eq!(b.metrics.subscribers.get(), 2);

        // Publish up to a buffer size & receive
        assert_eq!(b.publish(&topic1, "bar1".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef1".into()), Ok(1));
        assert_eq!(b.publish(&topic1, "bar2".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef2".into()), Ok(1));
        assert_eq!(b.publish(&topic1, "bar3".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef3".into()), Ok(1));
        assert_eq!(b.metrics.msgs_sent.get(), 6);

        assert_eq!(t1_sub.recv().await.unwrap(), "bar1");
        assert_eq!(t2_sub.recv().await.unwrap(), "beef1");
        assert_eq!(t1_sub.recv().await.unwrap(), "bar2");
        assert_eq!(t2_sub.recv().await.unwrap(), "beef2");
        assert_eq!(t1_sub.recv().await.unwrap(), "bar3");
        assert_eq!(t2_sub.recv().await.unwrap(), "beef3");

        // Publish more than a buffer size.
        // The oldest message is lost.
        assert_eq!(b.publish(&topic1, "bar1".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef1".into()), Ok(1));
        assert_eq!(b.publish(&topic1, "bar2".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef2".into()), Ok(1));
        assert_eq!(b.publish(&topic1, "bar3".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef3".into()), Ok(1));
        assert_eq!(b.publish(&topic1, "bar4".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef4".into()), Ok(1));
        assert_eq!(b.publish(&topic1, "bar5".into()), Ok(1));
        assert_eq!(b.publish(&topic2, "beef5".into()), Ok(1));

        assert!(matches!(
            t1_sub.recv().await.unwrap_err(),
            RecvError::Lagged(_)
        ));
        assert!(matches!(
            t2_sub.recv().await.unwrap_err(),
            RecvError::Lagged(_)
        ));
        assert_eq!(t1_sub.recv().await.unwrap(), "bar2");
        assert_eq!(t2_sub.recv().await.unwrap(), "beef2");
        assert_eq!(t1_sub.recv().await.unwrap(), "bar3");
        assert_eq!(t2_sub.recv().await.unwrap(), "beef3");
        assert_eq!(t1_sub.recv().await.unwrap(), "bar4");
        assert_eq!(t2_sub.recv().await.unwrap(), "beef4");
        assert_eq!(t1_sub.recv().await.unwrap(), "bar5");
        assert_eq!(t2_sub.recv().await.unwrap(), "beef5");

        // Drop subscribers
        drop(t1_sub);
        drop(t2_sub);
        assert_eq!(b.metrics.subscribers.get(), 0);
        assert_eq!(b.metrics.topics.get(), 2);

        // No subscribers
        assert_eq!(
            b.publish(&topic1, "".into()).unwrap_err(),
            PublishError::NoSubscribers
        );
        assert_eq!(
            b.publish(&topic2, "".into()).unwrap_err(),
            PublishError::NoSubscribers
        );

        // Try to subscribe again using topic API
        let t1 = b.topic_get_or_create(&topic1);
        let t2 = b.topic_get_or_create(&topic2);
        let mut t1_sub = t1.subscribe().unwrap();
        let mut t2_sub = t2.subscribe().unwrap();

        // Publish & read
        assert_eq!(t1.publish("foo".into()).unwrap(), 1);
        assert_eq!(t2.publish("bar".into()).unwrap(), 1);
        assert_eq!(t1_sub.recv().await.unwrap(), "foo");
        assert_eq!(t2_sub.recv().await.unwrap(), "bar");

        // Remove topics
        b.topic_remove(&topic1);
        b.topic_remove(&topic2);
        drop(t1);
        drop(t2);
        assert_eq!(b.metrics.topics.get(), 0);

        // Subscribers should error out
        assert_eq!(t1_sub.recv().await.unwrap_err(), RecvError::Closed);
        assert_eq!(t2_sub.recv().await.unwrap_err(), RecvError::Closed);
    }
}
