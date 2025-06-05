use std::{
    hash::Hash,
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use ahash::RandomState;
use moka::sync::{Cache, CacheBuilder};
use prometheus::{
    IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};
use strum::{Display, EnumString, IntoStaticStr};
use tokio::sync::broadcast::{
    Receiver, Sender,
    error::{RecvError, SendError},
};

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
    /// When it's exceeded (due to slow consumers) - the slow consumers lose  the oldest messages
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

/// Subscriber to receive messages
pub struct Subscriber<M: Message> {
    rx: Receiver<M>,
    metric: IntGauge,
    counter: Arc<AtomicUsize>,
}

impl<M: Message> Subscriber<M> {
    pub async fn recv(&mut self) -> Result<M, RecvError> {
        self.rx.recv().await
    }
}

impl<M: Message> Drop for Subscriber<M> {
    fn drop(&mut self) {
        // Decrement subscriber count
        self.metric.dec();
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Topic to manage subscribers
#[derive(Clone)]
struct Topic<M: Message> {
    tx: Sender<M>,
    subscribers: Arc<AtomicUsize>,
}

impl<M: Message> Topic<M> {
    fn new(capacity: usize) -> Self {
        Self {
            tx: Sender::new(capacity),
            subscribers: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn subscribe(&self, metric: IntGauge) -> Subscriber<M> {
        self.subscribers.fetch_add(1, Ordering::SeqCst);

        Subscriber {
            rx: self.tx.subscribe(),
            metric,
            counter: self.subscribers.clone(),
        }
    }

    fn publish(&self, msg: M) -> Result<usize, SendError<M>> {
        self.tx.send(msg)
    }
}

#[derive(Debug, Clone)]
pub struct Metrics {
    topics: IntGauge,
    msgs_sent: IntCounterVec,
    subscribers: IntGauge,
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

            msgs_sent: register_int_counter_vec_with_registry!(
                format!("pubsub_msgs_published"),
                format!("Number of messages published"),
                &["dropped"],
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

#[derive(Debug, Clone, Display, IntoStaticStr, EnumString, Eq, PartialEq)]
#[strum(serialize_all = "snake_case")]
pub enum PublishResult {
    TopicDoesNotExist,
    NoSubscribers,
    Success(usize),
}

pub struct Broker<M: Message, T: TopicId> {
    opts: Opts,
    topics: Cache<T, Arc<Topic<M>>, RandomState>,
    metrics: Metrics,
}

impl<M: Message, T: TopicId> Broker<M, T> {
    /// Create a new Broker
    pub fn new(opts: Opts, metrics: Metrics) -> Self {
        let metrics_clone = metrics.clone();

        let topics = CacheBuilder::new(opts.max_topics)
            .eviction_listener(move |_k, _v, _r| {
                metrics_clone.topics.dec();
            })
            .time_to_idle(opts.idle_timeout)
            .build_with_hasher(RandomState::new());

        Self {
            opts,
            topics,
            metrics,
        }
    }

    /// Tells if the given topic exists
    pub fn topic_exists(&self, topic: &T) -> bool {
        self.topics.contains_key(topic)
    }

    /// Subscribe to a given topic, returning a Subscriber that can be used to consume messages.
    /// If the limit of subscribers is reached - it returns None.
    pub fn subscribe(&self, topic: &T) -> Option<Subscriber<M>> {
        // Fetch or create a new topic
        let topic = self.topics.get_with_by_ref(topic, || {
            self.metrics.topics.inc();
            Arc::new(Topic::new(self.opts.buffer_size))
        });

        // Check if we're at the limit already
        if topic.subscribers.load(Ordering::SeqCst) >= self.opts.max_subscribers {
            return None;
        }

        self.metrics.subscribers.inc();
        Some(topic.subscribe(self.metrics.subscribers.clone()))
    }

    /// Tries to send the message to the given topic.
    /// If the topic does not exist, TopicDoesNotExist is returned.
    /// If it exists, but there are no active subscribers - it will return NoSubscribers.
    pub fn publish(&self, topic: &T, message: M) -> PublishResult {
        // Check if the topic exists
        let Some(topic) = self.topics.get(topic) else {
            self.metrics.msgs_sent.with_label_values(&["yes"]).inc();
            return PublishResult::TopicDoesNotExist;
        };

        topic.publish(message).map_or_else(
            |_| {
                self.metrics.msgs_sent.with_label_values(&["yes"]).inc();
                PublishResult::NoSubscribers
            },
            |v| {
                self.metrics.msgs_sent.with_label_values(&["no"]).inc();
                PublishResult::Success(v)
            },
        )
    }
}

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
            PublishResult::TopicDoesNotExist
        );
        assert_eq!(
            b.publish(&topic2, "".into()),
            PublishResult::TopicDoesNotExist
        );
        assert_eq!(b.metrics.topics.get(), 0);
        assert_eq!(b.metrics.msgs_sent.with_label_values(&["yes"]).get(), 2);

        // Subscribe
        let mut foo_sub = b.subscribe(&topic1).unwrap();
        let mut dead_sub = b.subscribe(&topic2).unwrap();
        assert!(b.topic_exists(&topic1));
        assert!(b.topic_exists(&topic2));
        assert_eq!(b.metrics.topics.get(), 2);

        // Make sure we hit the subscriber limit
        assert!(b.subscribe(&topic1).is_none());
        assert_eq!(b.metrics.subscribers.get(), 2);

        // Publish up to a buffer size & receive
        assert_eq!(b.publish(&topic1, "bar1".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef1".into()),
            PublishResult::Success(1)
        );
        assert_eq!(b.publish(&topic1, "bar2".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef2".into()),
            PublishResult::Success(1)
        );
        assert_eq!(b.publish(&topic1, "bar3".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef3".into()),
            PublishResult::Success(1)
        );
        assert_eq!(b.metrics.msgs_sent.with_label_values(&["no"]).get(), 6);

        assert_eq!(foo_sub.recv().await.unwrap(), "bar1");
        assert_eq!(dead_sub.recv().await.unwrap(), "beef1");
        assert_eq!(foo_sub.recv().await.unwrap(), "bar2");
        assert_eq!(dead_sub.recv().await.unwrap(), "beef2");
        assert_eq!(foo_sub.recv().await.unwrap(), "bar3");
        assert_eq!(dead_sub.recv().await.unwrap(), "beef3");

        // Publish more than a buffer size.
        // The oldest message is lost.
        assert_eq!(b.publish(&topic1, "bar1".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef1".into()),
            PublishResult::Success(1)
        );
        assert_eq!(b.publish(&topic1, "bar2".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef2".into()),
            PublishResult::Success(1)
        );
        assert_eq!(b.publish(&topic1, "bar3".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef3".into()),
            PublishResult::Success(1)
        );
        assert_eq!(b.publish(&topic1, "bar4".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef4".into()),
            PublishResult::Success(1)
        );
        assert_eq!(b.publish(&topic1, "bar5".into()), PublishResult::Success(1));
        assert_eq!(
            b.publish(&topic2, "beef5".into()),
            PublishResult::Success(1)
        );

        assert!(matches!(
            foo_sub.recv().await.unwrap_err(),
            RecvError::Lagged(_)
        ));
        assert!(matches!(
            dead_sub.recv().await.unwrap_err(),
            RecvError::Lagged(_)
        ));
        assert_eq!(foo_sub.recv().await.unwrap(), "bar2");
        assert_eq!(dead_sub.recv().await.unwrap(), "beef2");
        assert_eq!(foo_sub.recv().await.unwrap(), "bar3");
        assert_eq!(dead_sub.recv().await.unwrap(), "beef3");
        assert_eq!(foo_sub.recv().await.unwrap(), "bar4");
        assert_eq!(dead_sub.recv().await.unwrap(), "beef4");
        assert_eq!(foo_sub.recv().await.unwrap(), "bar5");
        assert_eq!(dead_sub.recv().await.unwrap(), "beef5");

        // Drop subscribers
        drop(foo_sub);
        drop(dead_sub);
        assert_eq!(b.metrics.subscribers.get(), 0);

        // No subscribers
        assert_eq!(b.publish(&topic1, "".into()), PublishResult::NoSubscribers);
        assert_eq!(b.publish(&topic2, "".into()), PublishResult::NoSubscribers);

        // We can subscribe again
        assert!(b.subscribe(&topic1).is_some());
        assert!(b.subscribe(&topic2).is_some());
    }
}
