use std::time::Duration;

use ahash::RandomState;
use moka::sync::Cache;
use prometheus::{
    IntCounterVec, IntGauge, Registry, register_int_counter_vec_with_registry,
    register_int_gauge_with_registry,
};
use rustls::server::StoresServerSessions;
use tokio::time::interval;
use zeroize::ZeroizeOnDrop;

type Key = Vec<u8>;

/// Sessions are considered highly sensitive data, so wipe the memory when
/// they're removed from storage. We can't do anything with the returned Vec<u8>,
/// but it's better than nothing.
#[derive(Debug, PartialEq, Eq, Hash, Clone, ZeroizeOnDrop)]
struct Val(Vec<u8>);

fn weigher(k: &Key, v: &Val) -> u32 {
    (k.len() + v.0.len()) as u32
}

/// Stores TLS sessions for TLSv1.2 only.
/// `SipHash` is replaced with ~10x faster aHash.
/// see <https://github.com/tkaitchuck/aHash/blob/master/compare/readme.md>
#[derive(Debug)]
pub struct Storage {
    cache: Cache<Key, Val, RandomState>,
    metrics: Metrics,
}

impl Storage {
    pub fn new(capacity: u64, tti: Duration, registry: &Registry) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_idle(tti)
            .weigher(weigher)
            .build_with_hasher(RandomState::default());

        let metrics = Metrics::new(registry);
        Self { cache, metrics }
    }

    pub async fn metrics_runner(&self) {
        let mut interval = interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            self.metrics.size.set(self.cache.weighted_size() as i64);
            self.metrics.count.set(self.cache.entry_count() as i64);
        }
    }
}

impl StoresServerSessions for Storage {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let v = self.cache.get(key).map(|x| x.0.clone());
        self.metrics.record("get", v.is_some());
        v
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.insert(key, Val(value));
        self.metrics.record("put", true);
        true
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let v = self.cache.remove(key).map(|x| x.0.clone());
        self.metrics.record("take", v.is_some());
        v
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct Metrics {
    count: IntGauge,
    size: IntGauge,
    processed: IntCounterVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            count: register_int_gauge_with_registry!(
                format!("tls_session_cache_count"),
                format!("Number of TLS sessions in the cache"),
                registry
            )
            .unwrap(),

            size: register_int_gauge_with_registry!(
                format!("tls_session_cache_size"),
                format!("Size of TLS sessions in the cache"),
                registry
            )
            .unwrap(),

            processed: register_int_counter_vec_with_registry!(
                format!("tls_sessions"),
                format!("Number of TLS sessions that were processed"),
                &["action", "found"],
                registry
            )
            .unwrap(),
        }
    }

    fn record(&self, action: &str, ok: bool) {
        self.processed
            .with_label_values(&[action, if ok { "yes" } else { "no" }])
            .inc();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_storage() {
        let c = Storage::new(10000, Duration::from_secs(3600), &Registry::new());

        let key1 = "a".repeat(2500).as_bytes().to_vec();
        let key2 = "b".repeat(2500).as_bytes().to_vec();
        let key3 = "b".as_bytes().to_vec();

        // Check that two entries fit
        c.put(key1.clone(), key1.clone());
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 1);
        assert_eq!(c.cache.weighted_size(), 5000);
        c.put(key2.clone(), key2.clone());
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 2);
        assert_eq!(c.cache.weighted_size(), 10000);

        // Check that 3rd entry won't fit
        c.put(key3.clone(), key3.clone());
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 2);
        assert_eq!(c.cache.weighted_size(), 10000);
        assert!(c.get(&key3).is_none());

        // Check that keys are taken and not left
        assert!(c.take(&key1).is_some());
        assert!(c.get(&key1).is_none());
        assert!(c.take(&key2).is_some());
        assert!(c.get(&key2).is_none());

        // Check that nothing left
        c.cache.run_pending_tasks();
        assert_eq!(c.cache.entry_count(), 0);
        assert_eq!(c.cache.weighted_size(), 0);
    }
}
