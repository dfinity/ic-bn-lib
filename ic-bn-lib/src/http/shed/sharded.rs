use std::{
    collections::BTreeMap,
    fmt::Debug,
    sync::Arc,
    task::{Context, Poll},
};

use tower::{Layer, Service, ServiceExt};

use super::{
    BoxFuture,
    little::{LoadShedLayer, LoadShedResponse},
};
use crate::http::shed::{ShardedOptions, ShedReason, ShedResponse, TypeExtractor};

/// Sharded version of `LoadShedLayer`
#[derive(Debug, Clone)]
pub struct ShardedLittleLoadShedder<T: TypeExtractor, I> {
    extractor: T,
    inner: I,
    shards: Arc<BTreeMap<T::Type, LoadShedLayer>>,
}

impl<T: TypeExtractor, I: Send + Sync + Clone> ShardedLittleLoadShedder<T, I> {
    /// Create new `ShardedLittleLoadShedder`
    pub const fn new(
        inner: I,
        extractor: T,
        shards: Arc<BTreeMap<T::Type, LoadShedLayer>>,
    ) -> Self {
        Self {
            extractor,
            inner,
            shards,
        }
    }

    // Tries to find a shard corresponding to the given request
    fn get_shard(&self, req: &T::Request) -> Option<LoadShedLayer> {
        let req_type = self.extractor.extract(req)?;
        self.shards.get(&req_type).cloned()
    }
}

// Implement tower service
impl<T: TypeExtractor, I> Service<T::Request> for ShardedLittleLoadShedder<T, I>
where
    I: Service<T::Request> + Clone + Send + Sync + 'static,
    I::Future: Send,
{
    type Response = ShedResponse<I::Response>;
    type Error = I::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: T::Request) -> Self::Future {
        // Try to find if we have a shard
        let Some(shard) = self.get_shard(&req) else {
            // If we don't - just pass the request to the inner service
            let inner = self.inner.clone();
            return Box::pin(async move { Ok(ShedResponse::Inner(inner.oneshot(req).await?)) });
        };

        // Construct the service using a layer shard.
        // This should be very lightweight.
        let svc = shard.layer(self.inner.clone());

        // Execute the request
        Box::pin(async move {
            // Map response to our
            svc.oneshot(req).await.map(|x| match x {
                LoadShedResponse::Overload => ShedResponse::Overload(ShedReason::Latency),
                LoadShedResponse::Inner(i) => ShedResponse::Inner(i),
            })
        })
    }
}

/// Tower Layer for `ShardedLittleLoadShedder`
#[derive(Debug, Clone)]
pub struct ShardedLittleLoadShedderLayer<T: TypeExtractor>(
    ShardedOptions<T>,
    Arc<BTreeMap<T::Type, LoadShedLayer>>,
);

impl<T: TypeExtractor> ShardedLittleLoadShedderLayer<T> {
    /// Create new `ShardedLittleLoadShedderLayer`
    pub fn new(opts: ShardedOptions<T>) -> Self {
        // Generate the shedding shards, one per provided request type
        let shards = Arc::new(BTreeMap::from_iter(opts.latencies.iter().map(|x| {
            (
                x.0.clone(),
                LoadShedLayer::new(opts.ewma_alpha, x.1, opts.passthrough_count),
            )
        })));

        Self(opts, shards)
    }
}

impl<T: TypeExtractor, I: Send + Sync + Clone> Layer<I> for ShardedLittleLoadShedderLayer<T> {
    type Service = ShardedLittleLoadShedder<T, I>;

    fn layer(&self, inner: I) -> Self::Service {
        ShardedLittleLoadShedder::new(inner, self.0.extractor.clone(), self.1.clone())
    }
}

#[cfg(test)]
mod test {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use tokio_util::task::TaskTracker;

    use super::*;
    use crate::{Error, http::shed::TypeLatency};

    #[derive(Debug, Clone)]
    struct StubService;

    impl Service<Duration> for StubService {
        type Response = ();
        type Error = Error;
        type Future = BoxFuture<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Duration) -> Self::Future {
            let fut = async move {
                tokio::time::sleep(req).await;
                Ok(())
            };

            Box::pin(fut)
        }
    }

    #[derive(Debug, Clone)]
    struct StubExtractor(u8);

    impl TypeExtractor for StubExtractor {
        type Type = u8;
        type Request = Duration;

        fn extract(&self, _req: &Self::Request) -> Option<Self::Type> {
            Some(self.0)
        }
    }

    #[tokio::test]
    async fn test_sharded_shedder() {
        let opts = ShardedOptions {
            extractor: StubExtractor(0),
            passthrough_count: 100,
            ewma_alpha: 0.9,
            latencies: vec![TypeLatency(0, Duration::from_millis(1))],
        };
        let inner = StubService;

        let layer = ShardedLittleLoadShedderLayer::new(opts);
        let mut shedder = layer.layer(inner);

        // Now try 100 of concurrent requests with high latency
        // They shouldn't be shedded due to passthrough_requests
        let shedded = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        for _ in 0..100 {
            let shedder = shedder.clone();
            let shedded = shedded.clone();

            tracker.spawn(async move {
                let resp = shedder.oneshot(Duration::from_millis(10)).await.unwrap();
                if matches!(resp, ShedResponse::Overload(ShedReason::Latency)) {
                    shedded.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(shedded.load(Ordering::SeqCst), 0);

        // Make sure sequential requests are not shedded no matter the latency
        for _ in 0..10 {
            let resp = shedder.call(Duration::from_millis(10)).await.unwrap();
            assert_eq!(resp, ShedResponse::Inner(()));
        }

        // Now try 10 of concurrent requests with high latency
        // 8 of them should be shedded
        let shedded = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        for _ in 0..10 {
            let shedder = shedder.clone();
            let shedded = shedded.clone();

            tracker.spawn(async move {
                let resp = shedder.oneshot(Duration::from_millis(10)).await.unwrap();
                if matches!(resp, ShedResponse::Overload(ShedReason::Latency)) {
                    shedded.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(shedded.load(Ordering::SeqCst), 8);

        // Now try requests with low latency and limited concurrency
        let shedded = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        let sem = Arc::new(tokio::sync::Semaphore::new(2));

        for _ in 0..10 {
            let shedder = shedder.clone();
            let shedded = shedded.clone();
            let sem = sem.clone();

            tracker.spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                let resp = shedder.oneshot(Duration::from_millis(1)).await.unwrap();
                if matches!(resp, ShedResponse::Overload(ShedReason::Latency)) {
                    shedded.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(shedded.load(Ordering::SeqCst), 0);

        // Finally it shouldn't shed
        let resp = shedder.oneshot(Duration::from_millis(10)).await.unwrap();
        assert_eq!(resp, ShedResponse::Inner(()));

        // Check that non-existent type still works (extractor returns 1 but we configure only 0)
        let opts = ShardedOptions {
            extractor: StubExtractor(1),
            ewma_alpha: 0.9,
            passthrough_count: 0,
            latencies: vec![TypeLatency(0, Duration::from_millis(1))],
        };
        let inner = StubService;
        let layer = ShardedLittleLoadShedderLayer::new(opts);
        let mut shedder = layer.layer(inner);
        let resp = shedder.call(Duration::from_millis(50)).await.unwrap();
        assert_eq!(resp, ShedResponse::Inner(()));
    }

    /// Request that carries its own shard key and the latency to simulate
    #[derive(Debug, Clone)]
    struct KeyedReq(u8, Duration);

    #[derive(Debug, Clone)]
    struct KeyedService;

    impl Service<KeyedReq> for KeyedService {
        /// Echo the shard key back so that the routing can be checked
        type Response = u8;
        type Error = Error;
        type Future = BoxFuture<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: KeyedReq) -> Self::Future {
            let fut = async move {
                tokio::time::sleep(req.1).await;
                Ok(req.0)
            };

            Box::pin(fut)
        }
    }

    /// Extracts the shard key from the request itself
    #[derive(Debug, Clone)]
    struct KeyedExtractor;

    impl TypeExtractor for KeyedExtractor {
        type Type = u8;
        type Request = KeyedReq;

        fn extract(&self, req: &Self::Request) -> Option<Self::Type> {
            Some(req.0)
        }
    }

    /// Extractor that never manages to classify a request
    #[derive(Debug, Clone)]
    struct NoneExtractor;

    impl TypeExtractor for NoneExtractor {
        type Type = u8;
        type Request = Duration;

        fn extract(&self, _req: &Self::Request) -> Option<Self::Type> {
            None
        }
    }

    fn keyed_layer(
        latencies: Vec<TypeLatency<u8>>,
        passthrough_count: u64,
    ) -> ShardedLittleLoadShedderLayer<KeyedExtractor> {
        ShardedLittleLoadShedderLayer::new(ShardedOptions {
            extractor: KeyedExtractor,
            ewma_alpha: 0.9,
            passthrough_count,
            latencies,
        })
    }

    #[test]
    fn test_sharded_get_shard() {
        let layer = keyed_layer(
            vec![
                TypeLatency(1, Duration::from_millis(10)),
                TypeLatency(3, Duration::from_millis(20)),
            ],
            0,
        );
        assert_eq!(layer.1.len(), 2);

        let svc = layer.layer(KeyedService);
        assert!(svc.get_shard(&KeyedReq(1, Duration::ZERO)).is_some());
        assert!(svc.get_shard(&KeyedReq(3, Duration::ZERO)).is_some());
        // Unconfigured request types don't get a shard
        assert!(svc.get_shard(&KeyedReq(0, Duration::ZERO)).is_none());
        assert!(svc.get_shard(&KeyedReq(2, Duration::ZERO)).is_none());
        assert!(svc.get_shard(&KeyedReq(u8::MAX, Duration::ZERO)).is_none());

        // Neither do requests that the extractor can't classify
        let layer = ShardedLittleLoadShedderLayer::new(ShardedOptions {
            extractor: NoneExtractor,
            ewma_alpha: 0.9,
            passthrough_count: 0,
            latencies: vec![TypeLatency(0, Duration::from_millis(10))],
        });
        let svc = layer.layer(StubService);
        assert!(svc.get_shard(&Duration::ZERO).is_none());
    }

    #[test]
    fn test_sharded_shards_dedup_types() {
        // The same request type listed twice still yields a single shard
        let layer = keyed_layer(
            vec![
                TypeLatency(7, Duration::from_millis(10)),
                TypeLatency(7, Duration::from_millis(20)),
            ],
            0,
        );
        assert_eq!(layer.1.len(), 1);
        assert!(layer.1.contains_key(&7));

        // ... and it's the last entry that wins, i.e. the surviving shard
        // targets 20ms and not 10ms.
        let dbg = format!("{:?}", layer.1.get(&7).unwrap());
        assert!(dbg.contains("target: 0.02"), "unexpected shard: {dbg}");
    }

    #[tokio::test]
    async fn test_sharded_shards_are_independent() {
        let layer = keyed_layer(
            vec![
                TypeLatency(0, Duration::from_millis(1)),
                TypeLatency(1, Duration::from_millis(1)),
            ],
            0,
        );
        let mut shedder = layer.layer(KeyedService);

        // Saturate shard 0: it fits a single in-flight request plus a single
        // queued one, everything else is shed.
        let shedded = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        for _ in 0..10 {
            let shedder = shedder.clone();
            let shedded = shedded.clone();

            tracker.spawn(async move {
                let resp = shedder
                    .oneshot(KeyedReq(0, Duration::from_millis(50)))
                    .await
                    .unwrap();
                if matches!(resp, ShedResponse::Overload(ShedReason::Latency)) {
                    shedded.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        // Let the spawned requests reach the shedder
        tokio::task::yield_now().await;
        assert_eq!(shedded.load(Ordering::SeqCst), 8);

        // Shard 1 is not affected by shard 0 being overloaded
        for _ in 0..3 {
            let resp = shedder
                .call(KeyedReq(1, Duration::from_millis(1)))
                .await
                .unwrap();
            assert_eq!(resp, ShedResponse::Inner(1));
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(shedded.load(Ordering::SeqCst), 8);
    }

    #[tokio::test]
    async fn test_sharded_many_shards_are_isolated() {
        const SHARDS: u8 = 32;

        let layer = keyed_layer(
            (0..SHARDS)
                .map(|x| TypeLatency(x, Duration::from_millis(1)))
                .collect(),
            0,
        );
        assert_eq!(layer.1.len(), SHARDS as usize);
        let shedder = layer.layer(KeyedService);

        // A single slow request per shard: every shard has its own capacity,
        // so none of them is shed even though they all run concurrently.
        let served = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        for i in 0..SHARDS {
            let shedder = shedder.clone();
            let served = served.clone();

            tracker.spawn(async move {
                let resp = shedder
                    .oneshot(KeyedReq(i, Duration::from_millis(50)))
                    .await
                    .unwrap();
                assert_eq!(resp, ShedResponse::Inner(i));
                served.fetch_add(1, Ordering::SeqCst);
            });
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(served.load(Ordering::SeqCst), SHARDS as usize);
    }

    #[tokio::test]
    async fn test_sharded_unconfigured_types_are_not_shed() {
        // Only type 0 is shedded, type 9 isn't configured at all
        let layer = keyed_layer(vec![TypeLatency(0, Duration::from_millis(1))], 0);
        let shedder = layer.layer(KeyedService);

        let shedded_configured = Arc::new(AtomicUsize::new(0));
        let shedded_unknown = Arc::new(AtomicUsize::new(0));
        let served_unknown = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();

        for (key, shedded) in [
            (0u8, shedded_configured.clone()),
            (9u8, shedded_unknown.clone()),
        ] {
            for _ in 0..10 {
                let shedder = shedder.clone();
                let served = served_unknown.clone();
                let shedded = shedded.clone();

                tracker.spawn(async move {
                    let resp = shedder
                        .oneshot(KeyedReq(key, Duration::from_millis(50)))
                        .await
                        .unwrap();

                    match resp {
                        ShedResponse::Overload(ShedReason::Latency) => {
                            shedded.fetch_add(1, Ordering::SeqCst);
                        }
                        ShedResponse::Inner(v) => {
                            assert_eq!(v, key);
                            if key == 9 {
                                served.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        v => panic!("unexpected response: {v:?}"),
                    }
                });
            }
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(shedded_configured.load(Ordering::SeqCst), 8);
        assert_eq!(shedded_unknown.load(Ordering::SeqCst), 0);
        assert_eq!(served_unknown.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn test_sharded_without_shards() {
        // Nothing configured -> everything passes through unshedded
        let layer = keyed_layer(vec![], 0);
        assert!(layer.1.is_empty());
        let shedder = layer.layer(KeyedService);

        let served = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        for i in 0..20u8 {
            let shedder = shedder.clone();
            let served = served.clone();

            tracker.spawn(async move {
                let resp = shedder
                    .oneshot(KeyedReq(i, Duration::from_millis(50)))
                    .await
                    .unwrap();
                assert_eq!(resp, ShedResponse::Inner(i));
                served.fetch_add(1, Ordering::SeqCst);
            });
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(served.load(Ordering::SeqCst), 20);
    }

    #[tokio::test]
    async fn test_sharded_unclassified_requests_are_not_shed() {
        let layer = ShardedLittleLoadShedderLayer::new(ShardedOptions {
            extractor: NoneExtractor,
            ewma_alpha: 0.9,
            passthrough_count: 0,
            latencies: vec![TypeLatency(0, Duration::from_millis(1))],
        });
        let shedder = layer.layer(StubService);

        let shedded = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        for _ in 0..20 {
            let shedder = shedder.clone();
            let shedded = shedded.clone();

            tracker.spawn(async move {
                let resp = shedder.oneshot(Duration::from_millis(50)).await.unwrap();
                if matches!(resp, ShedResponse::Overload(_)) {
                    shedded.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(shedded.load(Ordering::SeqCst), 0);
    }
}
