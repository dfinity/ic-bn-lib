use std::{
    collections::BTreeMap,
    fmt::Debug,
    sync::Arc,
    task::{Context, Poll},
};

use ic_bn_lib_common::{
    traits::shed::TypeExtractor,
    types::shed::{ShardedOptions, ShedReason, ShedResponse},
};
use tower::{Layer, Service, ServiceExt};

use super::{
    BoxFuture,
    little::{LoadShedLayer, LoadShedResponse},
};

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

    use ic_bn_lib_common::types::shed::TypeLatency;
    use tokio_util::task::TaskTracker;

    use super::*;
    use crate::Error;

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
}
