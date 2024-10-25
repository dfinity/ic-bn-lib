use std::{
    collections::BTreeMap,
    fmt::Debug,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tower::{Layer, Service, ServiceExt};

use super::{
    little::{LoadShed, LoadShedResponse},
    BoxFuture, ShedReason, ShedResponse,
};

/// Trait to extract the shedding key from the given request
pub trait TypeExtractor: Clone + Debug + Send + Sync + 'static {
    /// The type of the request.
    type Type: Clone + Debug + Send + Sync + Ord + 'static;
    type Request: Send;

    /// Extraction method, should return None response when the extraction failed
    fn extract(&self, req: &Self::Request) -> Option<Self::Type>;
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TypeLatency<T>(pub T, pub Duration);

#[derive(Debug, Clone)]
pub struct ShardedOptions<T: TypeExtractor> {
    pub extractor: T,
    pub ewma_alpha: f64,
    pub passthrough_count: u64,
    pub latencies: Vec<TypeLatency<T::Type>>,
}

#[derive(Debug, Clone)]
pub struct ShardedLittleLoadShedder<T: TypeExtractor, I> {
    extractor: T,
    inner: I,
    shards: Arc<BTreeMap<T::Type, LoadShed<I>>>,
}

impl<T: TypeExtractor, I: Send + Sync + Clone> ShardedLittleLoadShedder<T, I> {
    pub fn new(inner: I, opts: ShardedOptions<T>) -> Self {
        // Generate the shedding shards, one per provided request type
        let shards = Arc::new(BTreeMap::from_iter(opts.latencies.into_iter().map(|x| {
            (
                x.0,
                LoadShed::new(inner.clone(), opts.ewma_alpha, x.1, opts.passthrough_count),
            )
        })));

        Self {
            extractor: opts.extractor,
            inner,
            shards,
        }
    }

    // Tries to find a shard corresponding to the given request
    fn get_shard(&self, req: &T::Request) -> Option<LoadShed<I>> {
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

        Box::pin(async move {
            // Map response to our
            shard.oneshot(req).await.map(|x| match x {
                LoadShedResponse::Overload => ShedResponse::Overload(ShedReason::Latency),
                LoadShedResponse::Inner(i) => ShedResponse::Inner(i),
            })
        })
    }
}

#[derive(Debug, Clone)]
pub struct ShardedLittleLoadShedderLayer<T: TypeExtractor>(ShardedOptions<T>);

impl<T: TypeExtractor> ShardedLittleLoadShedderLayer<T> {
    pub const fn new(opts: ShardedOptions<T>) -> Self {
        Self(opts)
    }
}

impl<T: TypeExtractor, I: Send + Sync + Clone> Layer<I> for ShardedLittleLoadShedderLayer<T> {
    type Service = ShardedLittleLoadShedder<T, I>;

    fn layer(&self, inner: I) -> Self::Service {
        ShardedLittleLoadShedder::new(inner, self.0.clone())
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

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
        type Request = Duration;
        type Type = u8;

        fn extract(&self, _req: &Self::Request) -> Option<Self::Type> {
            return Some(self.0);
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

        let mut shedder = ShardedLittleLoadShedder::new(inner, opts);

        // Make sure sequential requests are not shedded no matter the latency
        for _ in 0..10 {
            let resp = shedder.call(Duration::from_millis(10)).await.unwrap();
            assert_eq!(resp, ShedResponse::Inner(()));
        }

        // Now try 90 of concurrent requests with high latency
        // They shouldn't be shedded due to passthrough_requests
        let shedded = Arc::new(AtomicUsize::new(0));
        let tracker = TaskTracker::new();
        for _ in 0..90 {
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

        // Check that non-existant type still works (extractor returns 1 but we configure only 0)
        let opts = ShardedOptions {
            extractor: StubExtractor(1),
            ewma_alpha: 0.9,
            passthrough_count: 0,
            latencies: vec![TypeLatency(0, Duration::from_millis(1))],
        };
        let inner = StubService;
        let mut shedder = ShardedLittleLoadShedder::new(inner, opts);
        let resp = shedder.call(Duration::from_millis(50)).await.unwrap();
        assert_eq!(resp, ShedResponse::Inner(()));
    }
}
