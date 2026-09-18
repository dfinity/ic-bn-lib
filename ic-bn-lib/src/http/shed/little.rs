//! A load-shedding middleware based on [Little's law].
//!
//! This provides middleware for shedding load to maintain a target average
//! latency, see the documentation on the [`LoadShed`] service for more detail.
//!
//! [Little's law]: https://en.wikipedia.org/wiki/Little%27s_law
//!
//! (c) https://github.com/Skepfyr/little-loadshedder

#![warn(missing_debug_implementations)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::significant_drop_in_scrutinee)]
#![forbid(unsafe_code)]

use std::{
    cmp::Ordering,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, atomic::AtomicU64},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tower::{Layer, Service, ServiceExt};

/// Load Shed service's current state of the world
#[derive(Debug)]
pub struct LoadShedConf {
    /// The number of initial requests to pass without shedding
    passthrough_count: u64,
    /// The target average latency in seconds.
    target: f64,
    /// The exponentially weighted moving average parameter.
    /// Must be in the range (0, 1), `0.25` means new value accounts for 25% of
    /// the moving average.
    ewma_param: f64,
    /// Semaphore controlling the waiting queue of requests.
    available_queue: Arc<Semaphore>,
    /// Semaphore controlling concurrency to the inner service.
    available_concurrency: Arc<Semaphore>,
    /// Stats about the latency that change with each completed request.
    stats: Mutex<ConfStats>,
    /// Number of requests that were served
    requests: AtomicU64,
}

#[derive(Debug)]
struct ConfStats {
    /// The current average latency in seconds.
    average_latency: f64,
    /// The average of the latency measured when
    /// `available_concurrent.available_permits() == 0`.
    average_latency_at_capacity: f64,
    /// The number of available permits in the queue semaphore
    /// (the current capacity of the queue).
    queue_capacity: usize,
    /// The number of permits in the available_concurrency semaphore.
    concurrency: usize,
    /// The value of `self.concurrency` before it was last changed.
    previous_concurrency: usize,
    /// The time that the concurrency was last adjusted, to rate limit changing it.
    last_changed: Instant,
    /// Average throughput when at the previous concurrency value.
    previous_throughput: f64,
}

// size of system [req] = target latency [s] * throughput [r/s]
// size of queue [req] = size of system [req] - concurrency [req]
// throughput [req/s] = concurrency [req] / average latency of service [s]
// => (size of queue [req] + concurrency[req]) = target latency [s] * concurrency[req] / latency [s]
// => size of queue [req] = concurrency [req] * (target latency [s] / latency [s] - 1)
//
// Control the concurrency:
// increase concurrency but not beyond target latency
//
// Control queue length:
// queue capacity = concurrency * ((target latency / average latency of service) - 1)

impl LoadShedConf {
    pub fn new(ewma_param: f64, target: f64, passthrough_count: u64) -> Self {
        Self {
            passthrough_count,
            target,
            ewma_param,
            available_concurrency: Arc::new(Semaphore::new(1)),
            available_queue: Arc::new(Semaphore::new(1)),
            stats: Mutex::new(ConfStats {
                average_latency: target,
                average_latency_at_capacity: target,
                queue_capacity: 1,
                concurrency: 1,
                previous_concurrency: 0,
                last_changed: Instant::now(),
                previous_throughput: 0.0,
            }),
            requests: AtomicU64::new(0),
        }
    }

    /// Add ourselves to the queue and wait until we've made it through and have
    /// obtained a permit to send the request.
    async fn start(&self) -> Option<OwnedSemaphorePermit> {
        {
            // Work inside a block so we drop the stats lock asap.
            let mut stats = self.stats.lock().unwrap();
            let desired_queue_capacity = usize::max(
                1, // The queue must always be at least 1 request long.
                // Use average latency at (concurrency) capacity so that this doesn't
                // grow too large while the system is under-utilised.
                (stats.concurrency as f64
                    * ((self.target / stats.average_latency_at_capacity) - 1.0))
                    .floor() as usize,
            );

            // Adjust the semaphore capacity by adding or acquiring many permits.
            // If acquiring permits fails we can return overload and let the next
            // request recompute the queue capacity.
            match desired_queue_capacity.cmp(&stats.queue_capacity) {
                Ordering::Less => {
                    match self
                        .available_queue
                        .try_acquire_many((stats.queue_capacity - desired_queue_capacity) as u32)
                    {
                        Ok(permits) => permits.forget(),
                        Err(TryAcquireError::NoPermits) => return None,
                        Err(TryAcquireError::Closed) => panic!(),
                    }
                }
                Ordering::Equal => {}
                Ordering::Greater => self
                    .available_queue
                    .add_permits(desired_queue_capacity - stats.queue_capacity),
            }
            stats.queue_capacity = desired_queue_capacity;
        }

        // Finally get our queue permit, if this fails then the queue is full
        // and we need to bail out.
        let _queue_permit = match self.available_queue.clone().try_acquire_owned() {
            Ok(queue_permit) => queue_permit,
            Err(TryAcquireError::NoPermits) => return None,
            Err(TryAcquireError::Closed) => panic!("queue semaphore closed?"),
        };

        // We're in the queue now so wait until we get ourselves a concurrency permit.
        let concurrency_permit = self
            .available_concurrency
            .clone()
            .acquire_owned()
            .await
            .unwrap();

        Some(concurrency_permit)
    }

    /// Register a completed call of the inner service, providing the latency to
    /// update the statistics.
    fn stop(&self, elapsed: Duration) {
        let elapsed = elapsed.as_secs_f64();

        // This function solely updates the stats (and is not async) so hold the
        // lock for the entire function.
        let mut stats = self.stats.lock().expect("To be able to lock stats");

        let available_permits = self.available_concurrency.available_permits();
        // Have some leeway on what "at max concurrency" means as you might
        // otherwise never see this condition at large concurrency values.
        let at_max_concurrency = available_permits <= usize::max(1, stats.concurrency / 10);

        // Update the average latency using the EWMA algorithm.
        stats.average_latency = stats
            .average_latency
            .mul_add(1.0 - self.ewma_param, self.ewma_param * elapsed);

        if at_max_concurrency {
            stats.average_latency_at_capacity = stats
                .average_latency_at_capacity
                .mul_add(1.0 - self.ewma_param, self.ewma_param * elapsed);
        }

        // Only ever change max concurrency if we're at the limit as we need
        // measurements to have happened at the current limit.
        // Also, introduce a max rate of change that's somewhat magically
        // related to the latency and ewma parameter to prevent this from
        // changing too quickly.
        if stats.last_changed.elapsed().as_secs_f64()
            > (stats.average_latency / self.ewma_param) / 10.0
            && at_max_concurrency
        {
            // Plausibly should be using average latency at capacity here and
            // stats.concurrency but this appears to work. It might do weird
            // things if it's been running under capacity for a while then spikes.
            let current_concurrency = stats.concurrency - available_permits;
            let throughput = current_concurrency as f64 / stats.average_latency;
            // Was the throughput better or worse than it was previously.
            let negative_gradient = (throughput > stats.previous_throughput)
                ^ (current_concurrency > stats.previous_concurrency);
            if negative_gradient || (stats.average_latency > self.target) {
                // Don't reduce concurrency below 1 or everything stops.
                if stats.concurrency > 1 {
                    // negative gradient so decrease concurrency
                    self.available_concurrency.forget_permits(1);
                    stats.concurrency -= 1;

                    // Adjust the average latency assuming that the change in
                    // concurrency doesn't affect the service latency, which is
                    // closer to the truth than the latency not changing.
                    let latency_factor =
                        stats.concurrency as f64 / (stats.concurrency as f64 + 1.0);
                    stats.average_latency *= latency_factor;
                    stats.average_latency_at_capacity *= latency_factor;
                }
            } else {
                self.available_concurrency.add_permits(1);
                stats.concurrency += 1;

                // Adjust the average latency assuming that the change in
                // concurrency doesn't affect the service latency, which is
                // closer to the truth than the latency not changing.
                let latency_factor = stats.concurrency as f64 / (stats.concurrency as f64 - 1.0);
                stats.average_latency *= latency_factor;
                stats.average_latency_at_capacity *= latency_factor;
            }

            stats.previous_throughput = throughput;
            stats.previous_concurrency = current_concurrency;
            stats.last_changed = Instant::now()
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadShed<Inner> {
    conf: Arc<LoadShedConf>,
    inner: Inner,
}

impl<Inner> LoadShed<Inner> {
    /// Wrap a service with this middleware, using the given target average
    /// latency and computing the current average latency using an exponentially
    /// weighted moving average with the given parameter.
    pub const fn new(inner: Inner, conf: Arc<LoadShedConf>) -> Self {
        Self { inner, conf }
    }

    /// The current average latency of requests through the inner service,
    /// that is ignoring the queue this service adds.
    pub fn average_latency(&self) -> Duration {
        Duration::from_secs_f64(self.conf.stats.lock().unwrap().average_latency)
    }

    /// The current maximum concurrency of requests to the inner service.
    pub fn concurrency(&self) -> usize {
        self.conf.stats.lock().unwrap().concurrency
    }

    /// The current maximum capacity of this service (including the queue).
    pub fn queue_capacity(&self) -> usize {
        let stats = self.conf.stats.lock().unwrap();
        stats.concurrency + stats.queue_capacity
    }

    /// The current number of requests that have been accepted by this service.
    pub fn queue_len(&self) -> usize {
        let stats = self.conf.stats.lock().unwrap();
        let current_concurrency =
            stats.concurrency - self.conf.available_concurrency.available_permits();
        let current_queue = stats.queue_capacity - self.conf.available_queue.available_permits();

        current_concurrency + current_queue
    }
}

/// Either an error from the wrapped service or message that the request was shed
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoadShedResponse<T> {
    /// A response from the inner service.
    Inner(T),
    /// The request was shed due to overload.
    Overload,
}

type BoxFuture<Output> = Pin<Box<dyn Future<Output = Output> + Send>>;

impl<Request, Inner> Service<Request> for LoadShed<Inner>
where
    Request: Send + 'static,
    Inner: Service<Request> + Clone + Send + 'static,
    Inner::Future: Send,
{
    type Response = LoadShedResponse<Inner::Response>;
    type Error = Inner::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    /// Always ready because there's a queue between this service and the inner one.
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // We're fine to use the clone because inner hasn't been polled to
        // readiness yet.
        let inner = self.inner.clone();
        let conf = self.conf.clone();
        let requests = conf
            .requests
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        Box::pin(async move {
            let permit = conf.start().await;
            // If there's no permit & we're past initial passthrough count - then do load shedding.
            if permit.is_none() && requests >= conf.passthrough_count {
                return Ok(LoadShedResponse::Overload);
            }

            let start = Instant::now();
            // The elapsed time includes waiting for readiness which should help
            // us stay under any upstream concurrency limiters.
            let response = inner.oneshot(req).await;
            conf.stop(start.elapsed());
            Ok(LoadShedResponse::Inner(response?))
        })
    }
}

/// A [`Layer`] to wrap services in a [`LoadShed`] middleware.
///
/// See [`LoadShed`] for details of the load shedding algorithm.
#[derive(Debug, Clone)]
pub struct LoadShedLayer(Arc<LoadShedConf>);

impl LoadShedLayer {
    /// Create a new layer with the given target average latency and
    /// computing the current average latency using an exponentially weighted
    /// moving average with the given parameter.
    pub fn new(ewma_param: f64, target: Duration, passthrough_count: u64) -> Self {
        let conf = Arc::new(LoadShedConf::new(
            ewma_param,
            target.as_secs_f64(),
            passthrough_count,
        ));

        Self(conf)
    }
}

impl<Inner> Layer<Inner> for LoadShedLayer {
    type Service = LoadShed<Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        LoadShed::new(inner, self.0.clone())
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
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

    #[tokio::test]
    async fn test_little_loadshedder() {
        let layer = LoadShedLayer::new(0.9, Duration::from_millis(1), 100);
        let inner = StubService;
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
                if matches!(resp, LoadShedResponse::Overload) {
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
            assert_eq!(resp, LoadShedResponse::Inner(()));
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
                if matches!(resp, LoadShedResponse::Overload) {
                    shedded.fetch_add(1, Ordering::SeqCst);
                }
            });
        }

        tracker.close();
        tracker.wait().await;
        assert_eq!(shedded.load(Ordering::SeqCst), 8);
    }

    #[derive(Debug, Clone)]
    struct FailService;

    impl Service<Duration> for FailService {
        type Response = ();
        type Error = Error;
        type Future = BoxFuture<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Duration) -> Self::Future {
            Box::pin(async move { Err(Error::Generic(anyhow::anyhow!("inner boom"))) })
        }
    }

    #[track_caller]
    fn assert_close(got: f64, want: f64) {
        assert!((got - want).abs() < 1e-9, "expected {want}, got {got}");
    }

    /// Rewind the "concurrency last changed" timestamp so that the control loop
    /// is not rate-limited during the next `stop()` call.
    fn unthrottle(conf: &LoadShedConf) {
        conf.stats.lock().unwrap().last_changed = Instant::now() - Duration::from_secs(10);
    }

    #[test]
    fn test_little_conf_initial_state() {
        let layer = LoadShedLayer::new(0.25, Duration::from_millis(1500), 7);
        let conf = &layer.0;

        assert_close(conf.target, 1.5);
        assert_close(conf.ewma_param, 0.25);
        assert_eq!(conf.passthrough_count, 7);
        assert_eq!(conf.requests.load(Ordering::SeqCst), 0);

        // Both semaphores start with a single permit and the latency averages
        // start out at the target, so nothing is shed before any measurement.
        assert_eq!(conf.available_concurrency.available_permits(), 1);
        assert_eq!(conf.available_queue.available_permits(), 1);

        let stats = conf.stats.lock().unwrap();
        assert_eq!(stats.concurrency, 1);
        assert_eq!(stats.queue_capacity, 1);
        assert_eq!(stats.previous_concurrency, 0);
        assert_close(stats.average_latency, 1.5);
        assert_close(stats.average_latency_at_capacity, 1.5);
        assert_close(stats.previous_throughput, 0.0);
    }

    #[test]
    fn test_little_stop_updates_ewma_and_is_rate_limited() {
        // With ewma_param 0.1 the control loop's rate limit stays around a
        // second, so these calls only exercise the EWMA update.
        let conf = LoadShedConf::new(0.1, 1.0, 0);

        conf.stop(Duration::from_millis(100));
        assert_close(conf.stats.lock().unwrap().average_latency, 0.91);
        conf.stop(Duration::from_millis(100));
        assert_close(conf.stats.lock().unwrap().average_latency, 0.829);
        conf.stop(Duration::from_millis(100));

        let stats = conf.stats.lock().unwrap();
        assert_close(stats.average_latency, 0.7561);
        // A single permit with concurrency 1 counts as "at capacity",
        // so this average tracks the other one.
        assert_close(stats.average_latency_at_capacity, 0.7561);
        // Concurrency was left alone: the control loop is rate limited.
        assert_eq!(stats.concurrency, 1);
        assert_eq!(conf.available_concurrency.available_permits(), 1);
    }

    #[test]
    fn test_little_at_capacity_leeway() {
        // "At max concurrency" tolerates max(1, concurrency / 10) free permits,
        // i.e. 3 of them at concurrency 30.
        for (held, at_capacity) in [(26u32, false), (27u32, true)] {
            let conf = LoadShedConf::new(0.1, 1.0, 0);
            conf.available_concurrency.add_permits(29);
            conf.stats.lock().unwrap().concurrency = 30;

            let _permits = conf
                .available_concurrency
                .clone()
                .try_acquire_many_owned(held)
                .unwrap();

            conf.stop(Duration::from_millis(100));

            let stats = conf.stats.lock().unwrap();
            assert_close(stats.average_latency, 0.91);
            if at_capacity {
                assert_close(stats.average_latency_at_capacity, 0.91);
            } else {
                // 4 free permits out of 30 is not yet "at capacity",
                // so this average is left at its initial value.
                assert_close(stats.average_latency_at_capacity, 1.0);
            }
            // Not enough time has passed to touch the concurrency.
            assert_eq!(stats.concurrency, 30);
        }
    }

    #[test]
    fn test_little_concurrency_grows_below_target() {
        let conf = LoadShedConf::new(0.5, 1.0, 0);
        unthrottle(&conf);

        conf.stop(Duration::from_millis(100));

        // 0.5 * 1.0 + 0.5 * 0.1 = 0.55 which is below the 1.0 target and the
        // throughput gradient isn't negative -> one more permit.
        assert_eq!(conf.available_concurrency.available_permits(), 2);

        let stats = conf.stats.lock().unwrap();
        assert_eq!(stats.concurrency, 2);
        // Averages are scaled by concurrency / (concurrency - 1) == 2.0
        assert_close(stats.average_latency, 1.1);
        assert_close(stats.average_latency_at_capacity, 1.1);
        assert_close(stats.previous_throughput, 0.0);
        assert_eq!(stats.previous_concurrency, 0);
    }

    #[test]
    fn test_little_concurrency_shrinks_above_target() {
        let conf = LoadShedConf::new(0.5, 1.0, 0);
        conf.available_concurrency.add_permits(1);
        conf.stats.lock().unwrap().concurrency = 2;
        unthrottle(&conf);

        // One in-flight request leaves one free permit, which still counts as
        // being at capacity when concurrency is 2.
        let permit = conf
            .available_concurrency
            .clone()
            .try_acquire_owned()
            .unwrap();

        conf.stop(Duration::from_secs(3));

        {
            let stats = conf.stats.lock().unwrap();
            // 0.5 * 1.0 + 0.5 * 3.0 = 2.0, way over the target -> shrink
            assert_eq!(stats.concurrency, 1);
            // Averages are scaled by concurrency / (concurrency + 1) == 0.5
            assert_close(stats.average_latency, 1.0);
            assert_close(stats.average_latency_at_capacity, 1.0);
            assert_close(stats.previous_throughput, 0.5);
            assert_eq!(stats.previous_concurrency, 1);
        }

        // The permit was really taken away from the semaphore
        assert_eq!(conf.available_concurrency.available_permits(), 0);
        drop(permit);
        assert_eq!(conf.available_concurrency.available_permits(), 1);
    }

    #[test]
    fn test_little_concurrency_shrinks_on_negative_gradient() {
        // Latency is far below the target, but the throughput went up while the
        // concurrency went down -> negative gradient -> shrink anyway.
        let conf = LoadShedConf::new(0.5, 1.0, 0);
        conf.available_concurrency.add_permits(1);
        {
            let mut stats = conf.stats.lock().unwrap();
            stats.concurrency = 2;
            stats.average_latency = 0.1;
            stats.average_latency_at_capacity = 0.1;
            stats.previous_concurrency = 5;
        }
        unthrottle(&conf);

        let _permit = conf
            .available_concurrency
            .clone()
            .try_acquire_owned()
            .unwrap();

        conf.stop(Duration::from_millis(100));

        let stats = conf.stats.lock().unwrap();
        assert_eq!(stats.concurrency, 1);
        assert_close(stats.average_latency, 0.05);
        assert!(stats.average_latency < conf.target);
        // 1 in-flight request / 0.1s average latency
        assert_close(stats.previous_throughput, 10.0);
        assert_eq!(stats.previous_concurrency, 1);
    }

    #[test]
    fn test_little_concurrency_never_drops_below_one() {
        let conf = LoadShedConf::new(0.5, 1.0, 0);
        unthrottle(&conf);

        // All permits are in use (so we're at capacity) and the latency is
        // way above the target, but concurrency can't go below 1.
        let permit = conf
            .available_concurrency
            .clone()
            .try_acquire_owned()
            .unwrap();

        conf.stop(Duration::from_secs(3));

        {
            let stats = conf.stats.lock().unwrap();
            assert_eq!(stats.concurrency, 1);
            // No concurrency change means no latency rescaling either
            assert_close(stats.average_latency, 2.0);
            assert_close(stats.average_latency_at_capacity, 2.0);
            assert_close(stats.previous_throughput, 0.5);
            assert_eq!(stats.previous_concurrency, 1);
        }

        // ... and no permit was forgotten
        drop(permit);
        assert_eq!(conf.available_concurrency.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_little_start_adjusts_queue_capacity() {
        let conf = LoadShedConf::new(0.5, 1.0, 0);
        {
            let mut stats = conf.stats.lock().unwrap();
            stats.concurrency = 10;
            stats.average_latency_at_capacity = 0.25;
        }

        // queue = concurrency * (target / latency_at_capacity - 1) = 10 * 3
        assert!(conf.start().await.is_some());
        assert_eq!(conf.stats.lock().unwrap().queue_capacity, 30);
        assert_eq!(conf.available_queue.available_permits(), 30);

        // Latency doubles -> the queue shrinks to 10 * (2 - 1)
        conf.stats.lock().unwrap().average_latency_at_capacity = 0.5;
        assert!(conf.start().await.is_some());
        assert_eq!(conf.stats.lock().unwrap().queue_capacity, 10);
        assert_eq!(conf.available_queue.available_permits(), 10);

        // Latency above the target would give a negative queue size,
        // but it's clamped to a single request.
        conf.stats.lock().unwrap().average_latency_at_capacity = 2.0;
        assert!(conf.start().await.is_some());
        assert_eq!(conf.stats.lock().unwrap().queue_capacity, 1);
        assert_eq!(conf.available_queue.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_little_start_returns_none_when_queue_is_full() {
        let conf = LoadShedConf::new(0.5, 1.0, 0);
        let _queued = conf.available_queue.clone().try_acquire_owned().unwrap();

        assert!(conf.start().await.is_none());
        assert_eq!(conf.stats.lock().unwrap().queue_capacity, 1);
        // The concurrency permit is never taken when we bail out early
        assert_eq!(conf.available_concurrency.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_little_start_returns_none_when_shrinking_queue_fails() {
        let conf = LoadShedConf::new(0.5, 1.0, 0);
        // Pretend the queue is 5 requests long while the semaphore only holds a
        // single permit: shrinking it back to 1 needs 4 permits that aren't there.
        conf.stats.lock().unwrap().queue_capacity = 5;

        assert!(conf.start().await.is_none());
        // The capacity is left alone so that the next request recomputes it
        assert_eq!(conf.stats.lock().unwrap().queue_capacity, 5);
        assert_eq!(conf.available_queue.available_permits(), 1);
    }

    #[test]
    fn test_little_accessors() {
        let layer = LoadShedLayer::new(0.5, Duration::from_millis(500), 0);
        let svc = layer.layer(StubService);
        let conf = &layer.0;

        assert_eq!(svc.average_latency(), Duration::from_millis(500));
        assert_eq!(svc.concurrency(), 1);
        // Concurrency + queue
        assert_eq!(svc.queue_capacity(), 2);
        assert_eq!(svc.queue_len(), 0);

        let _concurrency = conf
            .available_concurrency
            .clone()
            .try_acquire_owned()
            .unwrap();
        assert_eq!(svc.queue_len(), 1);
        let _queued = conf.available_queue.clone().try_acquire_owned().unwrap();
        assert_eq!(svc.queue_len(), 2);

        // 0.5 * 0.5 + 0.5 * 1.0 = 0.75
        conf.stop(Duration::from_secs(1));
        assert_eq!(svc.average_latency(), Duration::from_secs_f64(0.75));
    }

    #[tokio::test]
    async fn test_little_passthrough_count_boundary() {
        let layer = LoadShedLayer::new(0.1, Duration::from_millis(100), 1);
        let mut svc = layer.layer(StubService);
        // Block the queue so that no request can ever get a permit
        let _queued = layer.0.available_queue.clone().try_acquire_owned().unwrap();

        // The very first request is within the passthrough allowance ...
        assert_eq!(
            svc.call(Duration::ZERO).await.unwrap(),
            LoadShedResponse::Inner(())
        );
        // ... all the subsequent ones are shed
        assert_eq!(
            svc.call(Duration::ZERO).await.unwrap(),
            LoadShedResponse::Overload
        );
        assert_eq!(
            svc.call(Duration::ZERO).await.unwrap(),
            LoadShedResponse::Overload
        );
        assert_eq!(layer.0.requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_little_propagates_inner_error() {
        let layer = LoadShedLayer::new(0.5, Duration::from_secs(1), 100);
        let svc = layer.layer(FailService);

        let err = svc.clone().oneshot(Duration::ZERO).await.unwrap_err();
        assert!(err.to_string().contains("inner boom"), "{err}");

        // The latency of a failed call is still recorded:
        // 0.5 * 1.0 + 0.5 * ~0.0 == ~0.5s
        let avg = svc.average_latency().as_secs_f64();
        assert!(
            (0.45..0.55).contains(&avg),
            "unexpected average latency {avg}"
        );
    }
}
