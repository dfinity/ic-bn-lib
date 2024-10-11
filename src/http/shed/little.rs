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
    sync::{atomic::AtomicU64, Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tower::{Layer, Service, ServiceExt};

/// Load Shed service's current state of the world
#[derive(Debug, Clone)]
struct LoadShedConf {
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
    stats: Arc<Mutex<ConfStats>>,
    /// Number of requests that were served
    requests: Arc<AtomicU64>,
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
    fn new(ewma_param: f64, target: f64, passthrough_count: u64) -> Self {
        Self {
            passthrough_count,
            target,
            ewma_param,
            available_concurrency: Arc::new(Semaphore::new(1)),
            available_queue: Arc::new(Semaphore::new(1)),
            stats: Arc::new(Mutex::new(ConfStats {
                average_latency: target,
                average_latency_at_capacity: target,
                queue_capacity: 1,
                concurrency: 1,
                previous_concurrency: 0,
                last_changed: Instant::now(),
                previous_throughput: 0.0,
            })),
            requests: Arc::new(AtomicU64::new(0)),
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
        let queue_permit = match self.available_queue.clone().try_acquire_owned() {
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

        // Now we've got the permit required to send the request we can leave the queue.
        drop(queue_permit);
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
    conf: LoadShedConf,
    inner: Inner,
}

impl<Inner> LoadShed<Inner> {
    /// Wrap a service with this middleware, using the given target average
    /// latency and computing the current average latency using an exponentially
    /// weighted moving average with the given parameter.
    pub fn new(inner: Inner, ewma_param: f64, target: Duration, passthrough_count: u64) -> Self {
        Self {
            inner,
            conf: LoadShedConf::new(ewma_param, target.as_secs_f64(), passthrough_count),
        }
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
pub struct LoadShedLayer {
    ewma_param: f64,
    passthrough_count: u64,
    target: Duration,
}

impl LoadShedLayer {
    /// Create a new layer with the given target average latency and
    /// computing the current average latency using an exponentially weighted
    /// moving average with the given parameter.
    pub const fn new(ewma_param: f64, target: Duration, passthrough_count: u64) -> Self {
        Self {
            ewma_param,
            target,
            passthrough_count,
        }
    }
}

impl<Inner> Layer<Inner> for LoadShedLayer {
    type Service = LoadShed<Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        LoadShed::new(inner, self.ewma_param, self.target, self.passthrough_count)
    }
}
