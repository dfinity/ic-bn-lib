use std::{
    fmt::Debug,
    sync::{Arc, RwLock, RwLockWriteGuard},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use ic_bn_lib_common::{
    traits::shed::GetsSystemInfo,
    types::shed::{ShedReason, ShedResponse, SystemOptions},
};
use systemstat::{Platform, System};
use tower::{Layer, Service, ServiceExt};
use tracing::{debug, error};

use super::{BoxFuture, ewma::EWMA};
use crate::Error;

#[derive(Clone)]
pub struct SystemInfo(Arc<System>);

impl SystemInfo {
    pub fn new() -> Self {
        Self(Arc::new(System::new()))
    }
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GetsSystemInfo for SystemInfo {
    async fn cpu_usage(&self) -> Result<f64, Error> {
        let cpu = self
            .0
            .cpu_load_aggregate()
            .context("unable to measure CPU load")?;
        tokio::time::sleep(Duration::from_millis(900)).await;
        let cpu = cpu.done().context("unable to measure CPU load")?;

        Ok(1.0 - cpu.idle as f64)
    }

    fn memory_usage(&self) -> Result<f64, Error> {
        let mem = self.0.memory().context("unable to measure memory usage")?;
        if mem.total.as_u64() == 0 {
            return Err(anyhow!("total memory is zero").into());
        }

        Ok(1.0 - mem.free.as_u64() as f64 / mem.total.as_u64() as f64)
    }

    fn load_avg(&self) -> Result<(f64, f64, f64), Error> {
        let la = self
            .0
            .load_average()
            .context("unable to measure load average")?;

        Ok((la.one as f64, la.five as f64, la.fifteen as f64))
    }
}

#[derive(Debug)]
struct StateInner {
    cpu: EWMA,
    memory: EWMA,
    load_avg: (EWMA, EWMA, EWMA),
    shed_reason: Option<ShedReason>,
}

impl StateInner {
    fn new(alpha: f64) -> Self {
        Self {
            cpu: EWMA::new(alpha),
            memory: EWMA::new(alpha),
            load_avg: (EWMA::new(alpha), EWMA::new(alpha), EWMA::new(alpha)),
            shed_reason: None,
        }
    }
}

/// System info state
#[derive(Debug)]
pub struct State<S: GetsSystemInfo> {
    opts: SystemOptions,
    sys_info: S,
    inner: RwLock<StateInner>,
}

impl<S: GetsSystemInfo> State<S> {
    pub fn new(alpha: f64, opts: SystemOptions, sys_info: S) -> Self {
        Self {
            opts,
            sys_info,
            inner: RwLock::new(StateInner::new(alpha)),
        }
    }

    /// Perform system info measurement
    async fn measure(&self) -> Result<(), Error> {
        let cpu = self.sys_info.cpu_usage().await?;
        let mem = self.sys_info.memory_usage()?;
        let (l1, l5, l15) = self.sys_info.load_avg()?;

        let mut inner = self.inner.write().unwrap();
        inner.cpu.add(cpu);
        inner.memory.add(mem);
        inner.load_avg.0.add(l1);
        inner.load_avg.1.add(l5);
        inner.load_avg.2.add(l15);

        // Check if we're overloaded
        inner.shed_reason = self.evaluate(&inner);
        debug!(
            "System load: CPU {cpu}, MEM {mem}, LAVG1: {l1}, LAVG5: {l5}, LAVG15: {l15}, Overload: {:?}",
            inner.shed_reason
        );

        drop(inner); // clippy
        Ok(())
    }

    fn evaluate(&self, state: &RwLockWriteGuard<'_, StateInner>) -> Option<ShedReason> {
        if self
            .opts
            .cpu
            .map(|x| state.cpu.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::CPU);
        }

        if self
            .opts
            .memory
            .map(|x| state.memory.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::Memory);
        }

        if self
            .opts
            .loadavg_1
            .map(|x| state.load_avg.0.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::LoadAvg);
        }

        if self
            .opts
            .loadavg_5
            .map(|x| state.load_avg.1.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::LoadAvg);
        }

        if self
            .opts
            .loadavg_15
            .map(|x| state.load_avg.2.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::LoadAvg);
        }

        None
    }

    fn is_overloaded(&self) -> Option<ShedReason> {
        self.inner.read().unwrap().shed_reason
    }

    /// Periodically run the measurements
    async fn run(&self) {
        // CPU usage measurement takes 900ms so we run every second
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            if let Err(e) = self.measure().await {
                error!("SystemLoadShedder: error: {e:#}");
            }
        }
    }
}

/// Load shedder that sheds requests when the system load is over the defined thresholds
#[derive(Debug, Clone)]
pub struct SystemLoadShedder<S: GetsSystemInfo, I> {
    state: Arc<State<S>>,
    inner: I,
}

impl<S: GetsSystemInfo, I> SystemLoadShedder<S, I> {
    pub const fn new(inner: I, state: Arc<State<S>>) -> Self {
        Self { state, inner }
    }
}

// Implement tower service
impl<S: GetsSystemInfo, R, I> Service<R> for SystemLoadShedder<S, I>
where
    R: Send + 'static,
    I: Service<R> + Clone + Send + Sync + 'static,
    I::Future: Send,
{
    type Response = ShedResponse<I::Response>;
    type Error = I::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: R) -> Self::Future {
        // Check if we need to shed the load
        let shed_reason = self.state.is_overloaded();
        if let Some(v) = shed_reason {
            return Box::pin(async move { Ok(ShedResponse::Overload(v)) });
        }

        let inner = self.inner.clone();
        Box::pin(async move {
            let response = inner.oneshot(req).await;
            Ok(ShedResponse::Inner(response?))
        })
    }
}

/// Layer for `SystemLoadShedder`
#[derive(Debug, Clone)]
pub struct SystemLoadShedderLayer<S: GetsSystemInfo>(Arc<State<S>>);

impl<S: GetsSystemInfo> SystemLoadShedderLayer<S> {
    pub fn new(ewma_alpha: f64, opts: SystemOptions, sys_info: S) -> Self {
        // Create a state that will be shared among all the shedder instances
        let state = Arc::new(State::new(ewma_alpha, opts, sys_info));

        // Spawn the background task to perform the system measurements
        let state_bg = state.clone();
        tokio::spawn(async move { state_bg.run().await });

        Self(state)
    }
}

impl<S: GetsSystemInfo, I: Clone + Send + Sync + 'static> Layer<I> for SystemLoadShedderLayer<S> {
    type Service = SystemLoadShedder<S, I>;

    fn layer(&self, inner: I) -> Self::Service {
        SystemLoadShedder::new(inner, self.0.clone())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Mutex;

    use super::*;

    #[derive(Clone, Debug)]
    struct StubSystemInfoVal {
        cpu: f64,
        memory: f64,
        l1: f64,
        l5: f64,
        l15: f64,
    }

    #[derive(Clone, Debug)]
    struct StubSystemInfo {
        v: Arc<Mutex<StubSystemInfoVal>>,
    }

    #[async_trait]
    impl GetsSystemInfo for StubSystemInfo {
        async fn cpu_usage(&self) -> Result<f64, Error> {
            Ok(self.v.lock().unwrap().cpu)
        }

        fn memory_usage(&self) -> Result<f64, Error> {
            Ok(self.v.lock().unwrap().memory)
        }

        fn load_avg(&self) -> Result<(f64, f64, f64), Error> {
            let v = self.v.lock().unwrap();
            Ok((v.l1, v.l5, v.l15))
        }
    }

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
    async fn test_system_shedder() {
        let inner = StubService;
        let opts = SystemOptions {
            cpu: Some(0.5),
            memory: Some(0.5),
            loadavg_1: Some(0.5),
            loadavg_5: Some(0.5),
            loadavg_15: Some(0.5),
        };
        let sys_info = StubSystemInfo {
            v: Arc::new(Mutex::new(StubSystemInfoVal {
                cpu: 0.0,
                memory: 0.0,
                l1: 0.0,
                l5: 0.0,
                l15: 0.0,
            })),
        };

        let state = Arc::new(State::new(0.8, opts, sys_info.clone()));
        let mut shedder = SystemLoadShedder::new(inner, state.clone());
        let _ = state.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert!(matches!(resp, ShedResponse::Inner(_)));

        sys_info.v.lock().unwrap().cpu = 1.0;
        let _ = state.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::CPU));
        sys_info.v.lock().unwrap().cpu = 0.0;

        sys_info.v.lock().unwrap().memory = 1.0;
        let _ = state.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::Memory));
        sys_info.v.lock().unwrap().memory = 0.0;

        sys_info.v.lock().unwrap().l1 = 1.0;
        let _ = state.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::LoadAvg));
        sys_info.v.lock().unwrap().l1 = 0.0;

        sys_info.v.lock().unwrap().l5 = 1.0;
        let _ = state.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::LoadAvg));
        sys_info.v.lock().unwrap().l5 = 0.0;

        sys_info.v.lock().unwrap().l15 = 1.0;
        let _ = state.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::LoadAvg));
        sys_info.v.lock().unwrap().l15 = 0.0;

        let _ = state.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert!(matches!(resp, ShedResponse::Inner(_)));
    }
}
