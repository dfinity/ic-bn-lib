use std::{
    fmt::Debug,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use systemstat::{Platform, System};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service, ServiceExt};
use tracing::{error, warn};

use super::{ewma::EWMA, BoxFuture, ShedReason, ShedResponse};
use crate::{tasks::Run, Error};

#[async_trait]
pub trait GetsSystemInfo: Send + Sync + Clone {
    async fn cpu_usage(&self) -> Result<f64, Error>;
    fn memory_usage(&self) -> Result<f64, Error>;
    fn load_avg(&self) -> Result<(f64, f64, f64), Error>;
}

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
        tokio::time::sleep(Duration::from_secs(1)).await;
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

struct Averages {
    cpu: EWMA,
    memory: EWMA,
    load_avg: (EWMA, EWMA, EWMA),
}

impl Averages {
    fn new(alpha: f64) -> Self {
        Self {
            cpu: EWMA::new(alpha),
            memory: EWMA::new(alpha),
            load_avg: (EWMA::new(alpha), EWMA::new(alpha), EWMA::new(alpha)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SystemOptions {
    pub ewma_alpha: f64,
    pub cpu: Option<f64>,
    pub memory: Option<f64>,
    pub loadavg_1: Option<f64>,
    pub loadavg_5: Option<f64>,
    pub loadavg_15: Option<f64>,
}

impl SystemOptions {
    fn check(self) -> Result<Self, Error> {
        if self.ewma_alpha < 0.0 || self.ewma_alpha > 1.0 {
            return Err(anyhow!("EWMA alpha should be in [0.0, 1.0] range").into());
        }

        if self.cpu.is_none()
            && self.memory.is_none()
            && self.loadavg_1.is_none()
            && self.loadavg_5.is_none()
            && self.loadavg_15.is_none()
        {
            return Err(anyhow!("at least one load-shedding threshold must be enabled").into());
        }

        Ok(self)
    }
}

/// Load shedder that sheds requests when the system load is over the defined thresholds
pub struct SystemLoadShedder<S: GetsSystemInfo, I> {
    sys_info: S,
    avg: RwLock<Averages>,
    opts: SystemOptions,
    inner: I,
}

impl<S: GetsSystemInfo, I: Send + Sync> SystemLoadShedder<S, I> {
    pub fn new(inner: I, opts: SystemOptions, sys_info: S) -> Result<Self, Error> {
        let opts = opts.check()?;

        Ok(Self {
            sys_info,
            avg: RwLock::new(Averages::new(opts.ewma_alpha)),
            opts,
            inner,
        })
    }

    async fn measure(&self) -> Result<(), Error> {
        let cpu = self.sys_info.cpu_usage().await?;
        let mem = self.sys_info.memory_usage()?;
        let (l1, l5, l15) = self.sys_info.load_avg()?;

        let mut avg = self.avg.write().unwrap();
        avg.cpu.add(cpu);
        avg.memory.add(mem);
        avg.load_avg.0.add(l1);
        avg.load_avg.1.add(l5);
        avg.load_avg.2.add(l15);
        drop(avg); // clippy

        Ok(())
    }

    fn evaluate(&self) -> Option<ShedReason> {
        let avg = self.avg.read().unwrap();

        if self
            .opts
            .cpu
            .map(|x| avg.cpu.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::CPU);
        }

        if self
            .opts
            .memory
            .map(|x| avg.memory.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::Memory);
        }

        if self
            .opts
            .loadavg_1
            .map(|x| avg.load_avg.0.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::LoadAvg);
        }

        if self
            .opts
            .loadavg_5
            .map(|x| avg.load_avg.1.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::LoadAvg);
        }

        if self
            .opts
            .loadavg_15
            .map(|x| avg.load_avg.2.get().unwrap_or(0.0) > x)
            .unwrap_or(false)
        {
            return Some(ShedReason::LoadAvg);
        }

        None
    }
}

#[async_trait]
impl<S: GetsSystemInfo, I: Send + Sync> Run for SystemLoadShedder<S, I> {
    async fn run(&self, token: CancellationToken) -> Result<(), anyhow::Error> {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                () = token.cancelled() => {
                    warn!("SystemLoadShedder: exiting");
                    return Ok(());
                }

                _ = interval.tick() => {
                    if let Err(e) = self.measure().await {
                        error!("SystemLoadShedder: error: {e:#}");
                    }
                },
            }
        }
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
        if let Some(v) = self.evaluate() {
            return Box::pin(async move { Ok(ShedResponse::Overload(v)) });
        }

        let inner = self.inner.clone();
        Box::pin(async move {
            let response = inner.oneshot(req).await;
            Ok(ShedResponse::Inner(response?))
        })
    }
}

#[derive(Debug, Clone)]
pub struct SystemLoadShedderLayer<S: GetsSystemInfo>(SystemOptions, S);

impl<S: GetsSystemInfo> SystemLoadShedderLayer<S> {
    pub fn new(opts: SystemOptions, sys_info: S) -> Result<Self, Error> {
        Ok(Self(opts.check()?, sys_info))
    }
}

impl<S: GetsSystemInfo, I: Send + Sync> Layer<I> for SystemLoadShedderLayer<S> {
    type Service = SystemLoadShedder<S, I>;

    fn layer(&self, inner: I) -> Self::Service {
        // Error is checked in new() so unwrap is safe
        SystemLoadShedder::new(inner, self.0, self.1.clone()).unwrap()
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
        // Check incorrect options
        let opts = SystemOptions {
            ewma_alpha: 0.5,
            cpu: None,
            memory: None,
            loadavg_1: None,
            loadavg_5: None,
            loadavg_15: None,
        };
        assert!(opts.check().is_err());

        let opts = SystemOptions {
            ewma_alpha: -0.1,
            cpu: Some(0.5),
            memory: None,
            loadavg_1: None,
            loadavg_5: None,
            loadavg_15: None,
        };
        assert!(opts.check().is_err());

        let opts = SystemOptions {
            ewma_alpha: 1.1,
            cpu: Some(0.5),
            memory: None,
            loadavg_1: None,
            loadavg_5: None,
            loadavg_15: None,
        };
        assert!(opts.check().is_err());

        let inner = StubService;
        let opts = SystemOptions {
            ewma_alpha: 0.8,
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

        let mut shedder = SystemLoadShedder::new(inner, opts, sys_info.clone()).unwrap();
        let _ = shedder.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert!(matches!(resp, ShedResponse::Inner(_)));

        sys_info.v.lock().unwrap().cpu = 1.0;
        let _ = shedder.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::CPU));
        sys_info.v.lock().unwrap().cpu = 0.0;

        sys_info.v.lock().unwrap().memory = 1.0;
        let _ = shedder.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::Memory));
        sys_info.v.lock().unwrap().memory = 0.0;

        sys_info.v.lock().unwrap().l1 = 1.0;
        let _ = shedder.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::LoadAvg));
        sys_info.v.lock().unwrap().l1 = 0.0;

        sys_info.v.lock().unwrap().l5 = 1.0;
        let _ = shedder.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::LoadAvg));
        sys_info.v.lock().unwrap().l5 = 0.0;

        sys_info.v.lock().unwrap().l15 = 1.0;
        let _ = shedder.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert_eq!(resp, ShedResponse::Overload(ShedReason::LoadAvg));
        sys_info.v.lock().unwrap().l15 = 0.0;

        let _ = shedder.measure().await;
        let resp = shedder.call(Duration::ZERO).await.unwrap();
        assert!(matches!(resp, ShedResponse::Inner(_)));
    }
}
