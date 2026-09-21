use std::{
    fmt::Debug,
    sync::{Arc, RwLock, RwLockWriteGuard},
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, anyhow};
use async_trait::async_trait;
use systemstat::{Platform, System};
use tower::{Layer, Service, ServiceExt};
use tracing::{debug, error};

use super::{BoxFuture, ewma::EWMA};
use crate::http::{
    Error,
    shed::{GetsSystemInfo, ShedReason, ShedResponse, SystemOptions},
};

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

    use crate::http::Error;

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

    #[derive(Clone, Debug, Default)]
    struct StubVals {
        cpu: f64,
        memory: f64,
        load: (f64, f64, f64),
        /// Which measurement should fail: 0 - CPU, 1 - memory, 2 - load average
        fail: Option<u8>,
        /// Number of measurement rounds started
        rounds: usize,
    }

    #[derive(Clone, Debug)]
    struct StubSys(Arc<Mutex<StubVals>>);

    impl StubSys {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(StubVals::default())))
        }

        fn set(&self, f: impl FnOnce(&mut StubVals)) {
            f(&mut self.0.lock().unwrap());
        }

        fn rounds(&self) -> usize {
            self.0.lock().unwrap().rounds
        }
    }

    #[async_trait]
    impl GetsSystemInfo for StubSys {
        async fn cpu_usage(&self) -> Result<f64, Error> {
            let mut v = self.0.lock().unwrap();
            v.rounds += 1;
            if v.fail == Some(0) {
                return Err(anyhow::anyhow!("cpu boom").into());
            }
            Ok(v.cpu)
        }

        fn memory_usage(&self) -> Result<f64, Error> {
            let v = self.0.lock().unwrap();
            if v.fail == Some(1) {
                return Err(anyhow::anyhow!("memory boom").into());
            }
            Ok(v.memory)
        }

        fn load_avg(&self) -> Result<(f64, f64, f64), Error> {
            let v = self.0.lock().unwrap();
            if v.fail == Some(2) {
                return Err(anyhow::anyhow!("loadavg boom").into());
            }
            Ok(v.load)
        }
    }

    /// Options with only the CPU threshold set
    const fn cpu_opts(cpu: f64) -> SystemOptions {
        SystemOptions {
            cpu: Some(cpu),
            memory: None,
            loadavg_1: None,
            loadavg_5: None,
            loadavg_15: None,
        }
    }

    #[tokio::test]
    async fn test_system_thresholds_are_strict() {
        let sys = StubSys::new();
        let opts = SystemOptions {
            cpu: Some(0.5),
            memory: Some(0.8),
            loadavg_1: Some(4.0),
            loadavg_5: None,
            loadavg_15: None,
        };
        // EWMA alpha of 1.0 makes the average report exactly the last measurement
        let state = State::new(1.0, opts, sys.clone());

        // Sitting exactly at the thresholds is not an overload.
        // The 5/15min load averages are huge, but they have no threshold set.
        sys.set(|v| {
            v.cpu = 0.5;
            v.memory = 0.8;
            v.load = (4.0, 1000.0, 1000.0);
        });
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), None);

        // The tiniest bit above is
        sys.set(|v| v.cpu = 0.5 + f64::EPSILON);
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::CPU));

        sys.set(|v| {
            v.cpu = 0.5;
            v.memory = 0.80001;
        });
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::Memory));

        sys.set(|v| {
            v.memory = 0.8;
            v.load.0 = 4.00001;
        });
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::LoadAvg));

        sys.set(|v| v.load.0 = 4.0);
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), None);
    }

    #[tokio::test]
    async fn test_system_unset_thresholds_never_shed() {
        let sys = StubSys::new();
        let opts = SystemOptions {
            cpu: None,
            memory: None,
            loadavg_1: None,
            loadavg_5: None,
            loadavg_15: None,
        };
        let state = State::new(1.0, opts, sys.clone());

        sys.set(|v| {
            v.cpu = 1.0;
            v.memory = 1.0;
            v.load = (1000.0, 1000.0, 1000.0);
        });
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), None);
    }

    #[tokio::test]
    async fn test_system_evaluate_precedence() {
        let sys = StubSys::new();
        let opts = SystemOptions {
            cpu: Some(0.5),
            memory: Some(0.5),
            loadavg_1: Some(0.5),
            loadavg_5: Some(0.5),
            loadavg_15: Some(0.5),
        };
        let state = State::new(1.0, opts, sys.clone());

        // Everything is over its threshold -> CPU is reported
        sys.set(|v| {
            v.cpu = 1.0;
            v.memory = 1.0;
            v.load = (1.0, 1.0, 1.0);
        });
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::CPU));

        // CPU is fine -> memory takes precedence over the load averages
        sys.set(|v| v.cpu = 0.0);
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::Memory));

        sys.set(|v| v.memory = 0.0);
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::LoadAvg));

        // Only the 15min average is over the threshold
        sys.set(|v| v.load = (0.0, 0.0, 1.0));
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::LoadAvg));
    }

    #[tokio::test]
    async fn test_system_ewma_smooths_spikes() {
        let sys = StubSys::new();
        let state = State::new(0.5, cpu_opts(0.5), sys.clone());

        // The first measurement seeds the average
        state.measure().await.unwrap();
        assert_eq!(state.inner.read().unwrap().cpu.get(), Some(0.0));
        assert_eq!(state.is_overloaded(), None);

        // A single spike only moves the average halfway - exactly onto the
        // threshold, which is not enough to start shedding
        sys.set(|v| v.cpu = 1.0);
        state.measure().await.unwrap();
        assert_eq!(state.inner.read().unwrap().cpu.get(), Some(0.5));
        assert_eq!(state.is_overloaded(), None);

        // A sustained spike does
        state.measure().await.unwrap();
        assert_eq!(state.inner.read().unwrap().cpu.get(), Some(0.75));
        assert_eq!(state.is_overloaded(), Some(ShedReason::CPU));

        // ... and it recovers once the load goes away
        sys.set(|v| v.cpu = 0.0);
        state.measure().await.unwrap();
        assert_eq!(state.inner.read().unwrap().cpu.get(), Some(0.375));
        assert_eq!(state.is_overloaded(), None);
    }

    #[tokio::test]
    async fn test_system_shed_decision_is_a_snapshot() {
        let sys = StubSys::new();
        let state = Arc::new(State::new(1.0, cpu_opts(0.5), sys.clone()));
        let mut shedder = SystemLoadShedder::new(StubService, state.clone());

        // Nothing was measured yet -> no shedding
        assert_eq!(
            shedder.call(Duration::ZERO).await.unwrap(),
            ShedResponse::Inner(())
        );

        sys.set(|v| v.cpu = 1.0);
        state.measure().await.unwrap();
        assert_eq!(
            shedder.call(Duration::ZERO).await.unwrap(),
            ShedResponse::Overload(ShedReason::CPU)
        );

        // The load is gone, but requests keep being shed until the next measurement
        sys.set(|v| v.cpu = 0.0);
        assert_eq!(
            shedder.call(Duration::ZERO).await.unwrap(),
            ShedResponse::Overload(ShedReason::CPU)
        );

        state.measure().await.unwrap();
        assert_eq!(
            shedder.call(Duration::ZERO).await.unwrap(),
            ShedResponse::Inner(())
        );
    }

    #[tokio::test]
    async fn test_system_measure_errors_keep_the_last_verdict() {
        let sys = StubSys::new();
        let state = State::new(1.0, cpu_opts(0.5), sys.clone());

        for (which, msg) in [(0u8, "cpu boom"), (1, "memory boom"), (2, "loadavg boom")] {
            sys.set(|v| v.fail = Some(which));
            let err = state.measure().await.unwrap_err();
            assert!(err.to_string().contains(msg), "{err}");
            // Nothing was recorded at all
            assert_eq!(state.is_overloaded(), None);
            assert_eq!(state.inner.read().unwrap().cpu.get(), None);
        }

        // Get overloaded and then start failing: the last verdict sticks around
        sys.set(|v| {
            v.fail = None;
            v.cpu = 1.0;
        });
        state.measure().await.unwrap();
        assert_eq!(state.is_overloaded(), Some(ShedReason::CPU));

        sys.set(|v| {
            v.fail = Some(1);
            v.cpu = 0.0;
        });
        assert!(state.measure().await.is_err());
        assert_eq!(state.is_overloaded(), Some(ShedReason::CPU));
        assert_eq!(state.inner.read().unwrap().cpu.get(), Some(1.0));
    }

    // No sockets involved, so the paused clock is safe here
    #[tokio::test(start_paused = true)]
    async fn test_system_run_measures_every_second() {
        let sys = StubSys::new();
        sys.set(|v| v.cpu = 1.0);
        let state = Arc::new(State::new(1.0, cpu_opts(0.5), sys.clone()));

        let bg = tokio::spawn({
            let state = state.clone();
            async move { state.run().await }
        });

        // Measurements at 0s, 1s, 2s and 3s
        tokio::time::sleep(Duration::from_millis(3500)).await;
        assert_eq!(sys.rounds(), 4);
        assert_eq!(state.is_overloaded(), Some(ShedReason::CPU));

        bg.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn test_system_run_survives_measurement_errors() {
        let sys = StubSys::new();
        sys.set(|v| {
            v.cpu = 1.0;
            v.fail = Some(0);
        });
        let state = Arc::new(State::new(1.0, cpu_opts(0.5), sys.clone()));

        let bg = tokio::spawn({
            let state = state.clone();
            async move { state.run().await }
        });

        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(sys.rounds(), 3);
        assert_eq!(state.is_overloaded(), None);

        // The loop is still running and picks the measurements up once they work
        sys.set(|v| v.fail = None);
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(sys.rounds(), 4);
        assert_eq!(state.is_overloaded(), Some(ShedReason::CPU));

        bg.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn test_system_layer() {
        let sys = StubSys::new();
        sys.set(|v| v.cpu = 1.0);
        let layer = SystemLoadShedderLayer::new(1.0, cpu_opts(0.5), sys.clone());
        let mut shedder = layer.layer(StubService);

        // The spawned measurement task didn't run yet
        assert_eq!(sys.rounds(), 0);
        assert_eq!(
            shedder.call(Duration::ZERO).await.unwrap(),
            ShedResponse::Inner(())
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(sys.rounds(), 1);
        assert_eq!(
            shedder.call(Duration::ZERO).await.unwrap(),
            ShedResponse::Overload(ShedReason::CPU)
        );
    }

    #[test]
    fn test_real_system_info() {
        let sys = SystemInfo::default();

        // Some memory is always in use and some is always free
        let mem = sys.memory_usage().expect("unable to measure memory usage");
        assert!(mem > 0.0 && mem < 1.0, "memory usage out of range: {mem}");

        let (l1, l5, l15) = sys.load_avg().expect("unable to measure load average");
        let check = |v: f64| assert!(v.is_finite() && v >= 0.0, "bogus load average: {v}");
        check(l1);
        check(l5);
        check(l15);
    }
}
