use std::{
    fmt::{Debug, Display},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use async_trait::async_trait;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use scopeguard::defer;
use strum::{Display, EnumString};

/// Calculates Greatest Common Denominator
const fn calc_gcd(x: isize, y: isize) -> isize {
    let mut t: isize;
    let mut a = x;
    let mut b = y;

    loop {
        t = a % b;
        if t > 0 {
            a = b;
            b = t;
        } else {
            return b;
        }
    }
}

#[derive(Clone, Debug)]
pub struct Metrics {
    inflight: IntGaugeVec,
    requests: IntCounterVec,
    duration: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            inflight: register_int_gauge_vec_with_registry!(
                format!("distributor_inflight"),
                format!("Stores the current number of in-flight requests"),
                &["target"],
                registry
            )
            .unwrap(),

            requests: register_int_counter_vec_with_registry!(
                format!("distributor_requests"),
                format!("Counts the number of requests and results"),
                &["target", "result"],
                registry
            )
            .unwrap(),

            duration: register_histogram_vec_with_registry!(
                format!("distributor_duration"),
                format!("Records the duration of requests in seconds"),
                &["target"],
                [0.01, 0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2].to_vec(),
                registry
            )
            .unwrap(),
        }
    }
}

/// Distribution strategy to use
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, EnumString)]
pub enum Strategy {
    #[strum(serialize = "wrr")]
    WeightedRoundRobin,
    #[strum(serialize = "lor")]
    LeastOutstandingRequests,
}

/// Backend that represents a target that receives the request
#[derive(Debug)]
pub struct Backend<T> {
    backend: T,
    name: String,
    weight: usize,
    inflight: AtomicUsize,
}

impl<T: Display + Send + Sync> Backend<T> {
    pub fn new(backend: T, weight: usize) -> Self {
        Self {
            name: backend.to_string(),
            backend,
            weight,
            inflight: AtomicUsize::new(0),
        }
    }
}

/// Trait that executes the requests.
/// Akin to Tower's Service, but generic over backend.
#[async_trait]
pub trait ExecutesRequest<T>: Send + Sync + Debug {
    type Request;
    type Response;
    type Error;

    async fn execute(&self, backend: &T, req: Self::Request)
    -> Result<Self::Response, Self::Error>;
}

#[derive(Debug)]
struct Wrr {
    n: isize,
    i: isize,
    gcd: isize,
    max_weight: isize,
    curr_weight: isize,
}

impl Wrr {
    fn new<T>(backends: &[Backend<T>]) -> Self {
        let mut gcd = 0;
        let mut max_weight = 0;
        for v in backends.iter() {
            gcd = calc_gcd(gcd, v.weight as isize);

            if v.weight > max_weight {
                max_weight = v.weight;
            }
        }

        Self {
            n: backends.len() as isize,
            i: -1,
            gcd,
            max_weight: max_weight as isize,
            curr_weight: 0,
        }
    }
}

/// Distributes the requests over backends using the given `Strategy`
#[derive(Debug)]
pub struct Distributor<T, RQ = (), RS = (), E = ()> {
    backends: Vec<Backend<T>>,
    strategy: Strategy,
    executor: Arc<dyn ExecutesRequest<T, Request = RQ, Response = RS, Error = E>>,
    wrr: Mutex<Wrr>,
    metrics: Metrics,
}

impl<T, RQ, RS, E> Distributor<T, RQ, RS, E>
where
    T: Clone + Display + Send + Sync,
    RQ: Send,
    RS: Send,
    E: Send,
{
    pub fn new(
        backends: &[(T, usize)],
        strategy: Strategy,
        executor: Arc<dyn ExecutesRequest<T, Request = RQ, Response = RS, Error = E>>,
        metrics: Metrics,
    ) -> Self {
        if backends.is_empty() {
            panic!("There must be at least one backend");
        }

        let backends = backends
            .iter()
            .map(|(b, w)| Backend::new(b.clone(), *w))
            .collect::<Vec<_>>();
        let wrr = Wrr::new(&backends);

        Self {
            backends,
            strategy,
            executor,
            wrr: Mutex::new(wrr),
            metrics,
        }
    }

    /// Picks the next backend to execute the request using WRR algorigthm.
    /// Based on http://kb.linuxvirtualserver.org/wiki/Weighted_Round-Robin_Scheduling
    fn next_wrr(&self) -> &Backend<T> {
        let mut wrr = self.wrr.lock().unwrap();

        loop {
            wrr.i = (wrr.i + 1) % wrr.n;
            if wrr.i == 0 {
                wrr.curr_weight -= wrr.gcd;
                if wrr.curr_weight <= 0 {
                    wrr.curr_weight = wrr.max_weight;
                }
            }

            if (self.backends[wrr.i as usize].weight as isize) >= wrr.curr_weight {
                return &self.backends[wrr.i as usize];
            }
        }
    }

    /// Picks the next backend to execute the request using Least Outstanding Requests algorigthm.
    fn next_lor(&self) -> &Backend<T> {
        self.backends
            .iter()
            .min_by_key(|x| x.inflight.load(Ordering::SeqCst))
            .unwrap()
    }

    /// Execute the request using the next server picked by selected algorithm
    pub async fn execute(&self, request: RQ) -> Result<RS, E> {
        let backend = match self.strategy {
            Strategy::LeastOutstandingRequests => self.next_lor(),
            Strategy::WeightedRoundRobin => self.next_wrr(),
        };

        backend.inflight.fetch_add(1, Ordering::SeqCst);
        self.metrics
            .inflight
            .with_label_values(&[&backend.name])
            .inc();

        defer! {
            backend.inflight.fetch_sub(1, Ordering::SeqCst);
            self.metrics.inflight.with_label_values(&[&backend.name]).dec();
        }

        let start = Instant::now();
        let res = self.executor.execute(&backend.backend, request).await;
        self.metrics
            .duration
            .with_label_values(&[&backend.name])
            .observe(start.elapsed().as_secs_f64());

        self.metrics
            .requests
            .with_label_values(&[
                backend.name.as_str(),
                if res.is_ok() { "ok" } else { "fail" },
            ])
            .inc();

        res
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::{collections::HashMap, time::Duration};

    use tokio::task::JoinSet;

    use super::*;

    #[derive(Debug)]
    pub struct TestExecutor(pub Duration, pub Mutex<HashMap<String, usize>>);

    #[async_trait]
    impl ExecutesRequest<String> for TestExecutor {
        type Error = ();
        type Request = ();
        type Response = ();

        async fn execute(
            &self,
            backend: &String,
            _req: Self::Request,
        ) -> Result<Self::Response, Self::Error> {
            *self.1.lock().unwrap().entry(backend.clone()).or_insert(0) += 1;
            if self.0 > Duration::ZERO {
                tokio::time::sleep(self.0).await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_distributor_wrr() {
        let backends = vec![
            ("foo".to_string(), 2),
            ("bar".to_string(), 3),
            ("baz".to_string(), 5),
        ];

        let executor = Arc::new(TestExecutor(Duration::ZERO, Mutex::new(HashMap::new())));
        let metrics = Metrics::new(&Registry::new());
        let d = Distributor::new(
            &backends,
            Strategy::WeightedRoundRobin,
            executor.clone(),
            metrics,
        );

        // Do 1k backend selections
        for _ in 0..1000 {
            let _ = d.execute(()).await;
        }

        // Make sure that we get the distribution according to the weights
        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 200);
        assert_eq!(h["bar"], 300);
        assert_eq!(h["baz"], 500);
        drop(h)
    }

    #[tokio::test]
    async fn test_distributor_lor() {
        let backends = vec![
            ("foo".to_string(), 2),
            ("bar".to_string(), 3),
            ("baz".to_string(), 5),
        ];

        let executor = Arc::new(TestExecutor(
            Duration::from_secs(1),
            Mutex::new(HashMap::new()),
        ));

        let metrics = Metrics::new(&Registry::new());
        let d = Arc::new(Distributor::new(
            &backends,
            Strategy::LeastOutstandingRequests,
            executor.clone(),
            metrics,
        ));

        let mut js = JoinSet::new();
        // Do 1k backend selections
        for _ in 0..60 {
            let d = d.clone();
            js.spawn(async move {
                let _ = d.execute(()).await;
            });
        }

        js.join_all().await;

        // Make sure that we get even distribution since the requests are accumulated on each node evenly
        // due to sleep
        let h = executor.1.lock().unwrap();
        assert_eq!(h["foo"], 20);
        assert_eq!(h["bar"], 20);
        assert_eq!(h["baz"], 20);
        drop(h)
    }
}
