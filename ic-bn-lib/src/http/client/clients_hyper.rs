use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::RandomState;
use async_trait::async_trait;
use axum::body::Body as AxumBody;
use http::{Request, Response, uri::Scheme};
use http_body::Body;
use hyper_rustls::{FixedServerNameResolver, HttpsConnector};
use hyper_util::{
    client::legacy::{Client as ClientHyper, connect::HttpConnector},
    rt::{TokioExecutor, TokioTimer},
};
use moka::sync::{Cache, CacheBuilder};
use prometheus::Registry;
use rustls::pki_types::DnsName;
use scopeguard::defer;

use super::Metrics;
use crate::{
    dns::{resolvers::CloneableHyperDnsResolver, resolvers::Resolver},
    http::{
        Error,
        client::{ClientHttp, ClientOptions, HttpVersion},
    },
};

/// Hyper-based client with a generic body and resolver
#[derive(Debug, Clone)]
pub struct HyperClient<B, R = Resolver> {
    cli: ClientHyper<HttpsConnector<HttpConnector<R>>, B>,
}

impl<B> Default for HyperClient<B>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn default() -> Self {
        Self::new(ClientOptions::default(), Resolver::default())
    }
}

/// Creates a Hyper client from provided options & resolver
pub fn new<B, R>(
    opts: ClientOptions,
    resolver: R,
) -> ClientHyper<HttpsConnector<HttpConnector<R>>, B>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    let mut http_conn = HttpConnector::new_with_resolver(resolver);
    http_conn.set_connect_timeout(Some(opts.timeout_connect));
    http_conn.set_keepalive(opts.tcp_keepalive_delay);
    http_conn.set_keepalive_interval(opts.tcp_keepalive_interval);
    http_conn.set_keepalive_retries(opts.tcp_keepalive_retries);
    http_conn.enforce_http(false);
    http_conn.set_nodelay(true);
    http_conn.set_reuse_address(true);
    http_conn.set_happy_eyeballs_timeout(Some(opts.happy_eyeballs_timeout));

    let builder = HttpsConnector::<HttpConnector>::builder();
    let mut builder = if let Some(mut v) = opts.tls_config {
        // Hyper is sad when we set our ALPN
        v.alpn_protocols = vec![];
        builder.with_tls_config(v)
    } else {
        builder.with_platform_verifier()
    }
    .https_or_http();

    if let Some(v) = opts.tls_fixed_name {
        let name = DnsName::try_from(v).expect("able to parse as DNSName");
        builder = builder.with_server_name_resolver(FixedServerNameResolver::new(
            rustls::pki_types::ServerName::DnsName(name),
        ))
    }

    let https_conn = match opts.http_version {
        HttpVersion::Http1 => builder.enable_http1().wrap_connector(http_conn),
        HttpVersion::Http2 => builder.enable_http2().wrap_connector(http_conn),
        HttpVersion::All => builder.enable_all_versions().wrap_connector(http_conn),
    };

    let mut builder = ClientHyper::builder(TokioExecutor::new());
    builder
        .http2_adaptive_window(true)
        .http2_keep_alive_interval(opts.http2_keepalive)
        .http2_keep_alive_while_idle(opts.http2_keepalive_idle)
        .pool_idle_timeout(opts.pool_idle_timeout)
        .pool_timer(TokioTimer::new())
        .timer(TokioTimer::new())
        .retry_canceled_requests(true);

    if let Some(v) = opts.http2_keepalive_timeout {
        builder.http2_keep_alive_timeout(v);
    }

    if let Some(v) = opts.pool_idle_max {
        builder.pool_max_idle_per_host(v);
    }

    builder.build(https_conn)
}

impl<B, R> HyperClient<B, R>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    pub fn new(opts: ClientOptions, resolver: R) -> Self {
        Self {
            cli: new(opts, resolver),
        }
    }
}

#[async_trait]
impl<B, R> ClientHttp<B> for HyperClient<B, R>
where
    B: Body + Send + 'static + Unpin + Debug,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    async fn execute(&self, req: Request<B>) -> Result<Response<AxumBody>, Error> {
        let resp = self
            .cli
            .request(req)
            .await
            .map_err(Error::HyperClientError)?;

        let (parts, body) = resp.into_parts();
        let body = AxumBody::new(body);
        Ok(Response::from_parts(parts, body))
    }
}

/// Client that pools a defined number of `HyperClient`s and picks the least loaded one for the next request.
#[derive(Debug, Clone)]
pub struct HyperClientLeastLoaded<B, R = Resolver> {
    inner: Arc<Vec<HyperClientLeastLoadedInner<B, R>>>,
    metrics: Option<Metrics>,
}

#[derive(Debug, Clone)]
struct HyperClientLeastLoadedInner<B, R = Resolver> {
    cli: HyperClient<B, R>,
    outstanding: Cache<String, Arc<AtomicUsize>, RandomState>,
}

impl<B, R> HyperClientLeastLoaded<B, R>
where
    B: Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    pub fn new(
        opts: ClientOptions,
        resolver: R,
        count: usize,
        registry: Option<&Registry>,
    ) -> Self {
        let inner = (0..count)
            .map(|_| HyperClientLeastLoadedInner {
                cli: HyperClient::new(opts.clone(), resolver.clone()),
                // Creates a cache with some sensible max capacity to hold target hosts.
                // If the host isn't contacted in 10min then we remove it.
                outstanding: CacheBuilder::new(16384)
                    .time_to_idle(Duration::from_secs(600))
                    .build_with_hasher(RandomState::default()),
            })
            .collect::<Vec<_>>();

        Self {
            inner: Arc::new(inner),
            metrics: registry.map(Metrics::new),
        }
    }
}

#[async_trait]
impl<B, R> ClientHttp<B> for HyperClientLeastLoaded<B, R>
where
    B: Body + Send + 'static + Unpin + Debug,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: CloneableHyperDnsResolver,
{
    async fn execute(&self, req: http::Request<B>) -> Result<Response<AxumBody>, Error> {
        let uri = req.uri();
        let host = uri.host().unwrap_or_default();
        let port = uri.port_u16().unwrap_or_else(|| {
            // match doesn't work here
            if uri.scheme() == Some(&Scheme::HTTPS) {
                443
            } else if uri.scheme() == Some(&Scheme::HTTP) {
                80
            } else {
                0
            }
        });
        let host = format!("{host}:{port}");

        let labels = &[&host];

        self.metrics
            .as_ref()
            .inspect(|x| x.requests.with_label_values(labels).inc());

        // Select the client with least outstanding requests for the given host
        let (cli, counter) = self
            .inner
            .iter()
            .map(|x| {
                (
                    &x.cli,
                    // Get an atomic counter for the given host or create a new one
                    x.outstanding
                        .get_with_by_ref(&host, || Arc::new(AtomicUsize::new(0))),
                )
            })
            .min_by_key(|x| x.1.load(Ordering::SeqCst))
            .unwrap();

        // The future can be cancelled so we have to use defer to make sure the counter is decreased
        defer! {
            counter.fetch_sub(1, Ordering::SeqCst);
            self.metrics
                .as_ref()
                .inspect(|x| x.requests_inflight.with_label_values(labels).dec());
        }

        counter.fetch_add(1, Ordering::SeqCst);
        self.metrics
            .as_ref()
            .inspect(|x| x.requests_inflight.with_label_values(labels).inc());

        // Execute the request & observe duration
        let start = Instant::now();
        let result = cli.execute(req).await;
        self.metrics.as_ref().inspect(|x| {
            x.request_duration
                .with_label_values(labels)
                .observe(start.elapsed().as_secs_f64())
        });

        result
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::{
        Router,
        body::to_bytes,
        extract::{ConnectInfo, Request as AxumRequest, State},
        response::{IntoResponse, Response as AxumResponse},
        routing::{any, get},
    };
    use http::{Method, StatusCode, Version};
    use prometheus::proto::MetricFamily;
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{dns::resolvers::StaticResolver, tls::verify::NoopServerCertVerifier};

    /// Body type used by the tests: it's the default `ClientHttp` response body too.
    type TestClient = HyperClient<AxumBody, StaticResolver>;
    type TestClientLL = HyperClientLeastLoaded<AxumBody, StaticResolver>;

    /// Mock server state: lets a test park requests in-flight and count arrivals.
    struct MockState {
        /// Incremented as soon as `/slow` is entered, before it blocks.
        entered: AtomicUsize,
        /// `/slow` waits here; the test releases it by adding permits.
        gate: Semaphore,
    }

    impl MockState {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entered: AtomicUsize::new(0),
                gate: Semaphore::new(0),
            })
        }
    }

    async fn hello() -> AxumResponse {
        ([("x-mock", "yes")], "hello-body").into_response()
    }

    async fn teapot() -> AxumResponse {
        (StatusCode::IM_A_TEAPOT, "teapot-body").into_response()
    }

    /// Reflects what the server actually received back into response headers.
    async fn echo(req: AxumRequest) -> AxumResponse {
        let method = req.method().as_str().to_owned();
        let version = format!("{:?}", req.version());
        let probe = req
            .headers()
            .get("x-probe")
            .map_or_else(|| "absent".to_owned(), |v| v.to_str().unwrap().to_owned());
        let host = req
            .headers()
            .get(http::header::HOST)
            .map_or_else(|| "absent".to_owned(), |v| v.to_str().unwrap().to_owned());
        let ua = req
            .headers()
            .get(http::header::USER_AGENT)
            .map_or_else(|| "absent".to_owned(), |v| v.to_str().unwrap().to_owned());
        let body = to_bytes(req.into_body(), 64 * 1024).await.unwrap();

        (
            [
                ("x-seen-method", method),
                ("x-seen-version", version),
                ("x-seen-probe", probe),
                ("x-seen-host", host),
                ("x-seen-ua", ua),
            ],
            body,
        )
            .into_response()
    }

    /// Returns the client-side socket address, which identifies the TCP connection used.
    async fn peer(req: AxumRequest) -> AxumResponse {
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| "absent".to_owned(), |x| x.0.to_string())
            .into_response()
    }

    async fn slow(State(st): State<Arc<MockState>>) -> AxumResponse {
        st.entered.fetch_add(1, Ordering::SeqCst);
        // `forget()` so that one added permit releases exactly one waiter.
        st.gate.acquire().await.unwrap().forget();
        "slow-ok".into_response()
    }

    fn mock_router(state: Arc<MockState>) -> Router {
        Router::new()
            .route("/hello", get(hello))
            .route("/teapot", get(teapot))
            .route("/peer", get(peer))
            .route("/slow", get(slow))
            .route("/echo", any(echo))
            .with_state(state)
    }

    /// Spawns the mock router over plain HTTP on a random loopback port.
    async fn spawn_http_mock_server(state: Arc<MockState>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(
                listener,
                mock_router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        addr
    }

    /// Finds a loopback port that nothing is listening on by binding and immediately releasing it.
    fn closed_port() -> SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    }

    /// A `rustls::ClientConfig` that accepts anything. Built with an explicit provider so it
    /// doesn't depend on a process-wide default being installed.
    fn insecure_tls_config() -> rustls::ClientConfig {
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier::default()))
        .with_no_client_auth()
    }

    /// Options that never touch the platform certificate store.
    fn opts() -> ClientOptions {
        ClientOptions {
            tls_config: Some(insecure_tls_config()),
            timeout_connect: Duration::from_secs(2),
            ..Default::default()
        }
    }

    fn empty_resolver() -> StaticResolver {
        StaticResolver::new([])
    }

    fn get_req(uri: impl AsRef<str>) -> Request<AxumBody> {
        Request::builder()
            .uri(uri.as_ref())
            .body(AxumBody::empty())
            .unwrap()
    }

    async fn read_body(body: AxumBody) -> String {
        String::from_utf8(to_bytes(body, 64 * 1024).await.unwrap().to_vec()).unwrap()
    }

    fn header(resp: &Response<AxumBody>, name: &str) -> String {
        resp.headers()
            .get(name)
            .unwrap_or_else(|| panic!("header {name} is missing"))
            .to_str()
            .unwrap()
            .to_owned()
    }

    // ---------------------------------------------------------------------------------------
    // Plain HTTP
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn plain_http_returns_status_headers_and_body() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(opts(), empty_resolver());

        let resp = cli
            .execute(get_req(format!("http://{addr}/hello")))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(header(&resp, "x-mock"), "yes");
        assert_eq!(read_body(resp.into_body()).await, "hello-body");
    }

    #[tokio::test]
    async fn request_method_headers_and_body_are_forwarded() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(opts(), empty_resolver());

        let req = Request::builder()
            .method(Method::PUT)
            .uri(format!("http://{addr}/echo"))
            .header("x-probe", "probe-value")
            .body(AxumBody::from("request-payload"))
            .unwrap();

        let resp = cli.execute(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header(&resp, "x-seen-method"), "PUT");
        assert_eq!(header(&resp, "x-seen-probe"), "probe-value");
        assert_eq!(header(&resp, "x-seen-host"), addr.to_string());
        assert_eq!(read_body(resp.into_body()).await, "request-payload");
    }

    /// An HTTP error status is a successful call as far as the client is concerned.
    #[tokio::test]
    async fn error_status_is_not_an_error() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(opts(), empty_resolver());

        let resp = cli
            .execute(get_req(format!("http://{addr}/teapot")))
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(read_body(resp.into_body()).await, "teapot-body");
    }

    #[tokio::test]
    async fn connection_refused_maps_to_hyper_client_error() {
        let addr = closed_port();
        let cli: TestClient = HyperClient::new(opts(), empty_resolver());

        let err = cli
            .execute(get_req(format!("http://{addr}/hello")))
            .await
            .expect_err("nothing is listening on that port");

        assert!(
            matches!(err, Error::HyperClientError(_)),
            "unexpected error variant: {err:?}"
        );
    }

    /// A relative URI has neither scheme nor authority, so the client can't dispatch it.
    #[tokio::test]
    async fn relative_uri_maps_to_hyper_client_error() {
        let cli: TestClient = HyperClient::new(opts(), empty_resolver());

        let err = cli
            .execute(get_req("/hello"))
            .await
            .expect_err("a relative URI has no host");

        assert!(
            matches!(err, Error::HyperClientError(_)),
            "unexpected error variant: {err:?}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Resolver plumbing
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn provided_resolver_is_used_for_hostnames() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let resolver = StaticResolver::new([(
            "mock.test".to_owned(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        )]);
        let cli: TestClient = HyperClient::new(opts(), resolver);

        let uri = format!("http://mock.test:{}/echo", addr.port());
        let resp = cli.execute(get_req(&uri)).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        // The Host header carries the name, proving we went through DNS rather than an IP literal
        assert_eq!(
            header(&resp, "x-seen-host"),
            format!("mock.test:{}", addr.port())
        );
    }

    #[tokio::test]
    async fn unresolvable_hostname_maps_to_hyper_client_error() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(opts(), empty_resolver());

        let uri = format!("http://mock.test:{}/hello", addr.port());
        let err = cli
            .execute(get_req(&uri))
            .await
            .expect_err("the resolver knows no names");

        assert!(
            matches!(err, Error::HyperClientError(_)),
            "unexpected error variant: {err:?}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Connection pooling
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn connections_are_pooled_by_default() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(opts(), empty_resolver());
        let uri = format!("http://{addr}/peer");

        let first = read_body(cli.execute(get_req(&uri)).await.unwrap().into_body()).await;
        let second = read_body(cli.execute(get_req(&uri)).await.unwrap().into_body()).await;

        assert_ne!(first, "absent");
        assert_eq!(
            first, second,
            "the second request should have reused the pooled connection"
        );
    }

    #[tokio::test]
    async fn pool_idle_max_zero_disables_pooling() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(
            ClientOptions {
                pool_idle_max: Some(0),
                ..opts()
            },
            empty_resolver(),
        );
        let uri = format!("http://{addr}/peer");

        let first = read_body(cli.execute(get_req(&uri)).await.unwrap().into_body()).await;
        let second = read_body(cli.execute(get_req(&uri)).await.unwrap().into_body()).await;

        assert_ne!(first, "absent");
        assert_ne!(
            first, second,
            "with no idle slots each request needs a fresh connection"
        );
    }

    /// `pool_idle_timeout` has to be wired through: an idle connection is dropped once
    /// it expires, so the next request can't reuse it.
    #[tokio::test]
    async fn pool_idle_timeout_expires_idle_connections() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(
            ClientOptions {
                pool_idle_timeout: Some(Duration::from_millis(50)),
                ..opts()
            },
            empty_resolver(),
        );
        let uri = format!("http://{addr}/peer");

        let first = read_body(cli.execute(get_req(&uri)).await.unwrap().into_body()).await;
        // Real sleep on purpose: the pool reaper runs on the Tokio timer and the
        // connection underneath is a real socket, so the clock must not be paused.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let second = read_body(cli.execute(get_req(&uri)).await.unwrap().into_body()).await;

        assert_ne!(first, "absent");
        assert_ne!(
            first, second,
            "the idle connection should have expired before the second request"
        );
    }

    // ---------------------------------------------------------------------------------------
    // `ClientOptions` fields this client does not implement
    //
    // The Reqwest client honours `user_agent`, `timeout`, `timeout_read` and `dns_overrides`;
    // the Hyper one silently drops all four. Pin the asymmetry down so it can't change
    // unnoticed in either direction.
    // ---------------------------------------------------------------------------------------

    #[tokio::test]
    async fn user_agent_option_is_not_applied() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(
            ClientOptions {
                user_agent: "test-agent/1.0".into(),
                ..opts()
            },
            empty_resolver(),
        );

        let resp = cli
            .execute(get_req(format!("http://{addr}/echo")))
            .await
            .unwrap();

        assert_eq!(header(&resp, "x-seen-ua"), "absent");
    }

    #[tokio::test]
    async fn dns_overrides_option_is_not_applied() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClient = HyperClient::new(
            ClientOptions {
                dns_overrides: vec![("mock.test".to_owned(), addr)],
                ..opts()
            },
            empty_resolver(),
        );

        let err = cli
            .execute(get_req(format!("http://mock.test:{}/hello", addr.port())))
            .await
            .expect_err("dns_overrides is not wired into the hyper connector");

        assert!(
            matches!(err, Error::HyperClientError(_)),
            "unexpected error variant: {err:?}"
        );
    }

    #[tokio::test]
    async fn total_and_read_timeouts_are_not_applied() {
        let state = MockState::new();
        let addr = spawn_http_mock_server(state.clone()).await;
        let cli: TestClient = HyperClient::new(
            ClientOptions {
                timeout: Duration::from_millis(50),
                timeout_read: Duration::from_millis(50),
                ..opts()
            },
            empty_resolver(),
        );

        let uri = format!("http://{addr}/slow");
        let fut = cli.execute(get_req(&uri));

        // Well past both configured timeouts, yet the call is still in flight.
        assert!(
            tokio::time::timeout(Duration::from_millis(700), fut)
                .await
                .is_err(),
            "the hyper client doesn't implement `timeout`/`timeout_read`"
        );
        assert_eq!(state.entered.load(Ordering::SeqCst), 1);

        // Let the parked handler go so the server task isn't left blocked.
        state.gate.add_permits(1);
    }

    // ---------------------------------------------------------------------------------------
    // HyperClientLeastLoaded
    // ---------------------------------------------------------------------------------------

    fn find_family<'a>(families: &'a [MetricFamily], name: &str) -> &'a MetricFamily {
        families
            .iter()
            .find(|x| x.name() == name)
            .unwrap_or_else(|| panic!("metric family {name} not registered"))
    }

    /// Returns the `host` label values present in a metric family.
    fn family_hosts(families: &[MetricFamily], name: &str) -> Vec<String> {
        let mut v = find_family(families, name)
            .get_metric()
            .iter()
            .map(|m| m.get_label()[0].value().to_owned())
            .collect::<Vec<_>>();
        v.sort();
        v
    }

    #[tokio::test]
    async fn least_loaded_works_and_records_metrics() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let registry = Registry::new();
        let cli: TestClientLL =
            HyperClientLeastLoaded::new(opts(), empty_resolver(), 2, Some(&registry));

        let resp = cli
            .execute(get_req(format!("http://{addr}/hello")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(read_body(resp.into_body()).await, "hello-body");

        let families = registry.gather();
        let host = addr.to_string();

        assert_eq!(
            family_hosts(&families, "http_client_requests_total"),
            std::slice::from_ref(&host)
        );

        assert_eq!(
            find_family(&families, "http_client_requests_total").get_metric()[0]
                .get_counter()
                .value(),
            1.0
        );
        // The in-flight gauge is decremented again once the request is done
        assert_eq!(
            find_family(&families, "http_client_requests_inflight").get_metric()[0]
                .get_gauge()
                .value(),
            0.0
        );
        assert_eq!(
            find_family(&families, "http_client_request_duration_sec").get_metric()[0]
                .get_histogram()
                .get_sample_count(),
            1
        );

        // And the per-host outstanding counters are back to zero
        for inner in cli.inner.iter() {
            assert_eq!(
                inner
                    .outstanding
                    .get(host.as_str())
                    .unwrap()
                    .load(Ordering::SeqCst),
                0
            );
        }
    }

    #[tokio::test]
    async fn least_loaded_without_registry_has_no_metrics() {
        let addr = spawn_http_mock_server(MockState::new()).await;
        let cli: TestClientLL = HyperClientLeastLoaded::new(opts(), empty_resolver(), 1, None);

        assert!(cli.metrics.is_none());
        assert_eq!(cli.inner.len(), 1);

        let resp = cli
            .execute(get_req(format!("http://{addr}/hello")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// The metric/counter key is `host:port`, with the port defaulted from the scheme.
    #[tokio::test]
    async fn host_label_defaults_the_port_from_the_scheme() {
        let registry = Registry::new();
        let cli: TestClientLL =
            HyperClientLeastLoaded::new(opts(), empty_resolver(), 1, Some(&registry));

        // The counter is bumped synchronously before any I/O happens, so a 1-tick
        // timeout is enough to observe the label without actually connecting anywhere.
        for uri in [
            "https://example-a.test/x",
            "http://example-b.test/x",
            "ftp://example-c.test/x",
            "/relative",
        ] {
            let _ = tokio::time::timeout(Duration::from_millis(1), cli.execute(get_req(uri))).await;
        }

        assert_eq!(
            family_hosts(&registry.gather(), "http_client_requests_total"),
            [
                ":0".to_owned(),
                "example-a.test:443".to_owned(),
                "example-b.test:80".to_owned(),
                "example-c.test:0".to_owned(),
            ]
        );
    }

    /// Distinct hosts must get distinct outstanding counters.
    #[tokio::test]
    async fn outstanding_counters_are_per_host() {
        let state_a = MockState::new();
        let state_b = MockState::new();
        let addr_a = spawn_http_mock_server(state_a.clone()).await;
        let addr_b = spawn_http_mock_server(state_b.clone()).await;

        // The derived `Clone` on `HyperClientLeastLoaded` requires `B: Clone`, which
        // `axum::body::Body` isn't, so share it through an `Arc` instead.
        let cli: Arc<TestClientLL> = Arc::new(HyperClientLeastLoaded::new(
            opts(),
            empty_resolver(),
            1,
            None,
        ));

        let mut tasks = vec![];
        for (addr, n) in [(addr_a, 2), (addr_b, 1)] {
            for _ in 0..n {
                let cli = cli.clone();
                let uri = format!("http://{addr}/slow");
                tasks.push(tokio::spawn(
                    async move { cli.execute(get_req(&uri)).await },
                ));
            }
        }

        wait_for(|| state_a.entered.load(Ordering::SeqCst) == 2).await;
        wait_for(|| state_b.entered.load(Ordering::SeqCst) == 1).await;

        let outstanding = &cli.inner[0].outstanding;
        assert_eq!(
            outstanding
                .get(addr_a.to_string().as_str())
                .unwrap()
                .load(Ordering::SeqCst),
            2
        );
        assert_eq!(
            outstanding
                .get(addr_b.to_string().as_str())
                .unwrap()
                .load(Ordering::SeqCst),
            1
        );

        state_a.gate.add_permits(2);
        state_b.gate.add_permits(1);
        for t in tasks {
            assert_eq!(
                read_body(t.await.unwrap().unwrap().into_body()).await,
                "slow-ok"
            );
        }
    }

    /// With N inner clients the in-flight requests for a host have to spread evenly.
    #[tokio::test]
    async fn least_loaded_spreads_requests_across_inner_clients() {
        let state = MockState::new();
        let addr = spawn_http_mock_server(state.clone()).await;
        let cli: Arc<TestClientLL> = Arc::new(HyperClientLeastLoaded::new(
            opts(),
            empty_resolver(),
            3,
            None,
        ));

        let mut tasks = vec![];
        for _ in 0..6 {
            let cli = cli.clone();
            let uri = format!("http://{addr}/slow");
            tasks.push(tokio::spawn(
                async move { cli.execute(get_req(&uri)).await },
            ));
        }

        // All six are now parked inside the handler, so all six counters are held
        wait_for(|| state.entered.load(Ordering::SeqCst) == 6).await;

        let host = addr.to_string();
        let counters = cli
            .inner
            .iter()
            .map(|x| {
                x.outstanding
                    .get(host.as_str())
                    .unwrap()
                    .load(Ordering::SeqCst)
            })
            .collect::<Vec<_>>();
        assert_eq!(counters, vec![2, 2, 2], "requests were not spread evenly");

        state.gate.add_permits(6);
        for t in tasks {
            assert_eq!(
                read_body(t.await.unwrap().unwrap().into_body()).await,
                "slow-ok"
            );
        }

        // Everything drained
        let counters = cli
            .inner
            .iter()
            .map(|x| {
                x.outstanding
                    .get(host.as_str())
                    .unwrap()
                    .load(Ordering::SeqCst)
            })
            .collect::<Vec<_>>();
        assert_eq!(counters, vec![0, 0, 0]);
    }

    /// Polls `f` until it's true, failing the test if it never becomes true.
    async fn wait_for(f: impl Fn() -> bool) {
        for _ in 0..2000 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition was not met in time");
    }

    // ---------------------------------------------------------------------------------------
    // TLS
    // ---------------------------------------------------------------------------------------

    mod tls {
        use axum_server::tls_rustls::RustlsConfig;
        use rustls::{RootCertStore, pki_types::ServerName};

        use super::*;
        use crate::{
            tests::{TEST_CERT_1, TEST_KEY_1},
            tls::pem_convert_to_rustls,
        };

        /// Installs the process-level rustls `CryptoProvider`. Idempotent.
        ///
        /// NOTE: `crate::tls::acme::dns::test::support` has an identical helper plus an HTTPS
        /// mock server, but that `test` module is private to `tls::acme::dns`, so it can only
        /// be used from that module's own descendants.
        fn install_crypto_provider() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }

        /// The shared test certificate is self-signed for the single-label name "novg",
        /// so trusting it as a root is enough to verify it as a leaf.
        fn verifying_tls_config() -> rustls::ClientConfig {
            let ck = pem_convert_to_rustls(TEST_KEY_1.as_bytes(), TEST_CERT_1.as_bytes()).unwrap();
            let mut roots = RootCertStore::empty();
            let (added, ignored) = roots.add_parsable_certificates(ck.cert.clone());
            assert_eq!((added, ignored), (1, 0));

            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth()
        }

        /// Serves the mock router over HTTPS on a random loopback port using the shared
        /// self-signed test certificate.
        async fn spawn_tls_mock_server(state: Arc<MockState>) -> SocketAddr {
            install_crypto_provider();

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();

            let config = RustlsConfig::from_pem(
                TEST_CERT_1.as_bytes().to_vec(),
                TEST_KEY_1.as_bytes().to_vec(),
            )
            .await
            .unwrap();

            tokio::spawn(async move {
                axum_server::from_tcp_rustls(listener, config)
                    .unwrap()
                    .serve(mock_router(state).into_make_service())
                    .await
                    .unwrap();
            });

            addr
        }

        #[tokio::test]
        async fn https_request_works() {
            let addr = spawn_tls_mock_server(MockState::new()).await;
            let cli: TestClient = HyperClient::new(opts(), empty_resolver());

            let resp = cli
                .execute(get_req(format!("https://{addr}/hello")))
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(header(&resp, "x-mock"), "yes");
            assert_eq!(read_body(resp.into_body()).await, "hello-body");
        }

        /// The default options use the platform verifier, which must reject the
        /// self-signed test certificate.
        #[tokio::test]
        async fn default_client_rejects_self_signed_certificate() {
            let addr = spawn_tls_mock_server(MockState::new()).await;
            let cli: HyperClient<AxumBody> = HyperClient::default();

            let err = tokio::time::timeout(
                Duration::from_secs(30),
                cli.execute(get_req(format!("https://{addr}/hello"))),
            )
            .await
            .expect("verification should not hang")
            .expect_err("the test certificate is not in the platform trust store");

            assert!(
                matches!(err, Error::HyperClientError(_)),
                "unexpected error variant: {err:?}"
            );
        }

        /// `http_version` selects the ALPN protocol offered to the server.
        #[tokio::test]
        async fn http_version_selects_the_negotiated_protocol() {
            let addr = spawn_tls_mock_server(MockState::new()).await;

            for (version, expected) in [
                (HttpVersion::Http1, Version::HTTP_11),
                (HttpVersion::Http2, Version::HTTP_2),
                // The mock server prefers h2 when both are offered
                (HttpVersion::All, Version::HTTP_2),
            ] {
                let cli: TestClient = HyperClient::new(
                    ClientOptions {
                        http_version: version,
                        ..opts()
                    },
                    empty_resolver(),
                );

                let resp = cli
                    .execute(get_req(format!("https://{addr}/echo")))
                    .await
                    .unwrap();

                assert_eq!(resp.version(), expected, "client side, {version}");
                assert_eq!(
                    header(&resp, "x-seen-version"),
                    format!("{expected:?}"),
                    "server side, {version}"
                );
            }
        }

        /// hyper-rustls refuses a `ClientConfig` that already carries ALPN protocols,
        /// so they have to be stripped before it's handed over.
        #[tokio::test]
        async fn alpn_protocols_on_the_supplied_config_are_ignored() {
            let addr = spawn_tls_mock_server(MockState::new()).await;

            let mut tls = insecure_tls_config();
            tls.alpn_protocols = vec![b"totally-bogus".to_vec()];

            let cli: TestClient = HyperClient::new(
                ClientOptions {
                    tls_config: Some(tls),
                    http_version: HttpVersion::Http2,
                    ..opts()
                },
                empty_resolver(),
            );

            let resp = cli
                .execute(get_req(format!("https://{addr}/hello")))
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.version(), Version::HTTP_2);
        }

        /// Without a fixed name the connection is verified against the IP we dialled,
        /// which the test certificate doesn't cover.
        #[tokio::test]
        async fn without_tls_fixed_name_the_uri_host_is_verified() {
            let addr = spawn_tls_mock_server(MockState::new()).await;
            let cli: TestClient = HyperClient::new(
                ClientOptions {
                    tls_config: Some(verifying_tls_config()),
                    ..opts()
                },
                empty_resolver(),
            );

            let err = cli
                .execute(get_req(format!("https://{addr}/hello")))
                .await
                .expect_err("the certificate is not valid for 127.0.0.1");

            assert!(
                matches!(err, Error::HyperClientError(_)),
                "unexpected error variant: {err:?}"
            );
        }

        #[tokio::test]
        async fn tls_fixed_name_overrides_the_verified_name() {
            let addr = spawn_tls_mock_server(MockState::new()).await;
            let cli: TestClient = HyperClient::new(
                ClientOptions {
                    tls_config: Some(verifying_tls_config()),
                    tls_fixed_name: Some("novg".into()),
                    ..opts()
                },
                empty_resolver(),
            );

            let resp = cli
                .execute(get_req(format!("https://{addr}/hello")))
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(read_body(resp.into_body()).await, "hello-body");
        }

        /// A fixed name that the certificate doesn't cover still has to fail.
        #[tokio::test]
        async fn wrong_tls_fixed_name_is_rejected() {
            let addr = spawn_tls_mock_server(MockState::new()).await;
            let cli: TestClient = HyperClient::new(
                ClientOptions {
                    tls_config: Some(verifying_tls_config()),
                    tls_fixed_name: Some("not-novg".into()),
                    ..opts()
                },
                empty_resolver(),
            );

            let err = cli
                .execute(get_req(format!("https://{addr}/hello")))
                .await
                .expect_err("the certificate is only valid for novg");

            assert!(
                matches!(err, Error::HyperClientError(_)),
                "unexpected error variant: {err:?}"
            );
        }

        #[test]
        #[should_panic(expected = "able to parse as DNSName")]
        fn tls_fixed_name_must_be_a_dns_name() {
            // Sanity: the valid name really is accepted by the same conversion
            assert!(ServerName::try_from("novg").is_ok());

            let _ = new::<AxumBody, _>(
                ClientOptions {
                    tls_config: Some(insecure_tls_config()),
                    tls_fixed_name: Some("not a dns name!".into()),
                    ..Default::default()
                },
                empty_resolver(),
            );
        }
    }
}
