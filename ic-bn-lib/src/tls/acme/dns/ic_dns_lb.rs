use std::time::Duration;

use anyhow::{Context, Error, anyhow, bail};
use async_trait::async_trait;
use http::StatusCode;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::tls::acme::{Record, dns::DnsManager};

/// Number of attempts made against a single node before giving up.
const RETRIES: u32 = 5;

/// Base backoff: before attempt `i + 1` (0-based `i`) we sleep `BACKOFF * i`,
/// so a node that always fails is given up on after `BACKOFF * n * (n - 1) / 2`.
const BACKOFF: Duration = Duration::from_millis(250);

pub struct IcDnsLb {
    client: Client,
    base_urls: Vec<Url>,
    token: String,
    retries: u32,
    backoff: Duration,
}

impl IcDnsLb {
    /// Create a new IC-DNS-LB API client with a default HTTP client
    pub fn new(base_urls: Vec<Url>, token: String) -> Result<Self, Error> {
        let client = Client::builder()
            .build()
            .context("failed to initialize HTTP client")?;

        Self::new_with_http_client(base_urls, client, token)
    }

    /// Create a new IC-DNS-LB API client with a provided HTTP client
    pub fn new_with_http_client(
        base_urls: Vec<Url>,
        client: Client,
        token: String,
    ) -> Result<Self, Error> {
        if base_urls.is_empty() {
            bail!("At least one URL must be specified");
        }

        for url in &base_urls {
            if url.cannot_be_a_base() {
                bail!("Invalid URL (cannot be a base)");
            }
        }

        Ok(Self {
            client,
            base_urls,
            token,
            retries: RETRIES,
            backoff: BACKOFF,
        })
    }

    /// Overrides the retry policy. Test-only: production always uses [`RETRIES`] / [`BACKOFF`].
    /// `retries` must be at least 1.
    #[cfg(test)]
    fn with_retry_policy(mut self, retries: u32, backoff: Duration) -> Self {
        assert!(retries >= 1, "at least one attempt must be made");
        self.retries = retries;
        self.backoff = backoff;
        self
    }

    /// Sends a POST request
    async fn post(&self, url: Url, req: AcmeChallengeRequest) -> Result<(), Error> {
        let call = async || -> Result<StatusCode, Error> {
            Ok(self
                .client
                .post(url.clone())
                .bearer_auth(&self.token)
                .json(&req)
                .send()
                .await
                .context("unable to send request")?
                .status())
        };

        // The calls are idempotent - do a few retries
        let mut last_error = None;
        for i in 0..self.retries {
            match call().await {
                Ok(v) => {
                    if !v.is_success() {
                        last_error = Some(anyhow!("bad HTTP status code: {v}"));

                        // Do not retry when it's not a server error
                        if !v.is_server_error() {
                            return Err(last_error.unwrap());
                        }
                    } else {
                        return Ok(());
                    }
                }

                Err(e) => {
                    last_error = Some(e);
                }
            }

            // Back off exponentially
            tokio::time::sleep(self.backoff * i).await;
        }

        Err(last_error.unwrap())
    }
}

/// Request that IC-DNS-LB expects
#[derive(Clone, Serialize, Deserialize)]
struct AcmeChallengeRequest {
    challenge: String,
}

#[async_trait]
impl DnsManager for IcDnsLb {
    async fn create(
        &self,
        zone: &str,
        _name: &str,
        record: Record,
        _ttl: u32,
    ) -> Result<(), Error> {
        let Record::Txt(challenge) = record;

        for url in &self.base_urls {
            let mut url = url.clone();

            // Strip trailing slash if exists & add path
            // SAFETY: cannot-be-a-base is checked in new()
            url.path_segments_mut()
                .unwrap()
                .pop_if_empty()
                .extend(["acme-challenge", "set", zone]);

            self.post(
                url,
                AcmeChallengeRequest {
                    challenge: challenge.clone(),
                },
            )
            .await?;
        }

        Ok(())
    }

    async fn delete(&self, zone: &str, _name: &str, record: &Record) -> Result<(), Error> {
        let Record::Txt(challenge) = record;

        // Try to remove records from all nodes even if some fail
        let mut errors = vec![];
        for url in &self.base_urls {
            let mut url = url.clone();

            // Strip trailing slash if exists & add path
            // SAFETY: cannot-be-a-base is checked in new()
            url.path_segments_mut().unwrap().pop_if_empty().extend([
                "acme-challenge",
                "unset",
                zone,
            ]);

            if let Err(e) = self
                .post(
                    url,
                    AcmeChallengeRequest {
                        challenge: challenge.clone(),
                    },
                )
                .await
            {
                errors.push(e.to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::msg(errors.join(", ")))
        }
    }
}

/// Mocks the IC DNS LB HTTP API (`/acme-challenge/set/{zone}` and `/acme-challenge/unset/{zone}`)
#[cfg(test)]
mod test {
    use std::{
        sync::{Arc, Mutex},
        time::Instant,
    };

    use axum::{
        Json, Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };

    use super::*;
    use crate::tls::acme::dns::test::support::{
        check_bearer_auth, insecure_http_client, install_crypto_provider, spawn_https_mock_server,
    };

    const TOKEN: &str = "test-lb-token";

    /// In-memory state backing one mock IC DNS LB node.
    #[derive(Default)]
    struct MockState {
        // Incremented on every request regardless of outcome, so tests can tell a node
        // apart that was never contacted (e.g. because an earlier node in the list failed)
        // from one that was contacted but rejected the request.
        requests_received: u32,
        set_calls: Vec<(String, String)>,
        unset_calls: Vec<(String, String)>,
        fail_set: bool,
        fail_unset: bool,
        /// Status used to reject a request. `None` means 500, which `post` treats as a
        /// retryable server error; a 4xx here exercises the non-retryable branch.
        fail_status: Option<StatusCode>,
        /// Budget of transient failures: while non-zero it is decremented and the request is
        /// rejected even though the sticky `fail_*` flag is off, so a node can fail a few
        /// times and then start succeeding.
        fail_next: u32,
    }

    /// Decides how to answer the current request; `Some(status)` means reject it.
    /// The transient `fail_next` budget is consumed first, then the sticky flag applies.
    fn take_failure(state: &mut MockState, sticky: bool) -> Option<StatusCode> {
        let status = state
            .fail_status
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        if state.fail_next > 0 {
            state.fail_next -= 1;
            return Some(status);
        }

        sticky.then_some(status)
    }

    type SharedState = Arc<Mutex<MockState>>;

    async fn set_challenge(
        State(state): State<SharedState>,
        Path(zone): Path<String>,
        headers: HeaderMap,
        Json(body): Json<AcmeChallengeRequest>,
    ) -> Response {
        let mut state = state.lock().unwrap();
        state.requests_received += 1;

        if !check_bearer_auth(&headers, TOKEN) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let sticky = state.fail_set;
        if let Some(status) = take_failure(&mut state, sticky) {
            return status.into_response();
        }

        state.set_calls.push((zone, body.challenge));
        drop(state);
        StatusCode::OK.into_response()
    }

    async fn unset_challenge(
        State(state): State<SharedState>,
        Path(zone): Path<String>,
        headers: HeaderMap,
        Json(body): Json<AcmeChallengeRequest>,
    ) -> Response {
        let mut state = state.lock().unwrap();
        state.requests_received += 1;

        if !check_bearer_auth(&headers, TOKEN) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let sticky = state.fail_unset;
        if let Some(status) = take_failure(&mut state, sticky) {
            return status.into_response();
        }

        state.unset_calls.push((zone, body.challenge));
        drop(state);
        StatusCode::OK.into_response()
    }

    fn mock_router(state: SharedState) -> Router {
        Router::new()
            .route("/acme-challenge/set/{zone}", post(set_challenge))
            .route("/acme-challenge/unset/{zone}", post(unset_challenge))
            .with_state(state)
    }

    /// One mock LB node: its in-memory state plus the base URL `IcDnsLb` should be given.
    struct TestNode {
        state: SharedState,
        base_url: Url,
    }

    /// Backoff the tests run with. The production [`BACKOFF`] would add ~2.5s of real
    /// sleeping per failing node, and tokio's `start_paused` cannot be used to
    /// skip it here: these tests drive a real loopback TLS socket, and tokio's auto-advancing
    /// virtual clock fires hyper's connect/handshake/pool-idle timers immediately, tearing the
    /// connection down mid-request. So shrink the backoff instead and keep real time.
    const TEST_BACKOFF: Duration = Duration::ZERO;

    fn client_with_token(base_urls: Vec<Url>, token: &str) -> IcDnsLb {
        client_with_policy(base_urls, token, RETRIES, TEST_BACKOFF)
    }

    fn client_with_policy(
        base_urls: Vec<Url>,
        token: &str,
        retries: u32,
        backoff: Duration,
    ) -> IcDnsLb {
        IcDnsLb::new_with_http_client(base_urls, insecure_http_client(), token.to_string())
            .unwrap()
            .with_retry_policy(retries, backoff)
    }

    /// Boots `n` independent mock IC DNS LB nodes and a matching `IcDnsLb` client pointed at
    /// all of them, mirroring a real deployment where the same challenge is pushed to every
    /// node.
    async fn setup(n: usize) -> (IcDnsLb, Vec<TestNode>) {
        install_crypto_provider();

        let mut nodes = Vec::with_capacity(n);
        for _ in 0..n {
            let state: SharedState = Arc::new(Mutex::new(MockState::default()));
            let base_url = spawn_https_mock_server(mock_router(state.clone())).await;
            nodes.push(TestNode { state, base_url });
        }

        let base_urls = nodes.iter().map(|n| n.base_url.clone()).collect();
        let client = client_with_token(base_urls, TOKEN);

        (client, nodes)
    }

    #[tokio::test]
    async fn create_sends_challenge_to_every_node() {
        let (client, nodes) = setup(3).await;

        client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap();

        for node in &nodes {
            assert_eq!(
                node.state.lock().unwrap().set_calls,
                vec![("example.com".to_string(), "the-token".to_string())]
            );
        }
    }

    #[tokio::test]
    async fn delete_sends_challenge_to_every_node() {
        let (client, nodes) = setup(3).await;

        client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap();

        for node in &nodes {
            assert_eq!(
                node.state.lock().unwrap().unset_calls,
                vec![("example.com".to_string(), "the-token".to_string())]
            );
        }
    }

    #[tokio::test]
    async fn create_errors_when_a_node_returns_bad_status() {
        let (client, nodes) = setup(1).await;
        nodes[0].state.lock().unwrap().fail_set = true;

        let err = client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad HTTP status code"), "{err}");
        assert_eq!(nodes[0].state.lock().unwrap().requests_received, RETRIES);
    }

    #[tokio::test]
    async fn delete_errors_when_a_node_returns_bad_status() {
        let (client, nodes) = setup(1).await;
        nodes[0].state.lock().unwrap().fail_unset = true;

        let err = client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad HTTP status code"), "{err}");
        assert_eq!(nodes[0].state.lock().unwrap().requests_received, RETRIES);
    }

    #[tokio::test]
    async fn create_stops_at_first_failing_node_and_does_not_contact_the_rest() {
        let (client, nodes) = setup(2).await;
        nodes[0].state.lock().unwrap().fail_set = true;

        client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap_err();

        assert_eq!(nodes[0].state.lock().unwrap().requests_received, RETRIES);
        assert_eq!(
            nodes[1].state.lock().unwrap().requests_received,
            0,
            "later nodes must not be contacted once an earlier one fails"
        );
    }

    #[tokio::test]
    async fn delete_contacts_all_nodes_even_if_one_fails() {
        let (client, nodes) = setup(2).await;
        nodes[0].state.lock().unwrap().fail_unset = true;

        client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap_err();

        assert_eq!(nodes[0].state.lock().unwrap().requests_received, RETRIES);
        assert_eq!(nodes[1].state.lock().unwrap().requests_received, 1);
    }

    #[tokio::test]
    async fn create_errors_when_a_node_is_unreachable() {
        install_crypto_provider();

        // Bind and immediately drop the listener: the port is guaranteed free, but nothing
        // is listening on it, so a connection attempt is refused at the TCP level rather than
        // answered with an HTTP error status.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let base_url: Url = format!("https://{addr}/").parse().unwrap();
        let client = client_with_token(vec![base_url], TOKEN);

        let err = client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unable to send request"), "{err}");
    }

    #[tokio::test]
    async fn create_errors_on_wrong_token() {
        let (_client, nodes) = setup(1).await;
        let base_urls = nodes.iter().map(|n| n.base_url.clone()).collect();
        let client = client_with_token(base_urls, "wrong-token");

        let err = client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad HTTP status code"), "{err}");
        assert!(nodes[0].state.lock().unwrap().set_calls.is_empty());
    }

    /// Boots a single mock node whose API is mounted under a path prefix (e.g. as if the LB
    /// were reachable at `https://host/lb-api/...` rather than at the server root), so tests
    /// can check that `IcDnsLb` preserves an existing path prefix in `base_urls` instead of
    /// routing every request at the server root.
    async fn setup_with_path_prefix(prefix: &str) -> (Url, SharedState) {
        install_crypto_provider();

        let state: SharedState = Arc::new(Mutex::new(MockState::default()));
        let router = Router::new().nest(&format!("/{prefix}"), mock_router(state.clone()));
        let root_url = spawn_https_mock_server(router).await;

        (root_url, state)
    }

    #[tokio::test]
    async fn create_preserves_base_url_path_prefix_without_trailing_slash() {
        let (root_url, state) = setup_with_path_prefix("lb-api").await;
        let base_url: Url = format!("{root_url}lb-api").parse().unwrap();
        let client = client_with_token(vec![base_url], TOKEN);

        client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap();

        assert_eq!(
            state.lock().unwrap().set_calls,
            vec![("example.com".to_string(), "the-token".to_string())]
        );
    }

    #[tokio::test]
    async fn create_preserves_base_url_path_prefix_with_trailing_slash() {
        let (root_url, state) = setup_with_path_prefix("lb-api").await;
        let base_url: Url = format!("{root_url}lb-api/").parse().unwrap();
        let client = client_with_token(vec![base_url], TOKEN);

        client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap();

        assert_eq!(
            state.lock().unwrap().set_calls,
            vec![("example.com".to_string(), "the-token".to_string())]
        );
    }

    /// `IcDnsLb` isn't `Debug`, so discard the success value before unwrapping the error.
    fn new_err(base_urls: Vec<Url>) -> Error {
        IcDnsLb::new(base_urls, TOKEN.to_string())
            .map(|_| ())
            .unwrap_err()
    }

    #[test]
    fn new_rejects_an_empty_url_list() {
        let err = new_err(vec![]);
        assert!(
            err.to_string()
                .contains("At least one URL must be specified"),
            "{err}"
        );
    }

    #[test]
    fn new_rejects_a_url_that_cannot_be_a_base() {
        let err = new_err(vec!["mailto:dns@example.com".parse().unwrap()]);
        assert!(err.to_string().contains("cannot be a base"), "{err}");
    }

    /// Every URL is validated, not just the first one - `create`/`delete` unwrap
    /// `path_segments_mut()` for all of them.
    #[test]
    fn new_rejects_when_any_url_cannot_be_a_base() {
        let err = new_err(vec![
            "https://lb1.example.com/".parse().unwrap(),
            "data:text/plain,nope".parse().unwrap(),
        ]);
        assert!(err.to_string().contains("cannot be a base"), "{err}");
    }

    #[test]
    fn new_defaults_to_the_production_retry_policy() {
        // Pinned as literals on purpose. Every other assertion in this module is written in
        // terms of `RETRIES` / `BACKOFF`, so without these two the constants and the whole
        // suite would silently drift together: halving `RETRIES` would stay green everywhere.
        assert_eq!(RETRIES, 5, "production retry count changed");
        assert_eq!(
            BACKOFF,
            Duration::from_millis(250),
            "production backoff changed"
        );

        let lb = IcDnsLb::new(
            vec!["https://lb1.example.com/".parse().unwrap()],
            TOKEN.to_string(),
        )
        .unwrap();

        // ...and the constructor must actually use them.
        assert_eq!(lb.retries, RETRIES);
        assert_eq!(lb.backoff, BACKOFF);
    }

    /// The JSON field name is part of the wire contract with IC-DNS-LB.
    #[test]
    fn acme_challenge_request_round_trips_over_json() {
        let json = serde_json::to_string(&AcmeChallengeRequest {
            challenge: "the-token".to_string(),
        })
        .unwrap();
        assert_eq!(json, r#"{"challenge":"the-token"}"#);

        let back: AcmeChallengeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.challenge, "the-token");
    }

    /// "Do not retry when it's not a server error": a 4xx must fail after a single attempt.
    #[tokio::test]
    async fn create_does_not_retry_a_client_error() {
        let (client, nodes) = setup(1).await;
        {
            let mut state = nodes[0].state.lock().unwrap();
            state.fail_set = true;
            state.fail_status = Some(StatusCode::BAD_REQUEST);
        }

        let err = client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("bad HTTP status code: 400"),
            "{err}"
        );
        assert_eq!(
            nodes[0].state.lock().unwrap().requests_received,
            1,
            "a non-server error must not be retried"
        );
    }

    #[tokio::test]
    async fn delete_does_not_retry_a_client_error() {
        let (client, nodes) = setup(1).await;
        {
            let mut state = nodes[0].state.lock().unwrap();
            state.fail_unset = true;
            state.fail_status = Some(StatusCode::FORBIDDEN);
        }

        let err = client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("bad HTTP status code: 403"),
            "{err}"
        );
        assert_eq!(
            nodes[0].state.lock().unwrap().requests_received,
            1,
            "a non-server error must not be retried"
        );
    }

    /// The calls are idempotent and retried, so a node that fails with 5xx on every attempt
    /// but the last one must still end up with the challenge set.
    #[tokio::test]
    async fn create_succeeds_after_transient_server_errors() {
        let (client, nodes) = setup(1).await;
        nodes[0].state.lock().unwrap().fail_next = RETRIES - 1;

        client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap();

        assert_eq!(nodes[0].state.lock().unwrap().requests_received, RETRIES);
        assert_eq!(
            nodes[0].state.lock().unwrap().set_calls,
            vec![("example.com".to_string(), "the-token".to_string())]
        );
    }

    #[tokio::test]
    async fn delete_succeeds_after_transient_server_errors() {
        let (client, nodes) = setup(1).await;
        nodes[0].state.lock().unwrap().fail_next = RETRIES - 1;

        client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap();

        assert_eq!(nodes[0].state.lock().unwrap().requests_received, RETRIES);
        assert_eq!(
            nodes[0].state.lock().unwrap().unset_calls,
            vec![("example.com".to_string(), "the-token".to_string())]
        );
    }

    /// `delete` collects one error per failing node and joins them, rather than reporting only
    /// the first failure.
    #[tokio::test]
    async fn delete_reports_an_error_for_every_failing_node() {
        let (client, nodes) = setup(2).await;
        for node in &nodes {
            let mut state = node.state.lock().unwrap();
            state.fail_unset = true;
            // 4xx keeps this to exactly one attempt per node, so the message is exact.
            state.fail_status = Some(StatusCode::BAD_REQUEST);
        }

        let err = client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "bad HTTP status code: 400 Bad Request, bad HTTP status code: 400 Bad Request"
        );
        for node in &nodes {
            assert_eq!(node.state.lock().unwrap().requests_received, 1);
        }
    }

    /// `create` aborts on the first failing node, so a healthy node later in the list keeps
    /// whatever it had - but a healthy node *before* it has already been updated.
    #[tokio::test]
    async fn create_keeps_the_challenge_set_on_nodes_before_the_failing_one() {
        let (client, nodes) = setup(3).await;
        {
            let mut state = nodes[1].state.lock().unwrap();
            state.fail_set = true;
            state.fail_status = Some(StatusCode::BAD_REQUEST);
        }

        client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap_err();

        assert_eq!(
            nodes[0].state.lock().unwrap().set_calls,
            vec![("example.com".to_string(), "the-token".to_string())]
        );
        assert!(nodes[1].state.lock().unwrap().set_calls.is_empty());
        assert_eq!(nodes[2].state.lock().unwrap().requests_received, 0);
    }

    /// `post` sleeps `backoff * i` before attempt `i + 1`, so `n` attempts against an
    /// always-failing node take at least `backoff * n * (n - 1) / 2`. Lower bound only: a
    /// sleep can overshoot under load but never returns early. With a flat (non-multiplied)
    /// backoff the same run would only take `backoff * n`.
    #[tokio::test]
    async fn post_backs_off_exponentially_and_honours_the_retry_count() {
        let (_, nodes) = setup(1).await;
        nodes[0].state.lock().unwrap().fail_set = true;

        let retries = 4;
        let backoff = Duration::from_millis(30);
        let client = client_with_policy(vec![nodes[0].base_url.clone()], TOKEN, retries, backoff);

        let start = Instant::now();
        client
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("the-token".into()),
                60,
            )
            .await
            .unwrap_err();
        let elapsed = start.elapsed();

        assert_eq!(nodes[0].state.lock().unwrap().requests_received, retries);
        assert!(
            elapsed >= backoff * (1 + 2 + 3),
            "expected at least {:?} of backoff, took {elapsed:?}",
            backoff * (1 + 2 + 3)
        );
    }

    /// End-to-end lifecycle through the public `DnsManager` trait, fanned out across multiple
    /// nodes: create the challenge everywhere, then remove it everywhere.
    #[tokio::test]
    async fn create_then_delete_round_trip_across_nodes() {
        let (client, nodes) = setup(3).await;
        let manager: &dyn DnsManager = &client;

        manager
            .create(
                "example.com",
                "_acme-challenge",
                Record::Txt("round-trip-token".into()),
                60,
            )
            .await
            .unwrap();

        for node in &nodes {
            assert_eq!(
                node.state.lock().unwrap().set_calls,
                vec![("example.com".to_string(), "round-trip-token".to_string())]
            );
        }

        manager
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("round-trip-token".into()),
            )
            .await
            .unwrap();

        for node in &nodes {
            assert_eq!(
                node.state.lock().unwrap().unset_calls,
                vec![("example.com".to_string(), "round-trip-token".to_string())]
            );
        }
    }
}
