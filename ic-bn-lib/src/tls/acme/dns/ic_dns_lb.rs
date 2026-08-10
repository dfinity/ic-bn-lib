use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::tls::acme::{Record, dns::DnsManager};

pub struct IcDnsLb {
    client: Client,
    base_urls: Vec<Url>,
    token: String,
}

impl IcDnsLb {
    /// Create a new IC-DNS-LB API client with a default HTTP client
    pub fn new(base_urls: Vec<Url>, token: String) -> Result<Self, Error> {
        let client = Client::builder()
            .build()
            .context("failed to initialize HTTP client")?;

        Ok(Self::new_with_http_client(base_urls, client, token))
    }

    /// Create a new IC-DNS-LB API client with a provided HTTP client.
    /// Client needs to set the authentication token itself.
    pub const fn new_with_http_client(base_urls: Vec<Url>, client: Client, token: String) -> Self {
        Self {
            client,
            base_urls,
            token,
        }
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
            url.path_segments_mut()
                .map_err(|()| anyhow!("base URL cannot be used as a base for relative paths"))?
                .pop_if_empty()
                .extend(["acme-challenge", "set", zone]);

            self.client
                .post(url)
                .bearer_auth(&self.token)
                .json(&AcmeChallengeRequest {
                    challenge: challenge.clone(),
                })
                .send()
                .await
                .context("unable to send request")?
                .error_for_status()
                .context("bad HTTP status code")?;
        }

        Ok(())
    }

    async fn delete(&self, zone: &str, _name: &str, record: &Record) -> Result<(), Error> {
        let Record::Txt(challenge) = record;

        for url in &self.base_urls {
            let mut url = url.clone();

            // Strip trailing slash if exists & add path
            url.path_segments_mut()
                .map_err(|()| anyhow!("base URL cannot be used as a base for relative paths"))?
                .pop_if_empty()
                .extend(["acme-challenge", "unset", zone]);

            self.client
                .post(url)
                .bearer_auth(&self.token)
                .json(&AcmeChallengeRequest {
                    challenge: challenge.clone(),
                })
                .send()
                .await
                .context("unable to send request")?
                .error_for_status()
                .context("bad HTTP status code")?;
        }

        Ok(())
    }
}

/// Mocks the IC DNS LB HTTP API (`/acme-challenge/set/{zone}` and `/acme-challenge/unset/{zone}`)
#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

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
        if state.fail_set {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
        if state.fail_unset {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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

    fn client_with_token(base_urls: Vec<Url>, token: &str) -> IcDnsLb {
        IcDnsLb::new_with_http_client(base_urls, insecure_http_client(), token.to_string())
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

        assert_eq!(nodes[0].state.lock().unwrap().requests_received, 1);
        assert_eq!(
            nodes[1].state.lock().unwrap().requests_received,
            0,
            "later nodes must not be contacted once an earlier one fails"
        );
    }

    #[tokio::test]
    async fn delete_stops_at_first_failing_node_and_does_not_contact_the_rest() {
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

        assert_eq!(nodes[0].state.lock().unwrap().requests_received, 1);
        assert_eq!(
            nodes[1].state.lock().unwrap().requests_received,
            0,
            "later nodes must not be contacted once an earlier one fails"
        );
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
