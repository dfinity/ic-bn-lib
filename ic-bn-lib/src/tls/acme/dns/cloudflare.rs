use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{DnsManager, Record};

pub const DEFAULT_CLOUDFLARE_URL: &str = "https://api.cloudflare.com/";

#[derive(Deserialize)]
struct ApiResponse<T> {
    success: bool,
    errors: Vec<ApiError>,
    result: T,
}

impl<T> ApiResponse<T> {
    fn join_errors(&self) -> String {
        self.errors
            .iter()
            .map(|e| e.message.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
struct ApiError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

#[derive(Debug, Deserialize)]
pub struct DnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

#[derive(Serialize)]
struct CreateDnsRecordBody<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

pub struct Cloudflare {
    client: Client,
    base_url: Url,
    token: String,
}

impl Cloudflare {
    /// Create a new Cloudflare client with a default HTTP client
    pub fn new(base_url: Url, token: String) -> Result<Self, Error> {
        let client = Client::builder()
            .build()
            .context("failed to initialize HTTP client")?;

        Ok(Self::new_with_http_client(base_url, token, client))
    }

    /// Create a new Cloudflare client with a provided HTTP client
    pub const fn new_with_http_client(base_url: Url, token: String, client: Client) -> Self {
        Self {
            client,
            base_url,
            token,
        }
    }

    /// GET /client/v4/zones?name=<zone>
    pub async fn find_zone(&self, zone: &str) -> Result<String, Error> {
        let url = self
            .base_url
            .join("client/v4/zones")
            .context("failed to build zones URL")?;

        let resp: ApiResponse<Vec<Zone>> = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .query(&[("name", zone)])
            .send()
            .await
            .context("zones request failed")?
            .error_for_status()
            .context("zones request returned error status")?
            .json()
            .await
            .context("failed to deserialize zones response")?;

        if !resp.success {
            let msgs = resp
                .errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>();

            return Err(anyhow!("zones API error: {}", msgs.join(", ")));
        }

        resp.result
            .into_iter()
            .next()
            .map(|x| x.id)
            .ok_or_else(|| anyhow!("zone '{zone}' not found"))
    }

    /// GET /client/v4/zones/<zone_id>/dns_records?name=<name>
    pub async fn find_records(&self, zone_id: &str, name: &str) -> Result<Vec<DnsRecord>, Error> {
        let url = self
            .base_url
            .join(&format!("client/v4/zones/{zone_id}/dns_records"))
            .context("failed to build dns_records URL")?;

        let resp: ApiResponse<Vec<DnsRecord>> = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .query(&[("name", name)])
            .send()
            .await
            .context("list dns_records request failed")?
            .error_for_status()
            .context("list dns_records request returned error status")?
            .json()
            .await
            .context("failed to deserialize dns_records response")?;

        if !resp.success {
            return Err(anyhow!("dns_records API error: {}", resp.join_errors()));
        }

        Ok(resp.result)
    }
}

#[async_trait]
impl DnsManager for Cloudflare {
    /// POST /client/v4/zones/<zone_id>/dns_records
    async fn create(&self, zone: &str, name: &str, record: Record, ttl: u32) -> Result<(), Error> {
        let zone_id = self
            .find_zone(zone)
            .await
            .with_context(|| format!("unable to find zone '{zone}'"))?;

        let content = match record {
            Record::Txt(ref s) => s.as_str(),
        };

        let url = self
            .base_url
            .join(&format!("client/v4/zones/{zone_id}/dns_records"))
            .context("failed to build create dns_record URL")?;

        debug!("Cloudflare: creating TXT record {name} in zone {zone}: {content}");

        let body = CreateDnsRecordBody {
            record_type: "TXT",
            name,
            content,
            ttl,
        };

        let resp: ApiResponse<serde_json::Value> = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .context("create dns_record request failed")?
            .error_for_status()
            .context("create dns_record request returned error status")?
            .json()
            .await
            .context("failed to deserialize create dns_record response")?;

        if !resp.success {
            return Err(anyhow!(
                "create dns_record API error: {}",
                resp.join_errors()
            ));
        }

        Ok(())
    }

    /// DELETE /client/v4/zones/<zone_id>/dns_records/<record_id>  (once per match)
    async fn delete(&self, zone: &str, name: &str, target_record: &Record) -> Result<(), Error> {
        let zone_id = self
            .find_zone(zone)
            .await
            .with_context(|| format!("unable to find zone '{zone}'"))?;

        let fqdn = format!("{name}.{zone}");

        let records = self
            .find_records(&zone_id, &fqdn)
            .await
            .context("unable to find records")?;

        for record in records.into_iter() {
            match target_record {
                Record::Txt(v) => {
                    if !record.record_type.eq_ignore_ascii_case("TXT") || &record.content != v {
                        continue;
                    }
                }
            }

            debug!(
                "Cloudflare: deleting record {} ({}) in zone {zone}",
                record.name, record.content
            );

            let url = self
                .base_url
                .join(&format!(
                    "client/v4/zones/{zone_id}/dns_records/{}",
                    record.id
                ))
                .context("failed to build delete dns_record URL")?;

            let resp: ApiResponse<serde_json::Value> = self
                .client
                .delete(url)
                .bearer_auth(&self.token)
                .send()
                .await
                .context("delete dns_record request failed")?
                .error_for_status()
                .context("delete dns_record request returned error status")?
                .json()
                .await
                .context("failed to deserialize delete dns_record response")?;

            if !resp.success {
                return Err(anyhow!(
                    "Delete dns_record '{}' API error: {}",
                    record.id,
                    resp.join_errors()
                ));
            }
        }

        Ok(())
    }
}

/// Mocks the Cloudflare API v4 (https://developers.cloudflare.com/api/) over HTTPS
/// so that `Cloudflare` can be exercised without talking to the real service.
#[cfg(test)]
mod test {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use axum::{
        Json, Router,
        extract::{Path, Query, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::{delete, get},
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::tls::acme::dns::test::support::{
        check_bearer_auth, insecure_http_client, install_crypto_provider, spawn_https_mock_server,
    };

    const TOKEN: &str = "test-api-token";

    #[derive(Clone)]
    struct MockRecord {
        id: String,
        name: String,
        record_type: String,
        content: String,
        ttl: u32,
    }

    /// In-memory state backing the mock server, shared between the server tasks and the test
    /// so assertions can inspect what was persisted and error injection flags can be flipped.
    struct MockState {
        token: String,
        zones: HashMap<String, String>,
        records: HashMap<String, Vec<MockRecord>>,
        next_id: u64,
        fail_create: bool,
        fail_delete: bool,
        create_calls: Vec<(String, u32)>,
        delete_calls: Vec<String>,
    }

    impl MockState {
        fn new() -> Self {
            Self {
                token: TOKEN.into(),
                zones: HashMap::new(),
                records: HashMap::new(),
                next_id: 1,
                fail_create: false,
                fail_delete: false,
                create_calls: Vec::new(),
                delete_calls: Vec::new(),
            }
        }

        fn next_id(&mut self) -> String {
            let id = format!("{:032x}", self.next_id);
            self.next_id += 1;
            id
        }

        fn add_zone(&mut self, name: &str) -> String {
            let id = self.next_id();
            self.zones.insert(name.to_string(), id.clone());
            self.records.entry(id.clone()).or_default();
            id
        }

        fn add_record(
            &mut self,
            zone_id: &str,
            name: &str,
            record_type: &str,
            content: &str,
        ) -> String {
            let id = self.next_id();
            self.records
                .entry(zone_id.to_string())
                .or_default()
                .push(MockRecord {
                    id: id.clone(),
                    name: name.to_string(),
                    record_type: record_type.to_string(),
                    content: content.to_string(),
                    ttl: 60,
                });
            id
        }
    }

    type SharedState = Arc<Mutex<MockState>>;

    /// Cloudflare-shaped error envelope: HTTP status codes for auth/lookup failures follow
    /// https://developers.cloudflare.com/api/ (non-2xx), while application-level failures
    /// (e.g. record already exists) come back as HTTP 200 with `success: false`.
    fn error_response(status: StatusCode, code: u32, message: &str) -> Response {
        (
            status,
            Json(json!({
                "success": false,
                "errors": [{"code": code, "message": message}],
                "messages": [],
                "result": null
            })),
        )
            .into_response()
    }

    fn unauthorized() -> Response {
        error_response(StatusCode::BAD_REQUEST, 9109, "Invalid access token")
    }

    fn invalid_zone() -> Response {
        error_response(StatusCode::BAD_REQUEST, 1003, "Invalid zone identifier")
    }

    async fn list_zones(
        State(state): State<SharedState>,
        headers: HeaderMap,
        Query(params): Query<HashMap<String, String>>,
    ) -> Response {
        let result: Vec<Value> = {
            let state = state.lock().unwrap();
            if !check_bearer_auth(&headers, &state.token) {
                return unauthorized();
            }

            let name = params.get("name").cloned().unwrap_or_default();
            state
                .zones
                .get(&name)
                .map(|id| vec![json!({"id": id, "name": name})])
                .unwrap_or_default()
        };
        let count = result.len();

        Json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": result,
            "result_info": {"count": count, "page": 1, "per_page": 20, "total_count": count, "total_pages": 1},
        }))
        .into_response()
    }

    async fn list_dns_records(
        State(state): State<SharedState>,
        Path(zone_id): Path<String>,
        headers: HeaderMap,
        Query(params): Query<HashMap<String, String>>,
    ) -> Response {
        let records: Vec<MockRecord> = {
            let state = state.lock().unwrap();
            if !check_bearer_auth(&headers, &state.token) {
                return unauthorized();
            }

            let Some(records) = state.records.get(&zone_id) else {
                return invalid_zone();
            };
            let records = records.clone();
            drop(state);
            records
        };

        let name_filter = params.get("name");
        let result: Vec<Value> = records
            .iter()
            .filter(|r| name_filter.is_none_or(|n| &r.name == n))
            .map(|r| {
                json!({
                    "id": r.id,
                    "zone_id": zone_id,
                    "name": r.name,
                    "type": r.record_type,
                    "content": r.content,
                    "ttl": r.ttl,
                    "proxied": false,
                })
            })
            .collect();
        let count = result.len();

        Json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": result,
            "result_info": {"count": count, "page": 1, "per_page": 20, "total_count": count, "total_pages": 1},
        }))
        .into_response()
    }

    #[derive(Deserialize)]
    struct CreateBody {
        #[serde(rename = "type")]
        record_type: String,
        name: String,
        content: String,
        ttl: u32,
    }

    async fn create_dns_record(
        State(state): State<SharedState>,
        Path(zone_id): Path<String>,
        headers: HeaderMap,
        Json(body): Json<CreateBody>,
    ) -> Response {
        let id = {
            let mut state = state.lock().unwrap();
            if !check_bearer_auth(&headers, &state.token) {
                return unauthorized();
            }
            if !state.records.contains_key(&zone_id) {
                return invalid_zone();
            }
            if state.fail_create {
                return error_response(StatusCode::OK, 81058, "Record already exists.");
            }

            state.create_calls.push((body.content.clone(), body.ttl));
            state.add_record(&zone_id, &body.name, &body.record_type, &body.content)
        };

        Json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": {
                "id": id,
                "zone_id": zone_id,
                "name": body.name,
                "type": body.record_type,
                "content": body.content,
                "ttl": body.ttl,
                "proxied": false,
            },
        }))
        .into_response()
    }

    async fn delete_dns_record(
        State(state): State<SharedState>,
        Path((zone_id, record_id)): Path<(String, String)>,
        headers: HeaderMap,
    ) -> Response {
        {
            let mut state = state.lock().unwrap();
            if !check_bearer_auth(&headers, &state.token) {
                return unauthorized();
            }
            if state.fail_delete {
                return error_response(StatusCode::OK, 81044, "Record does not exist.");
            }

            let Some(records) = state.records.get_mut(&zone_id) else {
                return invalid_zone();
            };

            let before = records.len();
            records.retain(|r| r.id != record_id);
            if records.len() == before {
                return error_response(StatusCode::NOT_FOUND, 81044, "Record does not exist.");
            }

            state.delete_calls.push(record_id.clone());
        }

        Json(json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": {"id": record_id},
        }))
        .into_response()
    }

    /// Builds the mock Cloudflare API router, ready to be handed to `spawn_https_mock_server`.
    fn mock_router(state: SharedState) -> Router {
        Router::new()
            .route("/client/v4/zones", get(list_zones))
            .route(
                "/client/v4/zones/{zone_id}/dns_records",
                get(list_dns_records).post(create_dns_record),
            )
            .route(
                "/client/v4/zones/{zone_id}/dns_records/{record_id}",
                delete(delete_dns_record),
            )
            .with_state(state)
    }

    struct TestEnv {
        client: Cloudflare,
        state: SharedState,
        base_url: Url,
    }

    /// Boots a fresh mock server + matching `Cloudflare` client. Each test gets its own server
    /// instance (cheap, unlike the real Pebble-based ACME tests) so they can run independently.
    async fn setup() -> TestEnv {
        install_crypto_provider();

        let state: SharedState = Arc::new(Mutex::new(MockState::new()));
        let base_url = spawn_https_mock_server(mock_router(state.clone())).await;

        let client = client_with_token(base_url.clone(), TOKEN);

        TestEnv {
            client,
            state,
            base_url,
        }
    }

    fn client_with_token(base_url: Url, token: &str) -> Cloudflare {
        Cloudflare::new_with_http_client(base_url, token.to_string(), insecure_http_client())
    }

    #[tokio::test]
    async fn find_zone_returns_id_when_zone_exists() {
        let env = setup().await;
        let zone_id = env.state.lock().unwrap().add_zone("example.com");

        let found = env.client.find_zone("example.com").await.unwrap();
        assert_eq!(found, zone_id);
    }

    #[tokio::test]
    async fn find_zone_errors_when_zone_missing() {
        let env = setup().await;

        let err = env.client.find_zone("missing.com").await.unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[tokio::test]
    async fn find_zone_errors_on_unauthorized() {
        let env = setup().await;
        env.state.lock().unwrap().add_zone("example.com");

        let client = client_with_token(env.base_url.clone(), "wrong-token");
        let err = client.find_zone("example.com").await.unwrap_err();
        assert!(err.to_string().contains("returned error status"), "{err}");
    }

    #[tokio::test]
    async fn find_records_filters_by_name() {
        let env = setup().await;
        let zone_id = {
            let mut state = env.state.lock().unwrap();
            let zone_id = state.add_zone("example.com");
            state.add_record(&zone_id, "_acme-challenge.example.com", "TXT", "keep-me");
            state.add_record(&zone_id, "other.example.com", "TXT", "not-this-one");
            zone_id
        };

        let records = env
            .client
            .find_records(&zone_id, "_acme-challenge.example.com")
            .await
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content, "keep-me");
        assert_eq!(records[0].record_type, "TXT");
    }

    #[tokio::test]
    async fn find_records_errors_on_invalid_zone() {
        let env = setup().await;

        let err = env
            .client
            .find_records("nonexistent-zone-id", "foo")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("returned error status"), "{err}");
    }

    #[tokio::test]
    async fn create_adds_txt_record_in_correct_zone() {
        let env = setup().await;
        let zone_id = env.state.lock().unwrap().add_zone("example.com");

        env.client
            .create(
                "example.com",
                "_acme-challenge.example.com",
                Record::Txt("the-token".into()),
                120,
            )
            .await
            .unwrap();

        let (create_calls, records) = {
            let state = env.state.lock().unwrap();
            (state.create_calls.clone(), state.records[&zone_id].clone())
        };
        assert_eq!(create_calls, vec![("the-token".to_string(), 120)]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "_acme-challenge.example.com");
        assert_eq!(records[0].record_type, "TXT");
        assert_eq!(records[0].content, "the-token");
    }

    #[tokio::test]
    async fn create_errors_when_zone_missing() {
        let env = setup().await;

        let err = env
            .client
            .create(
                "missing.com",
                "_acme-challenge",
                Record::Txt("x".into()),
                60,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unable to find zone"), "{err}");
    }

    #[tokio::test]
    async fn create_errors_on_api_error() {
        let env = setup().await;
        env.state.lock().unwrap().add_zone("example.com");
        env.state.lock().unwrap().fail_create = true;

        let err = env
            .client
            .create(
                "example.com",
                "_acme-challenge.example.com",
                Record::Txt("x".into()),
                60,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("create dns_record API error"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn delete_only_removes_matching_txt_record() {
        let env = setup().await;
        let (zone_id, keep_wrong_content, keep_wrong_type, remove_id) = {
            let mut state = env.state.lock().unwrap();
            let zone_id = state.add_zone("example.com");
            let keep_wrong_content = state.add_record(
                &zone_id,
                "_acme-challenge.example.com",
                "TXT",
                "different-token",
            );
            let keep_wrong_type =
                state.add_record(&zone_id, "_acme-challenge.example.com", "A", "the-token");
            let remove_id =
                state.add_record(&zone_id, "_acme-challenge.example.com", "TXT", "the-token");
            drop(state);
            (zone_id, keep_wrong_content, keep_wrong_type, remove_id)
        };

        env.client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap();

        let (delete_calls, remaining) = {
            let state = env.state.lock().unwrap();
            let remaining: Vec<String> = state.records[&zone_id]
                .iter()
                .map(|r| r.id.clone())
                .collect();
            (state.delete_calls.clone(), remaining)
        };
        assert_eq!(delete_calls, vec![remove_id]);
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains(&keep_wrong_content));
        assert!(remaining.contains(&keep_wrong_type));
    }

    #[tokio::test]
    async fn delete_is_noop_when_nothing_matches() {
        let env = setup().await;
        let zone_id = env.state.lock().unwrap().add_zone("example.com");
        env.state.lock().unwrap().add_record(
            &zone_id,
            "_acme-challenge.example.com",
            "TXT",
            "some-token",
        );

        env.client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("no-such-token".into()),
            )
            .await
            .unwrap();

        assert!(env.state.lock().unwrap().delete_calls.is_empty());
        assert_eq!(env.state.lock().unwrap().records[&zone_id].len(), 1);
    }

    #[tokio::test]
    async fn delete_errors_on_api_error() {
        let env = setup().await;
        let zone_id = env.state.lock().unwrap().add_zone("example.com");
        env.state.lock().unwrap().add_record(
            &zone_id,
            "_acme-challenge.example.com",
            "TXT",
            "the-token",
        );
        env.state.lock().unwrap().fail_delete = true;

        let err = env
            .client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("the-token".into()),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("API error"), "{err}");
    }

    /// End-to-end lifecycle through the public `DnsManager` trait: create a TXT record,
    /// confirm it's visible, delete it, confirm it's gone.
    #[tokio::test]
    async fn create_then_delete_round_trip() {
        let env = setup().await;
        let zone_id = env.state.lock().unwrap().add_zone("example.com");

        env.client
            .create(
                "example.com",
                "_acme-challenge.example.com",
                Record::Txt("round-trip-token".into()),
                60,
            )
            .await
            .unwrap();

        let records = env
            .client
            .find_records(&zone_id, "_acme-challenge.example.com")
            .await
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content, "round-trip-token");

        env.client
            .delete(
                "example.com",
                "_acme-challenge",
                &Record::Txt("round-trip-token".into()),
            )
            .await
            .unwrap();

        let records = env
            .client
            .find_records(&zone_id, "_acme-challenge.example.com")
            .await
            .unwrap();
        assert!(records.is_empty());
    }
}
