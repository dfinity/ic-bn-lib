use std::{
    fmt::{self, Debug},
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use ahash::{HashMap, HashMapExt};
use anyhow::{Context as AnyhowContext, Error, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::Bytes;
use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use http::header::AUTHORIZATION;
use ic_bn_lib_common::{
    traits::{custom_domains::ProvidesCustomDomains, http::Client},
    types::CustomDomain,
};
use reqwest::{Method, Request, Url};
use serde::Deserialize;
use tracing::{info, warn};

use crate::http::client::basic_auth;

/// Gets the body of the given URL
async fn get_url_body(cli: &Arc<dyn Client>, url: &Url, timeout: Duration) -> Result<Bytes, Error> {
    let mut url = url.clone();
    let auth_header = if url.username() != "" {
        let hdr = basic_auth(url.username(), url.password());

        // Clear the user/pass from the URL
        let _ = url.set_username("");
        let _ = url.set_password(None);

        Some(hdr)
    } else {
        None
    };

    let mut req = Request::new(Method::GET, url);
    *req.timeout_mut() = Some(timeout);

    // Add HTTP Basic auth header if the URL contains at least a username
    if let Some(v) = auth_header {
        req.headers_mut().insert(AUTHORIZATION, v);
    }

    let response = cli
        .execute(req)
        .await
        .context("failed to make HTTP request")?;

    if !response.status().is_success() {
        return Err(anyhow!("bad response code: {}", response.status()));
    }

    response
        .bytes()
        .await
        .context("failed to fetch response body")
}

/// Fetches a list of custom domains from the given URL in JSON format
async fn get_custom_domains_from_url(
    cli: &Arc<dyn Client>,
    url: &Url,
    timeout: Duration,
) -> Result<Vec<CustomDomain>, Error> {
    let body = get_url_body(cli, url, timeout)
        .await
        .context("unable to fetch custom domains list JSON")?;

    let domains: HashMap<String, Principal> =
        serde_json::from_slice(&body).context("failed to parse JSON body")?;

    let mut domains_parsed = HashMap::with_capacity(domains.len());
    for (domain, canister) in domains {
        let fqdn = FQDN::from_str(&domain)
            .with_context(|| format!("unable to parse '{domain}' as FQDN"))?;

        domains_parsed.insert(fqdn, canister);
    }

    Ok(domains_parsed
        .into_iter()
        .map(|(k, v)| CustomDomain {
            name: k,
            canister_id: v,
            timestamp: 0,
        })
        .collect::<Vec<_>>())
}

/// Generic custom domain provider that fetches a JSON-serialized list from the given URL
#[derive(new)]
pub struct GenericProvider {
    http_client: Arc<dyn Client>,
    url: Url,
    timeout: Duration,
}

impl Debug for GenericProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GenericProvider({})", self.url)
    }
}

#[async_trait]
impl ProvidesCustomDomains for GenericProvider {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        get_custom_domains_from_url(&self.http_client, &self.url, self.timeout).await
    }
}

#[derive(Deserialize)]
struct TimestampedResponse {
    timestamp: u64,
    url: String,
}

/// Generic custom domain provider that fetches a JSON-serialized `TimestampedResponse` from the given URL and remembers the timestamp.
///
/// If it changes, then it fetches a JSON-serialized list from the embedded URL (it can be relative or absolute).
#[derive(new)]
pub struct GenericProviderTimestamped {
    http_client: Arc<dyn Client>,
    url: Url,
    timeout: Duration,
    #[new(default)]
    timestamp: AtomicU64,
    #[new(default)]
    cache: ArcSwapOption<Vec<CustomDomain>>,
}

impl Debug for GenericProviderTimestamped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GenericProviderTimestamped({})", self.url)
    }
}

#[async_trait]
impl ProvidesCustomDomains for GenericProviderTimestamped {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        let body = get_url_body(&self.http_client, &self.url, self.timeout)
            .await
            .context("failed to get timestamp JSON")?;

        let resp: TimestampedResponse = serde_json::from_slice(&body)
            .context("unable to parse response as TimestampedResponse")?;

        // Get the old timestamp
        let old_timestamp = self.timestamp.load(Ordering::SeqCst);

        // Return the cached value if we have one & the timestamps are the same
        if old_timestamp == resp.timestamp
            && let Some(v) = self.cache.load_full()
        {
            info!("{self:?}: timestamp unchanged ({} domains)", v.len());
            return Ok(v.as_ref().clone());
        }

        // Try to parse the response URL and use it if we can do it
        let domains_url = if let Ok(v) = Url::parse(&resp.url) {
            v
        } else {
            // Otherwise treat it as a path relative to our base URL
            let mut u = self.url.clone();
            u.set_path(&resp.url);
            u
        };

        // Otherwise fetch a fresh version from the provided URL
        let domains = get_custom_domains_from_url(&self.http_client, &domains_url, self.timeout)
            .await
            .context("unable to fetch custom domains")?;

        warn!("{self:?}: new timestamp, got {} domains", domains.len());

        // Store the new version in cache
        self.cache.store(Some(Arc::new(domains.clone())));
        self.timestamp.store(resp.timestamp, Ordering::SeqCst);

        Ok(domains)
    }
}

#[derive(Deserialize)]
struct DiffResponse {
    timestamp: u64,
    created: HashMap<String, Principal>,
    deleted: Vec<String>,
}

struct DiffResponseParsed {
    timestamp: u64,
    created: HashMap<FQDN, Principal>,
    deleted: Vec<FQDN>,
}

impl TryFrom<DiffResponse> for DiffResponseParsed {
    type Error = Error;

    fn try_from(v: DiffResponse) -> Result<Self, Self::Error> {
        let mut created = HashMap::with_capacity(v.created.len());
        let mut deleted = Vec::with_capacity(v.deleted.len());

        for (domain, canister) in v.created {
            let fqdn = FQDN::from_str(&domain)
                .with_context(|| format!("unable to parse '{domain}' as FQDN"))?;

            created.insert(fqdn, canister);
        }

        for domain in v.deleted {
            let fqdn = FQDN::from_str(&domain)
                .with_context(|| format!("unable to parse '{domain}' as FQDN"))?;

            deleted.push(fqdn);
        }

        Ok(Self {
            timestamp: v.timestamp,
            created,
            deleted,
        })
    }
}

#[derive(new)]
pub struct GenericProviderDiff {
    http_client: Arc<dyn Client>,
    url: Url,
    timeout: Duration,
    #[new(default)]
    timestamp: AtomicU64,
    #[new(default)]
    cache: Mutex<HashMap<FQDN, Principal>>,
}

impl GenericProviderDiff {
    async fn get_response(&self, url: &Url) -> Result<DiffResponseParsed, Error> {
        let body = get_url_body(&self.http_client, url, self.timeout)
            .await
            .context("unable to fetch custom domains JSON")?;

        let resp: DiffResponse =
            serde_json::from_slice(&body).context("failed to parse JSON body")?;

        resp.try_into().context("unable to parse DiffResponse")
    }

    /// Downloads the initial snapshot of data
    async fn seed(&self) -> Result<(), Error> {
        let resp = self
            .get_response(&self.url)
            .await
            .context("unable to get seed response")?;

        *self.cache.lock().unwrap() = resp.created;
        self.timestamp.store(resp.timestamp, Ordering::SeqCst);

        Ok(())
    }

    /// Converts from internal hashmap to a vec
    fn convert(&self) -> Vec<CustomDomain> {
        self.cache
            .lock()
            .unwrap()
            .clone()
            .into_iter()
            .map(|(name, canister_id)| CustomDomain {
                name,
                canister_id,
                timestamp: 0,
            })
            .collect()
    }
}

impl Debug for GenericProviderDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GenericProviderDiff({})", self.url)
    }
}

#[async_trait]
impl ProvidesCustomDomains for GenericProviderDiff {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        let ts = self.timestamp.load(Ordering::SeqCst);

        // If the timestamp is zero - we need to seed our cache with full snapshot
        if ts == 0 {
            self.seed()
                .await
                .context("unable to download initial snapshot")?;

            return Ok(self.convert());
        }

        // Otherwise get the incremental changes since the timestamp
        let mut url = self.url.clone();
        url.set_query(Some(&format!("timestamp={ts}")));

        let resp = self
            .get_response(&url)
            .await
            .context("unable to get diff reponse")?;

        // Apply the requested changes to the local snapshot
        let mut cache = self.cache.lock().unwrap();

        for (k, v) in resp.created {
            cache.insert(k, v);
        }

        for k in resp.deleted {
            cache.remove(&k);
        }
        drop(cache);

        self.timestamp.store(resp.timestamp, Ordering::SeqCst);

        Ok(self.convert())
    }
}

/// Local file-based custom domain provider.
///
/// Reads domain-to-canister mappings from a file with one mapping per line in the format `domain:principal`.
/// Empty lines are ignored, and whitespace is trimmed.
///
/// # Example File Format
///
/// ```text
/// example.com:aaaaa-aa
/// test.org:qoctq-giaaa-aaaaa-aaaea-cai
/// my-domain.net:ryjl3-tyaaa-aaaaa-aaaba-cai
///
/// another-domain.com:2vxsx-fae
/// ```
#[derive(new)]
pub struct LocalFileProvider {
    file_path: PathBuf,
}

impl Debug for LocalFileProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalFileProvider({})", self.file_path.display())
    }
}

#[async_trait]
impl ProvidesCustomDomains for LocalFileProvider {
    async fn get_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        let body = std::fs::read_to_string(&self.file_path).context("unable to read file")?;

        let mut domains = Vec::new();
        for line in body.lines() {
            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Split by colon
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow!(
                    "invalid line format '{}', expected 'domain:principal'",
                    line
                ));
            }

            let domain_str = parts[0].trim();
            let principal_str = parts[1].trim();

            // Parse domain as FQDN
            let name = FQDN::from_str(domain_str)
                .with_context(|| format!("unable to parse '{}' as FQDN", domain_str))?;

            // Parse principal
            let canister_id = Principal::from_text(principal_str)
                .with_context(|| format!("unable to parse '{}' as principal", principal_str))?;

            domains.push(CustomDomain {
                name,
                canister_id,
                timestamp: 0,
            });
        }

        Ok(domains)
    }
}

#[cfg(test)]
mod test {
    use ::http::Response as HttpResponse;
    use async_trait::async_trait;
    use fqdn::fqdn;
    use ic_bn_lib_common::principal;
    use itertools::Itertools;
    use serde_json::json;

    use crate::hval;

    use super::*;

    #[derive(Debug)]
    struct MockClient;

    #[async_trait]
    impl Client for MockClient {
        async fn execute(&self, r: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            assert_eq!(r.url().as_str(), "http://foo/beef");

            // Check HTTP Basic Auth
            assert_eq!(
                r.headers().get(AUTHORIZATION),
                Some(&hval!("Basic Zm9vOmJhcg=="))
            );

            Ok(HttpResponse::new(
                json!({
                    "foo.bar": "aaaaa-aa",
                    "2athis-domain-is-exactly-fifty-one-characters-l.com": "qoctq-giaaa-aaaaa-aaaea-cai"
                }).to_string(),
            )
            .into())
        }
    }

    #[derive(Debug)]
    struct MockClientBadDomain;

    #[async_trait]
    impl Client for MockClientBadDomain {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            Ok(HttpResponse::new(json!({"foo.bar!!!!": "aaaaa-aa"}).to_string()).into())
        }
    }

    #[derive(Debug)]
    struct MockClientBadCanister;

    #[async_trait]
    impl Client for MockClientBadCanister {
        async fn execute(&self, _: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
            Ok(HttpResponse::new(json!({"foo.bar": "aaaaa-aa!!!"}).to_string()).into())
        }
    }

    #[derive(Debug)]
    struct MockClientTimestamped(AtomicU64);

    #[async_trait]
    impl Client for MockClientTimestamped {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            if req.url().as_str().contains("subdomains") {
                return Ok(HttpResponse::new(
                    if req.url().as_str() == "http://foo/subdomains1" {
                        json!({"2athis-domain-is-exactly-fifty-one-characters-l.com": "aaaaa-aa", "bar.foo": "qoctq-giaaa-aaaaa-aaaea-cai"})
                    } else if req.url().as_str() == "https://caffeine.ai/subdomains2" {
                        json!({"foo.barr": "aaaaa-aa", "bar.foos": "qoctq-giaaa-aaaaa-aaaea-cai"})
                    } else {
                        panic!("shouldn't happen");
                    }
                    .to_string(),
                )
                .into());
            }

            let i = self.0.fetch_add(1, Ordering::SeqCst);
            return Ok(HttpResponse::new(
                if i <= 1 {
                    json!({"timestamp": 1743756162, "url": "/subdomains1"})
                } else {
                    json!({"timestamp": 1743756163, "url": "https://caffeine.ai/subdomains2"})
                }
                .to_string(),
            )
            .into());
        }
    }

    #[derive(Debug)]
    struct MockClientDiff;

    #[async_trait]
    impl Client for MockClientDiff {
        async fn execute(
            &self,
            req: reqwest::Request,
        ) -> Result<reqwest::Response, reqwest::Error> {
            if req.url().as_str().ends_with("timestamp=10") {
                return Ok(HttpResponse::new(
                    json!({
                        "timestamp": 20,
                        "created": {
                            "foo.bar3": "aaaaa-aa",
                            "foo.bar4": "qoctq-giaaa-aaaaa-aaaea-cai"
                        },
                        "deleted": ["2athis-domain-is-exactly-fifty-one-characters-l.com", "foo.bar0"],
                    })
                    .to_string(),
                )
                .into());
            }

            if req.url().as_str().ends_with("timestamp=20") {
                return Ok(HttpResponse::new(
                    json!({
                        "timestamp": 30,
                        "created": {
                            "foo.bar5": "qoctq-giaaa-aaaaa-aaaea-cai"
                        },
                        "deleted": ["foo.bar2", "foo.bar3", "foo.bar4"],
                    })
                    .to_string(),
                )
                .into());
            }

            return Ok(HttpResponse::new(
                json!({
                    "timestamp": 10,
                    "created": {
                        "2athis-domain-is-exactly-fifty-one-characters-l.com": "aaaaa-aa",
                        "foo.bar2": "qoctq-giaaa-aaaaa-aaaea-cai"
                    },
                    "deleted": [],
                })
                .to_string(),
            )
            .into());
        }
    }

    #[tokio::test]
    async fn test_generic_provider_diff() {
        let cli = Arc::new(MockClientDiff);
        let prov = GenericProviderDiff::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);

        // Check that 1st call provides the seed set
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("foo.bar2"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("2athis-domain-is-exactly-fifty-one-characters-l.com"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
            ]
        );

        // Check that 2nd call does the updates
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("foo.bar2"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("foo.bar3"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("foo.bar4"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
            ]
        );

        // Check that 3rd call does the updates
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![CustomDomain {
                name: fqdn!("foo.bar5"),
                canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                timestamp: 0,
            },]
        );
    }

    #[tokio::test]
    async fn test_generic_provider_timestamped() {
        let cli = Arc::new(MockClientTimestamped(AtomicU64::new(0)));
        let prov =
            GenericProviderTimestamped::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);

        // Check that 1st call provides the 1st set of domains
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foo"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("2athis-domain-is-exactly-fifty-one-characters-l.com"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
            ]
        );

        // Check that 2nd call provides the same set (timestamp not changed)
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foo"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("2athis-domain-is-exactly-fifty-one-characters-l.com"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
            ]
        );

        // Check that 3rd call provides different set
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foos"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("foo.barr"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
            ]
        );

        // Check that 4th call provides same set again
        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("bar.foos"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("foo.barr"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_generic_provider() {
        let cli = Arc::new(MockClient);
        let prov = GenericProvider::new(
            cli,
            "http://foo:bar@foo/beef".try_into().unwrap(),
            Duration::ZERO,
        );

        let domains: Vec<CustomDomain> = prov
            .get_custom_domains()
            .await
            .unwrap()
            .into_iter()
            .sorted_by_key(|x| x.name.clone())
            .collect();

        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("foo.bar"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("2athis-domain-is-exactly-fifty-one-characters-l.com"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
            ]
        );

        let cli = Arc::new(MockClientBadDomain);
        let prov = GenericProvider::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);
        assert!(prov.get_custom_domains().await.is_err());

        let cli = Arc::new(MockClientBadCanister);
        let prov = GenericProvider::new(cli, "http://foo".try_into().unwrap(), Duration::ZERO);
        assert!(prov.get_custom_domains().await.is_err());
    }

    #[tokio::test]
    async fn test_local_file_provider_valid() {
        use std::io::Write;
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();

        // Write valid domain:principal pairs
        writeln!(temp_file, "foo.bar:aaaaa-aa").unwrap();
        writeln!(temp_file, "test.example.com:qoctq-giaaa-aaaaa-aaaea-cai").unwrap();
        writeln!(
            temp_file,
            "2athis-domain-is-exactly-fifty-one-characters-l.com:ryjl3-tyaaa-aaaaa-aaaba-cai"
        )
        .unwrap();
        temp_file.flush().unwrap();

        let prov = LocalFileProvider::new(temp_file.path().to_path_buf());
        let mut domains: Vec<CustomDomain> = prov.get_custom_domains().await.unwrap();
        domains.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(domains.len(), 3);
        assert_eq!(
            domains,
            vec![
                CustomDomain {
                    name: fqdn!("foo.bar"),
                    canister_id: principal!("aaaaa-aa"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("test.example.com"),
                    canister_id: principal!("qoctq-giaaa-aaaaa-aaaea-cai"),
                    timestamp: 0,
                },
                CustomDomain {
                    name: fqdn!("2athis-domain-is-exactly-fifty-one-characters-l.com"),
                    canister_id: principal!("ryjl3-tyaaa-aaaaa-aaaba-cai"),
                    timestamp: 0,
                },
            ]
        );
    }

    #[tokio::test]
    async fn test_local_file_provider_missing_colon() {
        use std::io::Write;
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();

        // Write invalid format (no colon)
        writeln!(temp_file, "foo.bar aaaaa-aa").unwrap();
        temp_file.flush().unwrap();

        let prov = LocalFileProvider::new(temp_file.path().to_path_buf());
        let result = prov.get_custom_domains().await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid line format"));
    }

    #[tokio::test]
    async fn test_local_file_provider_file_not_found() {
        let prov = LocalFileProvider::new("/nonexistent/path/to/file.txt".into());
        let result = prov.get_custom_domains().await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unable to read file"));
    }
}
