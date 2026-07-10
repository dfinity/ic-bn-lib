use std::collections::HashSet;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use candid::Principal;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::OsRng};
use fqdn::FQDN;
use pem::parse_many;
use prometheus::Registry;
use tokio::{spawn, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use x509_parser::{parse_x509_certificate, prelude::GeneralName};

use super::helpers::{TestEnv, init_logging};

use crate::tls::acme::{AcmeCertificateClient, AcmeUrl, TokenManager};
use crate::{
    custom_domains::{
        backend::router::{RateLimitConfig, create_router},
        base::{
            traits::{
                repository::Repository,
                validation::{ValidatesDomains, ValidationError},
            },
            types::{
                cipher::CertificateCipher,
                domain::RegistrationStatus,
                worker::{Worker, WorkerConfig, WorkerMetrics},
            },
        },
        client::CanisterClient,
    },
    ic_agent::{Agent, Identity, identity::BasicIdentity},
    reqwest::{self, Url},
    tests::pebble::{Env, dns::TokenManagerPebble},
    tls::acme::client::ClientBuilder,
};

const INIT_CANISTER_CALL_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_CANISTER_CALL_RETRY_DELAY: Duration = Duration::from_secs(2);

const DOMAINS_COUNT: usize = 160;
const WORKERS_COUNT: usize = 4;

// Title: Custom Domains with Pebble ACME test server and multiple workers processing registration requests in parallel
// Setup:
// - Start Pocket IC and install the Custom Domains canister
// - Start HTTP Gateway server on top of Pocket IC to emulate prod environment
// - Start Pebble environment for issuing certificates via ACME DNS-01 challenge (includes ACME server and DNS management server)
// - Start one backend API server accepting domain registration requests
// - Start M workers polling the canister for tasks, executing them and submitting results back to the canister
// Steps:
// 1. Submit N domains for registration via the API
//    Each worker should start picking up tasks and obtain certificates in parallel
// 2. Verify all domains have been registered after all tasks are processed
// 3. Download all certificates and verify they match the requested domains
// 4. Submit half of the registered domains for deletion via the API calls
// 5. Verify all these domains are eventually deleted from the canister
// 6. Get canister metrics and verify the expected stats of domain registrations
// 7. Get workers metrics and verify they all have processed more than one task each

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_pebble_test() -> anyhow::Result<()> {
    init_logging();

    info!(
        "Setting up test environment: Pocket IC, Pebble ACME and DNS servers, workers, and API server ..."
    );
    let (ctx, workers_metrics) = setup_test_environment().await?;

    info!("Step 1: Submitting {DOMAINS_COUNT} domains for registration via the API ...");
    let domains = submit_domains_for_registration(&ctx).await?;
    wait_for_all_tasks_completion(&ctx.canister_repository).await?;

    info!("Step 2: Verifying all domains have been registered after all tasks are processed");
    verify_domains_registration(&ctx, &domains).await?;

    info!("Step 3: Downloading all certificates and verifying they match the requested domains");
    download_certificates_and_validate(&ctx, domains.clone()).await?;

    info!("Step 4: Registering a wildcard domain and verifying its certificate carries both SANs");
    wildcard_domain_e2e(&ctx).await?;

    info!("Step 5: Submitting half of the registered domains for deletion via the API calls");
    let deleted_domains = delete_half_domains(&ctx, domains).await?;

    info!("Step 6: Verifying all these domains are eventually deleted from the canister");
    verify_domains_deletion(&ctx, deleted_domains).await?;

    info!(
        "Step 7: Getting canister metrics and verifying the expected stats of domain registrations"
    );
    verify_canister_metrics(&ctx).await?;

    info!(
        "Step 8: Getting workers metrics and verifying they all have processed more than one task each"
    );
    verify_workers_metrics_with_retries(workers_metrics).await?;

    Ok(())
}

async fn create_acme_client(
    addr_acme: String,
    token_manager: Arc<dyn TokenManager>,
) -> anyhow::Result<Arc<dyn AcmeCertificateClient>> {
    let builder = ClientBuilder::new(true)
        .with_acme_url(AcmeUrl::Custom(format!("https://{addr_acme}/dir").parse()?))
        .with_token_manager(token_manager);

    let (builder, _contract) = builder.create_account("mailto:foo@bar.com").await?;

    let acme_client = builder
        .build()
        .await
        .with_context(|| "failed to build ACME client")?;

    Ok(Arc::new(acme_client))
}

// Mock validator that approves all domains for registration and deletion
struct MockValidator;

#[async_trait]
impl ValidatesDomains for MockValidator {
    async fn validate(&self, _domain: &FQDN) -> Result<Principal, ValidationError> {
        Ok("laqa6-raaaa-aaaam-aehzq-cai".parse().unwrap())
    }

    async fn validate_deletion(&self, _domain: &FQDN) -> Result<(), ValidationError> {
        Ok(())
    }
}

#[allow(dead_code)]
struct TestContext {
    pocket_ic_env: TestEnv,
    pebble_env: Env,
    canister_repository: Arc<CanisterClient>,
    http_gateway_url: Url,
    api_server_addr: SocketAddr,
    sender: Principal,
}

async fn setup_test_environment() -> anyhow::Result<(TestContext, Arc<WorkerMetrics>)> {
    let identity = test_identity();
    let sender = identity
        .sender()
        .map_err(|_| anyhow!("Failed to extract sender"))?;
    let authorized_principal = Some(sender);

    let mut pocket_ic_env = TestEnv::new(authorized_principal, sender).await?;

    // Make HTTP Gateway with autoprogressing Pocket IC
    let http_gateway_url = pocket_ic_env
        .pic
        .make_live_with_params(None, None, None, None)
        .await;
    info!("HTTP Gateway for Pocket IC running at {http_gateway_url}");

    let pebble_env = Env::new().await;
    info!(
        "Pebble test environment started: ACME server at {}, DNS management server at {}",
        pebble_env.addr_acme(),
        pebble_env.addr_dns_management()
    );

    // Token manager for executing ACME DNS-01 challenges
    let token_manager = Arc::new(TokenManagerPebble::new(
        format!("http://{}", pebble_env.addr_dns_management()).parse()?,
    ));

    let acme_client = create_acme_client(pebble_env.addr_acme(), token_manager.clone()).await?;

    let cancellation_token = CancellationToken::new();

    let agent = Agent::builder()
        .with_url(http_gateway_url.clone())
        .with_identity(identity)
        .build()?;
    let root_key = pocket_ic_env
        .pic
        .root_key()
        .await
        .expect("failed to get root key");
    agent.set_root_key(root_key);

    let cipher = {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = CertificateCipher::new(&key);
        Arc::new(cipher)
    };

    let repository = Arc::new(CanisterClient::new(
        agent,
        pocket_ic_env.canister_id,
        cipher,
        Duration::ZERO,
        Duration::ZERO,
        0,
        None,
    ));

    let prometheus_registry = Registry::new_custom(Some("custom_domains".into()), None).unwrap();
    let workers_metrics = Arc::new(WorkerMetrics::new(&prometheus_registry));
    let validator = Arc::new(MockValidator);

    spawn_workers(
        repository.clone(),
        validator.clone(),
        acme_client.clone(),
        workers_metrics.clone(),
        cancellation_token,
    )
    .await;

    let api_addr = spawn_api_server(repository.clone(), validator, prometheus_registry).await?;

    Ok((
        TestContext {
            pocket_ic_env,
            pebble_env,
            http_gateway_url,
            sender,
            canister_repository: repository,
            api_server_addr: api_addr,
        },
        workers_metrics,
    ))
}

async fn spawn_workers(
    repository: Arc<CanisterClient>,
    validator: Arc<MockValidator>,
    acme_client: Arc<dyn AcmeCertificateClient>,
    metrics: Arc<WorkerMetrics>,
    cancellation_token: CancellationToken,
) {
    for i in 0..WORKERS_COUNT {
        let worker = Worker::new(
            format!("worker_{}", i + 1),
            repository.clone(),
            validator.clone(),
            acme_client.clone(),
            WorkerConfig::default(),
            metrics.clone(),
            cancellation_token.clone(),
        );

        let delay = Duration::from_millis(i as u64 * 30);

        spawn(async move {
            sleep(delay).await;
            worker.run().await
        });
    }
}

async fn spawn_api_server(
    repository: Arc<CanisterClient>,
    validator: Arc<MockValidator>,
    prometheus_registry: Registry,
) -> anyhow::Result<SocketAddr> {
    let api_addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    spawn(async move {
        let router = create_router(
            repository,
            validator,
            prometheus_registry,
            RateLimitConfig::default(),
            true,
            None,
        );
        info!("Starting API server at http://{}", api_addr);
        axum_server::bind(api_addr)
            .serve(router.into_make_service())
            .await
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()?;

    let metrics_url = format!("http://{}:{}/metrics", api_addr.ip(), api_addr.port());
    // Wait for server to be ready by polling metrics endpoint
    loop {
        match client.get(&metrics_url).send().await {
            Ok(response) if response.status().is_success() => {
                info!("API server ready");
                return Ok(api_addr);
            }
            Ok(_) | Err(_) => {
                debug!("API server not ready yet");
                sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

async fn submit_domains_for_registration(ctx: &TestContext) -> anyhow::Result<Vec<String>> {
    let domains = (0..DOMAINS_COUNT)
        .map(|i| format!("custom-domain-{i}.example.com"))
        .collect::<Vec<_>>();

    let mut task_handles = vec![];

    let client = reqwest::Client::new();

    for domain in domains.clone() {
        let client_cloned = client.clone();
        let api_addr = ctx.api_server_addr;

        let handle = spawn(async move {
            client_cloned
                .post(format!(
                    "http://{}:{}/v1/{domain}",
                    api_addr.ip(),
                    api_addr.port()
                ))
                .send()
                .await
                .unwrap()
        });

        task_handles.push(handle);
    }

    for handle in task_handles {
        let response = handle.await?;
        assert!(response.status().is_success());
    }

    Ok(domains)
}

async fn wait_for_all_tasks_completion(repository: &Arc<CanisterClient>) -> anyhow::Result<()> {
    let duration = Duration::from_secs(5);
    while repository.has_next_task().await? {
        debug!("Tasks queue is not empty, sleeping {duration:?} ...");
        sleep(duration).await;
    }
    Ok(())
}

async fn verify_domains_registration(
    ctx: &TestContext,
    domains: &Vec<String>,
) -> anyhow::Result<()> {
    for domain in domains {
        let mut sleep_interval = INIT_CANISTER_CALL_RETRY_DELAY;
        loop {
            let status = ctx
                .canister_repository
                .get_domain_status(&domain.parse()?)
                .await?
                .context("Domain not found")?;
            if status.status == RegistrationStatus::Registered {
                break;
            }
            info!("Domain {domain} is not yet registered, sleeping {sleep_interval:?} ...");
            sleep(sleep_interval).await;
            sleep_interval = 2 * sleep_interval;
            sleep_interval = sleep_interval.min(MAX_CANISTER_CALL_RETRY_DELAY)
        }
    }
    Ok(())
}

async fn download_certificates_and_validate(
    ctx: &TestContext,
    domains: Vec<String>,
) -> anyhow::Result<()> {
    let registered_domains = ctx.canister_repository.all_registrations(false).await?;
    let mut domains_set: HashSet<String> = HashSet::from_iter(domains);
    for registered_domain in registered_domains {
        let domain = extract_domain_from_cert(registered_domain.cert)?;
        assert!(domains_set.remove(&domain));
    }
    // All domains should have been matched
    assert!(domains_set.is_empty());
    Ok(())
}

/// Registers a single domain with `wildcard=true`, waits for issuance, and verifies the
/// resulting certificate contains both the bare domain and its `*.domain` wildcard SAN.
///
/// The domain is deleted again at the end so the canister state (and the registration
/// counts asserted in later steps) is left exactly as it was before this step.
async fn wildcard_domain_e2e(ctx: &TestContext) -> anyhow::Result<()> {
    let domain = "wildcard-domain.example.com".to_string();
    let wildcard_san = format!("*.{domain}");

    let client = reqwest::Client::new();
    let base_url = format!(
        "http://{}:{}/v1/{domain}",
        ctx.api_server_addr.ip(),
        ctx.api_server_addr.port()
    );

    // Register the domain requesting a wildcard certificate
    let response = client
        .post(format!("{base_url}?wildcard=true"))
        .send()
        .await?;
    assert!(
        response.status().is_success(),
        "wildcard registration request was rejected: {}",
        response.status()
    );

    wait_for_all_tasks_completion(&ctx.canister_repository).await?;
    verify_domains_registration(ctx, &vec![domain.clone()]).await?;

    // Download the freshly issued certificate and verify both SANs are present
    let registered_domains = ctx.canister_repository.all_registrations(false).await?;
    let registered = registered_domains
        .into_iter()
        .find(|r| r.domain == domain)
        .with_context(|| format!("registered wildcard domain {domain} not found"))?;

    let sans = extract_all_sans_from_cert(registered.cert)?;
    assert!(
        sans.contains(&domain),
        "certificate is missing the bare domain SAN {domain}; SANs: {sans:?}"
    );
    assert!(
        sans.contains(&wildcard_san),
        "certificate is missing the wildcard SAN {wildcard_san}; SANs: {sans:?}"
    );

    // Clean up so later registration-count assertions remain valid
    let response = client.delete(&base_url).send().await?;
    assert!(response.status().is_success());
    verify_domains_deletion(ctx, vec![domain]).await?;

    Ok(())
}

async fn delete_half_domains(
    ctx: &TestContext,
    domains: Vec<String>,
) -> anyhow::Result<Vec<String>> {
    let domains_to_delete = domains[..(DOMAINS_COUNT / 2)].to_vec();

    let client = reqwest::Client::new();

    for domain in domains_to_delete.clone() {
        let response = client
            .delete(format!(
                "http://{}:{}/v1/{}",
                ctx.api_server_addr.ip(),
                ctx.api_server_addr.port(),
                domain
            ))
            .send()
            .await?;
        assert!(response.status().is_success());
    }

    Ok(domains_to_delete)
}

async fn verify_domains_deletion(
    ctx: &TestContext,
    deleted_domains: Vec<String>,
) -> anyhow::Result<()> {
    for domain in deleted_domains {
        let mut sleep_interval = INIT_CANISTER_CALL_RETRY_DELAY;
        loop {
            let status = ctx
                .canister_repository
                .get_domain_status(&domain.parse()?)
                .await?;
            if status.is_none() {
                break;
            }
            info!("Domain {domain} is not yet deleted, sleeping {sleep_interval:?} ...");
            sleep(sleep_interval).await;
            sleep_interval = 2 * sleep_interval;
            sleep_interval = sleep_interval.min(MAX_CANISTER_CALL_RETRY_DELAY)
        }
    }
    Ok(())
}

async fn verify_canister_metrics(ctx: &TestContext) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    let metrics_text = client
        .get(format!(
            "http://{}.raw.{}:{}/metrics",
            ctx.pocket_ic_env.canister_id,
            ctx.http_gateway_url.domain().unwrap(),
            ctx.http_gateway_url.port().unwrap(),
        ))
        .send()
        .await?
        .text()
        .await?;

    assert!(metrics_text.contains(&format!(
        "domains_total{{registration_status=\"registered\"}} {}",
        DOMAINS_COUNT / 2
    )));
    assert!(metrics_text.contains("domains_total{registration_status=\"expired\"} 0"));
    assert!(metrics_text.contains("domains_total{registration_status=\"failed\"} 0"));
    assert!(metrics_text.contains("domains_total{registration_status=\"registering\"} 0"));

    Ok(())
}

async fn verify_workers_metrics(metrics: Arc<WorkerMetrics>) -> anyhow::Result<bool> {
    for i in 0..WORKERS_COUNT {
        let worker_name = format!("worker_{}", i + 1);
        let worker_name = worker_name.as_str();

        let issue_tasks = metrics
            .task_submissions
            .get_metric_with_label_values(&[
                worker_name, // worker_name
                "issue",     // task_kind
                "success",   // status
                "1",         // attempts
                "",          // last_failure
            ])?
            .get();

        let delete_tasks = metrics
            .task_submissions
            .get_metric_with_label_values(&[
                worker_name, // worker_name
                "delete",    // task_kind
                "success",   // status
                "1",         // attempts
                "",          // last_failure
            ])?
            .get();

        info!("Worker {worker_name} has processed {issue_tasks} issue tasks");
        info!("Worker {worker_name} has processed {delete_tasks} delete tasks");

        if issue_tasks == 0 || delete_tasks == 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn verify_workers_metrics_with_retries(metrics: Arc<WorkerMetrics>) -> anyhow::Result<bool> {
    // As workers update their own metrics only after execution of update+read call to the canister, it may take some time till metrics are updated
    let max_retries = 10;
    let max_delay = Duration::from_secs(2);
    let mut retries = 0;
    let mut sleep_interval = Duration::from_millis(200);
    loop {
        if verify_workers_metrics(metrics.clone()).await? {
            return Ok(true);
        }
        if retries >= max_retries {
            bail!("Workers metrics did not reach expected values after {max_retries} retries");
        }
        info!("Workers metrics not ready, sleeping {sleep_interval:?} ...");
        sleep(sleep_interval).await;
        sleep_interval = 2 * sleep_interval;
        sleep_interval = sleep_interval.min(max_delay);
        retries += 1;
    }
}

fn extract_domain_from_cert(cert: Vec<u8>) -> anyhow::Result<String> {
    let cert_domains = extract_all_sans_from_cert(cert)?;
    Ok(cert_domains[0].clone())
}

/// Extracts all DNS Subject Alternative Names from the first certificate in the PEM chain.
fn extract_all_sans_from_cert(cert: Vec<u8>) -> anyhow::Result<Vec<String>> {
    // Parse certificate chain
    let pem_str =
        std::str::from_utf8(&cert).with_context(|| "Certificate contains invalid UTF-8")?;

    let pems = parse_many(pem_str).with_context(|| "Failed to parse PEM certificates")?;

    let Some(first_cert) = pems.first() else {
        bail!("No certificates found in PEM chain");
    };

    // Parse certificate
    let (_, cert) = parse_x509_certificate(first_cert.contents())
        .with_context(|| "Failed to parse X509 certificate")?;

    // Collect all DNS SANs from the issued certificate
    let subject_alt_names = cert
        .subject_alternative_name()?
        .map(|ext| &ext.value.general_names)
        .with_context(|| "Certificate has no Subject Alternative Name")?;

    let cert_domains: Vec<String> = subject_alt_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect();

    Ok(cert_domains)
}

pub fn test_identity() -> BasicIdentity {
    BasicIdentity::from_pem(
        &b"-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIJKDIfd1Ybt48Z23cVEbjL2DGj1P5iDYmthcrptvBO3z
oSMDIQCJuBJPWt2WWxv0zQmXcXMjY+fP0CJSsB80ztXpOFd2ZQ==
-----END PRIVATE KEY-----"[..],
    )
    .expect("failed to parse identity from PEM")
}
