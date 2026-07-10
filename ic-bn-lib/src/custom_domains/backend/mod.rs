mod backend_service;
mod handlers;
mod metrics;
mod models;
mod openapi;
pub mod router;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use axum::Router;
use base64::{Engine, prelude::BASE64_STANDARD};
use chacha20poly1305::Key;
use prometheus::Registry;
use tokio::fs;
use tokio_util::sync::CancellationToken;

use crate::{
    custom_domains::{
        base::{
            cli::CustomDomainsCli,
            types::{
                acme::AcmeClientConfig,
                cipher::CertificateCipher,
                validator::Validator,
                worker::{Worker, WorkerConfig, WorkerMetrics},
            },
        },
        client::CanisterClient,
    },
    dns::Options as DnsOptions,
    ic_agent::{Agent, identity::Secp256k1Identity},
    reqwest,
    tls::acme::instant_acme::AccountCredentials,
};
use router::{RateLimitConfig, create_router};

/// Sets up everything required to run Custom Domains.
/// Returns Worker, Axum Router and a CanisterClient to access data.
pub async fn setup(
    cli: &CustomDomainsCli,
    dns_opts: DnsOptions,
    token: CancellationToken,
    hostname: &str,
    metrics_registry: Registry,
    rate_limiter_bypass_token: Option<String>,
) -> Result<(Vec<Worker>, Router, Arc<CanisterClient>), anyhow::Error> {
    let cipher = {
        let key = BASE64_STANDARD
            .decode(&cli.custom_domains_encryption_key)
            .context("unable to decode base64 encryption key")?;

        if key.len() != 32 {
            return Err(anyhow!("encryption key must be exactly 32 bytes long"));
        }

        let key = Key::from_slice(&key);
        let cipher = CertificateCipher::new(key);
        Arc::new(cipher)
    };

    let agent = {
        let key = fs::read(&cli.custom_domains_ic_identity)
            .await
            .context("unable to read identity from file")?;
        let identity =
            Secp256k1Identity::from_pem(key.as_slice()).context("failed to create IC identity")?;

        let client = reqwest::ClientBuilder::new()
            .resolve(
                &cli.custom_domains_ic_domain.to_string(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            )
            .build()
            .context("unable to build Reqwest client")?;

        let agent = Agent::builder()
            .with_identity(identity)
            .with_url(format!("https://{}", cli.custom_domains_ic_domain))
            .with_arc_http_middleware(Arc::new(client))
            .build()?;

        if let Some(path) = &cli.custom_domains_ic_root_key {
            let root_key = fs::read(path).await.context("unable to read IC root key")?;
            agent.set_root_key(root_key);
        }

        agent
    };

    let validator = {
        Arc::new(
            Validator::new(
                cli.custom_domains_delegation_domain.clone(),
                cli.custom_domains_validation_domains.clone(),
                dns_opts.clone(),
            )
            .context("unable to create validator")?,
        )
    };

    let repository = Arc::new(CanisterClient::new(
        agent,
        cli.custom_domains_canister_id,
        cipher,
        cli.custom_domains_canister_poll_interval,
        cli.custom_domains_canister_refresh_interval,
        0,
        None,
    ));

    let acme_client = {
        let creds = fs::read(&cli.custom_domains_acme_account)
            .await
            .context("unable to read ACME credentials from disk")?;
        let creds: AccountCredentials =
            serde_json::from_slice(&creds).context("unable to parse ACME credentials as JSON")?;

        let cfg = AcmeClientConfig::new(cli.custom_domains_cloudflare_token.clone())
            .with_acme_url(cli.custom_domains_acme_url.clone())
            .with_credentials(creds)
            .with_cloudflare_url(cli.custom_domains_cloudflare_url.clone())
            .with_delegation_domain(cli.custom_domains_delegation_domain.to_string())
            .with_dns_options(dns_opts);

        Arc::new(cfg.build().await.context("unable to build ACME client")?)
    };

    let metrics = Arc::new(WorkerMetrics::new(&metrics_registry));
    let mut workers = vec![];

    for i in 0..cli.custom_domains_workers_count {
        let worker = Worker::new(
            format!("{hostname}-{i}"),
            repository.clone(),
            validator.clone(),
            acme_client.clone(),
            WorkerConfig::default(),
            metrics.clone(),
            token.clone(),
        );

        workers.push(worker);
    }

    let router = create_router(
        repository.clone(),
        validator,
        metrics_registry,
        RateLimitConfig::default(),
        false,
        rate_limiter_bypass_token,
    );

    Ok((workers, router, repository))
}
