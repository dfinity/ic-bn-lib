use std::{path::PathBuf, time::Duration};

use candid::Principal;
use clap::Args;
use fqdn::FQDN;
use humantime::parse_duration;
use reqwest::Url;

use crate::tls::acme::{AcmeUrl, dns::cloudflare::DEFAULT_CLOUDFLARE_URL};

#[derive(Debug, Args)]
pub struct CustomDomainsCli {
    /// Domain name to access the IC (used to interact with the Custom Domains management canister).
    #[clap(env, long, default_value = "icp0.io")]
    pub custom_domains_ic_domain: FQDN,

    /// Comma-separated validation domains used to verify canister ownership via
    /// https://<canister-id>.<validation-domain>/.well-known/ic-domains (tried in order until one succeeds).
    #[clap(env, long, value_delimiter = ',', default_values = ["icp0.io", "ic0.app"])]
    pub custom_domains_validation_domains: Vec<FQDN>,

    /// Path to an IC identity file (PEM-encoded)
    #[clap(env, long, required = false)]
    pub custom_domains_ic_identity: PathBuf,

    /// Path to an IC root key.
    /// If not specified - hardcoded one will be used.
    #[clap(env, long)]
    pub custom_domains_ic_root_key: Option<PathBuf>,

    /// ID of the management canister
    #[clap(env, long, required = false)]
    pub custom_domains_canister_id: Principal,

    /// How frequently the canister client would poll it for changes to the data.
    #[clap(env, long, value_parser = parse_duration, default_value = "5s")]
    pub custom_domains_canister_poll_interval: Duration,

    /// How frequently to perform the full sync of the certificates from the canister irrespecive
    /// of the the changes timestamp
    #[clap(env, long, value_parser = parse_duration, default_value = "5m")]
    pub custom_domains_canister_refresh_interval: Duration,

    /// Cloudflare API URL
    #[clap(env, long, default_value = DEFAULT_CLOUDFLARE_URL)]
    pub custom_domains_cloudflare_url: Url,

    /// Token to access Cloudflare API
    #[clap(env, long, required = false)]
    pub custom_domains_cloudflare_token: String,

    /// Encryption key to encrypt/decrypt certificates in the canister storage.
    /// Must be exactly 256 bits / 32 bytes and Base64-encoded.
    #[clap(env, long, required = false)]
    pub custom_domains_encryption_key: String,

    /// Domain that the clients delegate their entries (ACME & canister) to
    #[clap(env, long, default_value = "icp2.io")]
    pub custom_domains_delegation_domain: FQDN,

    /// Which ACME provider URL to use. Can be "le_stag", "le_prod" for LetsEncrypt, or a custom URL.
    /// Defaults to "le_stag".
    #[clap(env, long, default_value = "le_stag")]
    pub custom_domains_acme_url: AcmeUrl,

    /// Path to a JSON file with ACME account data
    #[clap(env, long, required = false)]
    pub custom_domains_acme_account: PathBuf,

    /// How many worker tasks to spawn
    #[clap(env, long, default_value = "1")]
    pub custom_domains_workers_count: usize,
}
