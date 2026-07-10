use std::{sync::Arc, time::Duration};

use anyhow::Context;
use instant_acme::AccountCredentials;
use reqwest::Url;

use crate::{
    dns::{Options as DnsOptions, resolvers::Resolver},
    tls::acme::{
        AcmeUrl,
        client::{Client, ClientBuilder},
        dns::{
            TokenManagerDns,
            cloudflare::{Cloudflare, DEFAULT_CLOUDFLARE_URL},
        },
    },
};

const DEFAULT_POLL_ORDER_TIMEOUT: Duration = Duration::from_secs(140);
const DEFAULT_POLL_TOKEN_TIMEOUT: Duration = Duration::from_secs(140);

/// Configuration for ACME client setup and certificate operations.
pub struct AcmeClientConfig {
    /// Cloudflare API token for authentication
    pub cloudflare_api_token: String,
    /// Base URL for Cloudflare API requests
    pub cloudflare_url: Url,
    /// ACME provider URL, e.g. staging letsencrypt https://acme-staging-v02.api.letsencrypt.org/directory
    pub acme_url: AcmeUrl,
    /// ACME account credentials
    pub acme_credentials: Option<AccountCredentials>,
    /// Delegation domain to use
    pub delegation_domain: Option<String>,
    /// Whether to allow insecure TLS connections
    pub insecure_tls: bool,
    /// Timeout for polling ACME order status
    pub poll_order_timeout: Duration,
    /// Timeout for token polling, which verifies the dns record is correct
    pub poll_token_timeout: Duration,
    /// DNS options
    pub dns_options: DnsOptions,
}

impl AcmeClientConfig {
    /// Creates a new ACME client configuration with default settings.
    pub fn new(cloudflare_api_token: String) -> Self {
        Self {
            cloudflare_api_token,
            cloudflare_url: Url::parse(DEFAULT_CLOUDFLARE_URL).unwrap(),
            acme_url: AcmeUrl::LetsEncryptStaging,
            acme_credentials: None,
            delegation_domain: None,
            insecure_tls: false,
            poll_order_timeout: DEFAULT_POLL_ORDER_TIMEOUT,
            poll_token_timeout: DEFAULT_POLL_TOKEN_TIMEOUT,
            dns_options: DnsOptions::default(),
        }
    }

    /// Sets a custom Cloudflare API URL.
    pub fn with_cloudflare_url(mut self, url: Url) -> Self {
        self.cloudflare_url = url;
        self
    }

    /// Sets the ACME provider URL (e.g., Let's Encrypt production/staging).
    pub fn with_acme_url(mut self, acme_url: AcmeUrl) -> Self {
        self.acme_url = acme_url;
        self
    }

    /// Sets the delegation domain
    pub fn with_delegation_domain(mut self, delegation_domain: String) -> Self {
        self.delegation_domain = Some(delegation_domain);
        self
    }

    /// Sets existing ACME account credentials to reuse an account.
    pub fn with_credentials(mut self, credentials: AccountCredentials) -> Self {
        self.acme_credentials = Some(credentials);
        self
    }

    /// Enables or disables insecure TLS connections (for testing).
    pub const fn with_insecure_tls(mut self, insecure: bool) -> Self {
        self.insecure_tls = insecure;
        self
    }

    /// Sets the timeout for polling ACME order status.
    pub const fn with_poll_order_timeout(mut self, timeout: Duration) -> Self {
        self.poll_order_timeout = timeout;
        self
    }

    /// Sets the timeout for DNS token verification polling.
    pub const fn with_poll_token_timeout(mut self, timeout: Duration) -> Self {
        self.poll_token_timeout = timeout;
        self
    }

    /// Sets the DNS options to use
    pub fn with_dns_options(mut self, dns_options: DnsOptions) -> Self {
        self.dns_options = dns_options;
        self
    }
}

impl AcmeClientConfig {
    /// Builds an ACME client from this configuration.
    ///
    /// Creates the necessary DNS resolver, Cloudflare integration, and ACME account.
    /// If no credentials are provided, a new account will be created.
    pub async fn build(mut self) -> anyhow::Result<Client> {
        let cloudflare = Arc::new(Cloudflare::new(
            self.cloudflare_url,
            self.cloudflare_api_token,
        )?);

        // DNS resolver
        self.dns_options.opts.cache_size = 0;
        let dns_resolver =
            Resolver::new(self.dns_options).context("unable to create DNS Resolver")?;
        let token_manager = Arc::new(TokenManagerDns::new(
            Arc::new(dns_resolver),
            cloudflare,
            self.delegation_domain,
        ));

        let builder = ClientBuilder::new(self.insecure_tls)
            .with_acme_url(self.acme_url.clone())
            .with_token_manager(token_manager);

        let builder = if let Some(credentials) = self.acme_credentials {
            builder
                .load_account(credentials)
                .await
                .context("unable to load ACME account")?
        } else {
            let (builder, _) = builder
                .create_account("mailto:boundary-nodes@dfinity.org")
                .await
                .context("unable to create ACME account")?;

            builder
        };

        let client = builder
            .with_order_timeout(self.poll_order_timeout)
            .with_token_timeout(self.poll_token_timeout)
            .build()
            .await
            .context("unable to build ACME client")?;

        Ok(client)
    }
}
