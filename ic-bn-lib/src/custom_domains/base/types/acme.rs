use std::{sync::Arc, time::Duration};

use anyhow::Context;
use instant_acme::AccountCredentials;
use reqwest::Url;

use crate::{
    dns::{Options as DnsOptions, resolvers::Resolver},
    http::client::ClientOptions,
    tls::acme::{
        AcmeUrl,
        client::{Client, ClientBuilder, HttpClient},
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
            Arc::new(dns_resolver.clone()),
            cloudflare,
            self.delegation_domain,
        ));

        let http_client = HttpClient::new(ClientOptions::default(), dns_resolver);

        let builder = ClientBuilder::new(Box::new(http_client))
            .with_acme_url(self.acme_url.clone())
            .with_token_manager(token_manager);

        let builder = if let Some(credentials) = self.acme_credentials {
            builder
                .load_account(credentials)
                .await
                .context("unable to load ACME account")?
        } else {
            let (builder, _) = builder
                .create_account("boundary-nodes@dfinity.org")
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

#[cfg(test)]
mod test {
    use super::*;

    /// Builds a syntactically valid [`AccountCredentials`] without touching the network.
    /// The key material is arbitrary: deserialization only base64-decodes it.
    fn credentials(id: &str) -> AccountCredentials {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "key_pkcs8": "AQIDBA",
            "directory": "https://acme.example.com/directory",
        }))
        .expect("credentials should deserialize")
    }

    fn account_id(credentials: &AccountCredentials) -> String {
        serde_json::to_value(credentials).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn new_uses_documented_defaults() {
        let cfg = AcmeClientConfig::new("cf-token".to_string());

        assert_eq!(cfg.cloudflare_api_token, "cf-token");
        assert_eq!(cfg.cloudflare_url.as_str(), DEFAULT_CLOUDFLARE_URL);
        // Staging by default: creating an account against production by accident
        // would burn Let's Encrypt rate limits.
        assert_eq!(cfg.acme_url, AcmeUrl::LetsEncryptStaging);
        assert!(cfg.acme_credentials.is_none());
        assert!(cfg.delegation_domain.is_none());
        assert!(!cfg.insecure_tls);
        assert_eq!(cfg.poll_order_timeout, Duration::from_secs(140));
        assert_eq!(cfg.poll_token_timeout, Duration::from_secs(140));
    }

    #[test]
    fn default_cloudflare_url_is_parseable_and_https() {
        let cfg = AcmeClientConfig::new(String::new());
        // Pinned as a literal so that a change to DEFAULT_CLOUDFLARE_URL itself is caught
        // here rather than silently agreeing with the constant.
        assert_eq!(cfg.cloudflare_url.as_str(), "https://api.cloudflare.com/");
        assert_eq!(cfg.cloudflare_url.scheme(), "https");
        assert_eq!(cfg.cloudflare_url.host_str(), Some("api.cloudflare.com"));
    }

    #[test]
    fn with_cloudflare_url_overrides_only_that_field() {
        let url = Url::parse("http://127.0.0.1:8080/base/").unwrap();
        let cfg = AcmeClientConfig::new("t".to_string()).with_cloudflare_url(url.clone());

        assert_eq!(cfg.cloudflare_url, url);
        assert_eq!(cfg.acme_url, AcmeUrl::LetsEncryptStaging);
        assert_eq!(cfg.cloudflare_api_token, "t");
    }

    #[test]
    fn with_acme_url_accepts_custom_and_production() {
        let url = Url::parse("https://acme.example.com/directory").unwrap();
        let cfg =
            AcmeClientConfig::new("t".to_string()).with_acme_url(AcmeUrl::Custom(url.clone()));
        assert_eq!(cfg.acme_url, AcmeUrl::Custom(url));

        let cfg =
            AcmeClientConfig::new("t".to_string()).with_acme_url(AcmeUrl::LetsEncryptProduction);
        assert_eq!(cfg.acme_url, AcmeUrl::LetsEncryptProduction);
    }

    #[test]
    fn with_delegation_domain_wraps_value_in_some() {
        let cfg =
            AcmeClientConfig::new("t".to_string()).with_delegation_domain("icp2.io".to_string());
        assert_eq!(cfg.delegation_domain.as_deref(), Some("icp2.io"));

        // An empty string is stored as-is rather than collapsed into `None`.
        let cfg = AcmeClientConfig::new("t".to_string()).with_delegation_domain(String::new());
        assert_eq!(cfg.delegation_domain.as_deref(), Some(""));
    }

    #[test]
    fn with_credentials_stores_the_account() {
        let cfg = AcmeClientConfig::new("t".to_string()).with_credentials(credentials("acct-42"));

        let stored = cfg.acme_credentials.expect("credentials should be stored");
        assert_eq!(account_id(&stored), "acct-42");
        assert_eq!(stored.private_key().secret_pkcs8_der(), &[1, 2, 3, 4]);
    }

    #[test]
    fn with_credentials_replaces_a_previous_account() {
        let cfg = AcmeClientConfig::new("t".to_string())
            .with_credentials(credentials("acct-1"))
            .with_credentials(credentials("acct-2"));

        let stored = cfg.acme_credentials.unwrap();
        assert_eq!(account_id(&stored), "acct-2");
    }

    #[test]
    fn with_insecure_tls_toggles_both_ways() {
        let cfg = AcmeClientConfig::new("t".to_string()).with_insecure_tls(true);
        assert!(cfg.insecure_tls);

        let cfg = AcmeClientConfig::new("t".to_string())
            .with_insecure_tls(true)
            .with_insecure_tls(false);
        assert!(!cfg.insecure_tls);
    }

    #[test]
    fn poll_timeout_setters_are_independent() {
        let cfg =
            AcmeClientConfig::new("t".to_string()).with_poll_order_timeout(Duration::from_secs(1));
        assert_eq!(cfg.poll_order_timeout, Duration::from_secs(1));
        assert_eq!(cfg.poll_token_timeout, DEFAULT_POLL_TOKEN_TIMEOUT);

        let cfg =
            AcmeClientConfig::new("t".to_string()).with_poll_token_timeout(Duration::from_secs(2));
        assert_eq!(cfg.poll_token_timeout, Duration::from_secs(2));
        assert_eq!(cfg.poll_order_timeout, DEFAULT_POLL_ORDER_TIMEOUT);
    }

    #[test]
    fn zero_poll_timeouts_are_accepted_verbatim() {
        let cfg = AcmeClientConfig::new("t".to_string())
            .with_poll_order_timeout(Duration::ZERO)
            .with_poll_token_timeout(Duration::ZERO);

        assert_eq!(cfg.poll_order_timeout, Duration::ZERO);
        assert_eq!(cfg.poll_token_timeout, Duration::ZERO);
    }

    #[test]
    fn with_dns_options_replaces_the_options() {
        let mut opts = DnsOptions::default();
        opts.opts.cache_size = 4321;

        let cfg = AcmeClientConfig::new("t".to_string()).with_dns_options(opts);
        // `build()` later forces this to 0, but the setter must not do it.
        assert_eq!(cfg.dns_options.opts.cache_size, 4321);
    }

    #[test]
    fn builders_chain_without_clobbering_each_other() {
        let cloudflare_url = Url::parse("http://127.0.0.1:1/").unwrap();
        let acme_url = Url::parse("https://acme.example.com/directory").unwrap();
        let mut dns_options = DnsOptions::default();
        dns_options.opts.cache_size = 7;

        let cfg = AcmeClientConfig::new("cf-token".to_string())
            .with_cloudflare_url(cloudflare_url.clone())
            .with_acme_url(AcmeUrl::Custom(acme_url.clone()))
            .with_delegation_domain("icp2.io".to_string())
            .with_credentials(credentials("acct-9"))
            .with_insecure_tls(true)
            .with_poll_order_timeout(Duration::from_secs(11))
            .with_poll_token_timeout(Duration::from_secs(22))
            .with_dns_options(dns_options);

        assert_eq!(cfg.cloudflare_api_token, "cf-token");
        assert_eq!(cfg.cloudflare_url, cloudflare_url);
        assert_eq!(cfg.acme_url, AcmeUrl::Custom(acme_url));
        assert_eq!(cfg.delegation_domain.as_deref(), Some("icp2.io"));
        assert_eq!(account_id(&cfg.acme_credentials.unwrap()), "acct-9");
        assert!(cfg.insecure_tls);
        assert_eq!(cfg.poll_order_timeout, Duration::from_secs(11));
        assert_eq!(cfg.poll_token_timeout, Duration::from_secs(22));
        assert_eq!(cfg.dns_options.opts.cache_size, 7);
    }
}
