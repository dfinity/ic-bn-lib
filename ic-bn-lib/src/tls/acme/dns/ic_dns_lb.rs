use anyhow::{Context, Error};
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
    /// Create a new Cloudflare client with a default HTTP client
    pub fn new(base_urls: Vec<Url>, token: String) -> Result<Self, Error> {
        let client = Client::builder()
            .build()
            .context("failed to initialize HTTP client")?;

        Ok(Self::new_with_http_client(base_urls, client, token))
    }

    /// Create a new Cloudflare client with a provided HTTP client.
    /// Client needs to set the authentication token itself.
    pub const fn new_with_http_client(base_urls: Vec<Url>, client: Client, token: String) -> Self {
        Self {
            client,
            base_urls,
            token,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AcmeChallengeRequest {
    pub challenge: String,
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
            let url: Url = format!("{url}/acme-challenge/set/{zone}")
                .parse()
                .context("unable to parse URL")?;

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
            let url: Url = format!("{url}/acme-challenge/unset/{zone}")
                .parse()
                .context("unable to parse URL")?;

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
