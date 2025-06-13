use anyhow::{Error, anyhow};
use async_trait::async_trait;
use serde_json::json;
use url::Url;

use super::TokenManager;

/// Manages ACME tokens using Pebble Challenge Test Server.
/// To be used for testing only.
pub struct TokenManagerPebble {
    cli: reqwest::Client,
    url: Url,
}

impl TokenManagerPebble {
    pub fn new(url: Url) -> Self {
        Self {
            cli: reqwest::ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            url,
        }
    }
}

#[async_trait]
impl TokenManager for TokenManagerPebble {
    async fn verify(&self, _zone: &str, _token: &str) -> Result<(), Error> {
        // We can't really verify it
        Ok(())
    }

    async fn set(&self, zone: &str, token: &str) -> Result<(), Error> {
        let url = self.url.join("/set-txt").unwrap();
        let body = json!({
            "host" : format!("_acme-challenge.{zone}."),
            "value": token,
        })
        .to_string();

        let res = self.cli.post(url).body(body).send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("Incorrect status code: {}", res.status()));
        }

        Ok(())
    }

    async fn unset(&self, zone: &str) -> Result<(), Error> {
        let url = self.url.join("/clear-txt").unwrap();
        let body = json!({
            "host" : format!("_acme-challenge.{zone}."),
        })
        .to_string();

        let res = self.cli.post(url).body(body).send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("Incorrect status code: {}", res.status()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_token_manager_pebble() {
        let tm = TokenManagerPebble::new("http://127.0.0.1:8055".parse().unwrap());
        tm.set("foo", "bar").await.unwrap();
        tm.unset("foo").await.unwrap();
    }
}
