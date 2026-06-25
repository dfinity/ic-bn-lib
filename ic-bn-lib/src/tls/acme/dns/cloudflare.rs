use super::{DnsManager, Record};
use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use tracing::debug;

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
    pub fn new(base_url: Url, token: String) -> Result<Self, Error> {
        let client = Client::builder()
            .build()
            .context("failed to initialize HTTP client")?;

        Ok(Self {
            client,
            base_url,
            token,
        })
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
    async fn delete(&self, zone: &str, name: &str) -> Result<(), Error> {
        let zone_id = self
            .find_zone(zone)
            .await
            .with_context(|| format!("unable to find zone '{zone}'"))?;

        let fqdn = format!("{name}.{zone}");

        let records = self
            .find_records(&zone_id, &fqdn)
            .await
            .context("unable to find records")?;

        for record in records
            .into_iter()
            .filter(|r| r.record_type.eq_ignore_ascii_case("TXT"))
        {
            debug!("deleting record {} in Cloudflare", record.name);

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
