use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use cloudflare::{
    endpoints::{
        dns::dns::{
            CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, DnsRecord,
            ListDnsRecords, ListDnsRecordsParams,
        },
        zones::zone::{ListZones, ListZonesParams, Zone},
    },
    framework::{
        Environment,
        auth::Credentials,
        client::{ClientConfig, async_api::Client},
        response::ApiSuccess,
    },
};
use tracing::debug;
use url::Url;

use super::{DnsManager, Record};

impl TryFrom<DnsContent> for Record {
    type Error = Error;

    fn try_from(value: DnsContent) -> Result<Self, Self::Error> {
        match value {
            DnsContent::TXT { content } => Ok(Self::Txt(content)),
            _ => Err(anyhow!("not supported")),
        }
    }
}

pub struct Cloudflare {
    client: Client,
}

impl Cloudflare {
    pub fn new(url: Url, token: String) -> Result<Self, Error> {
        let credentials = Credentials::UserAuthToken { token };

        let client = Client::new(
            credentials,
            ClientConfig::default(),
            Environment::Custom(url.to_string()),
        )
        .context("failed to initialize cloudflare api client")?;

        Ok(Self { client })
    }

    async fn find_zone(&self, zone: &str) -> Result<String, Error> {
        let resp = self
            .client
            .request(&ListZones {
                params: ListZonesParams {
                    name: Some(zone.into()),
                    status: None,
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        let zone_id = match resp.result.first() {
            Some(Zone { id, .. }) => id.clone(),
            None => return Err(anyhow!("zone '{zone}' not found")),
        };

        Ok(zone_id)
    }

    async fn find_record(
        &self,
        zone_id: &str,
        name: String,
    ) -> Result<ApiSuccess<Vec<DnsRecord>>, Error> {
        let resp = self
            .client
            .request(&ListDnsRecords {
                zone_identifier: zone_id,
                params: ListDnsRecordsParams {
                    record_type: None,
                    name: Some(name),
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        Ok(resp)
    }
}

#[async_trait]
impl DnsManager for Cloudflare {
    async fn create(&self, zone: &str, name: &str, record: Record, ttl: u32) -> Result<(), Error> {
        // Find zone
        let zone_id = self
            .find_zone(zone)
            .await
            .context(format!("unable to find zone '{zone}'"))?;

        // Create record
        let content = match record {
            Record::Txt(content) => DnsContent::TXT { content },
        };

        self.client
            .request(&CreateDnsRecord {
                zone_identifier: &zone_id,
                params: CreateDnsRecordParams {
                    ttl: Some(ttl),
                    priority: None,
                    proxied: None,
                    name,
                    content,
                },
            })
            .await?;

        Ok(())
    }

    async fn delete(&self, zone: &str, name: &str) -> Result<(), Error> {
        // Find zone
        let zone_id = self
            .find_zone(zone)
            .await
            .context(format!("unable to find zone '{zone}'"))?;

        // Find records
        let resp = self
            .find_record(&zone_id, format!("{name}.{zone}"))
            .await
            .context("unable to find records")?;

        // Delete all matching TXT records
        for record in resp
            .result
            .into_iter()
            .filter(|r| matches!(&r.content, DnsContent::TXT { .. }))
        {
            debug!("deleting record {} in Cloudflare", record.name);

            self.client
                .request(&DeleteDnsRecord {
                    zone_identifier: &zone_id,
                    identifier: &record.id,
                })
                .await?;
        }

        Ok(())
    }
}
