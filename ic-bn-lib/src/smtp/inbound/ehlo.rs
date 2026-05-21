use std::str::FromStr;

use fqdn::FQDN;

use crate::{
    network::AsyncReadWrite,
    smtp::inbound::{Session, SessionResult},
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles EHLO/HELO commands
    pub async fn handle_ehlo(&mut self, host: &str, extended: bool) -> SessionResult<()> {
        // Validate hostname
        let Ok(ehlo_hostname) = FQDN::from_str(host) else {
            return self.reply("550", "5.5.0", "Invalid EHLO hostname.").await;
        };

        // If EHLO hostname is already set to the same value - just reply directly,
        // avoid redundant checks
        if let Some(v) = &self.data.ehlo_hostname
            && v == &ehlo_hostname
        {
            return self.send_ehlo(extended).await;
        }

        if ehlo_hostname.depth() < 2 {
            return self
                .reply("550", "5.5.0", "EHLO hostname must be an FQDN.")
                .await;
        };

        // Check if EHLO hostname resolves if configured
        if self.cfg.verify_ehlo_hostname {
            match self.cfg.authenticator.resolver().lookup_ip(host).await {
                Ok(v) => {
                    if v.iter().next().is_none() {
                        return self
                            .reply("550", "5.5.0", "EHLO hostname not found in DNS.")
                            .await;
                    }
                }

                Err(e) => {
                    if e.is_no_records_found() {
                        return self
                            .reply("550", "5.5.0", "EHLO hostname not found in DNS.")
                            .await;
                    }

                    return self
                        .reply("451", "4.7.25", "Temporary error validating EHLO hostname.")
                        .await;
                }
            }
        }

        self.reset_message();
        self.data.ehlo_hostname = Some(ehlo_hostname);

        return self.send_ehlo(extended).await;
    }

    async fn send_ehlo(&mut self, extended: bool) -> SessionResult<()> {
        let buf = if !extended {
            &self.cfg.helo
        } else if self.tls_info.is_none() && self.cfg.tls_mode.enabled() {
            &self.cfg.ehlo_tls
        } else {
            &self.cfg.ehlo
        };

        self.write(&buf.clone()).await
    }
}
