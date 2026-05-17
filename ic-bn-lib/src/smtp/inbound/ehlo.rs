use std::str::FromStr;

use fqdn::FQDN;
use mail_auth::hickory_resolver::proto::ProtoErrorKind;
use smtp_proto::{
    EXT_8BIT_MIME, EXT_CHUNKING, EXT_ENHANCED_STATUS_CODES, EXT_SMTP_UTF8, EXT_START_TLS,
    EhloResponse,
};

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

        // If EHLO hostname is already set to the same value - just reply directly
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
                    if matches!(e.kind(), ProtoErrorKind::NoRecordsFound(_)) {
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
        if !extended {
            return self
                .write(format!("250 {} you had me at HELO\r\n", self.cfg.hostname).as_bytes())
                .await;
        }

        let mut response = EhloResponse::new(self.cfg.hostname.as_str());
        response.capabilities =
            EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_SMTP_UTF8 | EXT_CHUNKING;
        response.size = self.cfg.max_message_size;

        // Send STARTTLS cap only if we support TLS & we're not already in TLS mode
        if self.tls_info.is_none() && self.cfg.tls_enabled() {
            response.capabilities |= EXT_START_TLS;
        }

        let mut buf = Vec::with_capacity(128);
        response.write(&mut buf).ok();

        self.write(&buf).await
    }
}
