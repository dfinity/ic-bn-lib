use std::{io, str::FromStr};

use ahash::AHashSet;
use fqdn::FQDN;
use mail_auth::hickory_resolver::proto::{ProtoErrorKind, rr::RecordType};
use smtp_proto::{
    EXT_8BIT_MIME, EXT_ENHANCED_STATUS_CODES, EXT_SMTP_UTF8, EXT_START_TLS, EhloResponse,
};
use tracing::info;

use crate::{network::AsyncReadWrite, smtp::session::Session};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles HELO/EHLO commands
    pub async fn handle_helo(&mut self, domain: &str) -> io::Result<()> {
        // Validate hostname
        let Ok(helo_hostname) = FQDN::from_str(domain) else {
            return self.write(b"550 5.5.0 Invalid EHLO hostname.\r\n").await;
        };
        if helo_hostname.depth() < 2 {
            return self
                .write(b"550 5.5.0 EHLO hostname must be an FQDN.\r\n")
                .await;
        };

        // Check if EHLO hostname resolves if configured
        if self.params.verify_ehlo_hostname {
            match self.authenticator.resolver().lookup_ip(domain).await {
                Ok(v) => {
                    if v.iter().next().is_none() {
                        return self
                            .write(b"550 5.5.0 EHLO hostname not found in DNS.\r\n")
                            .await;
                    }
                }

                Err(e) => {
                    if matches!(e.kind(), ProtoErrorKind::NoRecordsFound(_)) {
                        return self
                            .write(b"550 5.5.0 EHLO hostname not found in DNS.\r\n")
                            .await;
                    }

                    info!("Unable to lookup '{domain}' in DNS: {e:#}");
                    return self
                        .write(b"451 4.7.25 Temporary error validating EHLO hostname.\r\n")
                        .await;
                }
            }
        }

        self.data.helo_hostname = Some(helo_hostname);
        self.data.mail_from = None;
        self.data.rcpt_to = AHashSet::new();

        let mut response = EhloResponse::new(self.hostname.as_str());
        response.capabilities = EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_SMTP_UTF8;

        // Send STARTTLS cap only if we support TLS & we're not already in TLS mode
        if !self.in_starttls && self.tls_config.is_some() {
            response.capabilities |= EXT_START_TLS;
        }

        let mut buf = Vec::with_capacity(128);
        response.write(&mut buf).ok();

        self.write(&buf).await
    }
}
