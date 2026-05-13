use std::{io, str::FromStr};

use fqdn::FQDN;
use smtp_proto::{
    EXT_8BIT_MIME, EXT_ENHANCED_STATUS_CODES, EXT_SMTP_UTF8, EXT_START_TLS, EhloResponse,
};

use crate::{network::AsyncReadWrite, smtp::session::Session};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles HELO/EHLO messages
    pub async fn handle_helo(&mut self, domain: &str) -> io::Result<()> {
        // Validate hostname
        let Ok(helo_hostname) = FQDN::from_str(domain) else {
            return self.write(b"550 5.5.0 Invalid EHLO hostname.\r\n").await;
        };

        self.data.helo_hostname = Some(helo_hostname);

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
