use std::{borrow::Cow, io, str::FromStr};

use fqdn::FQDN;
use mail_auth::{IprevResult, Parameters};
use smtp_proto::{
    EXT_8BIT_MIME, EXT_ENHANCED_STATUS_CODES, EXT_SMTP_UTF8, EXT_START_TLS, EhloResponse, MailFrom,
};

use crate::{
    network::AsyncReadWrite,
    smtp::{address::EmailAddress, session::Session},
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles MAIL FROM command
    pub async fn handle_mail_from(&mut self, from: MailFrom<Cow<'_, str>>) -> io::Result<()> {
        if self.data.helo_hostname.is_none() {
            return self
                .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                .await;
        }

        if self.data.mail_from.is_some() {
            return self
                .write(b"503 5.5.1 Multiple MAIL FROM commands not allowed.\r\n")
                .await;
        }

        // Validate address
        let Ok(address) = EmailAddress::from_str(&from.address) else {
            return self
                .write(b"550 5.7.1 Sender address is incorrect.\r\n")
                .await;
        };

        // Validate reverse IP if configured
        if self.params.verify_reverse_ip {
            let result = self
                .authenticator
                .verify_iprev(Parameters::from(self.remote_ip))
                .await
                .result;

            if !matches!(result, IprevResult::Pass) {
                let message = if matches!(result, IprevResult::TempError(_)) {
                    &b"451 4.7.25 Temporary error validating reverse DNS.\r\n"[..]
                } else {
                    &b"550 5.7.25 Reverse DNS validation failed.\r\n"[..]
                };

                return self.write(message).await;
            }
        }

        self.data.mail_from = Some(address);
        Ok(())
    }
}
