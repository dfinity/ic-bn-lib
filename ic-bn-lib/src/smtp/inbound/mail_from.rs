use std::{borrow::Cow, fmt::Write, str::FromStr};

use mail_auth::{IprevResult, Parameters, SpfResult, spf::verify::SpfParameters};
use smtp_proto::{MAIL_BY_NOTIFY, MAIL_BY_RETURN, MailFrom};

use crate::{
    network::AsyncReadWrite,
    smtp::{
        address::EmailAddress,
        inbound::{Session, SessionResult},
    },
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles MAIL FROM command
    pub async fn handle_mail_from(&mut self, from: MailFrom<Cow<'_, str>>) -> SessionResult<()> {
        let Some(helo_hostname) = &self.data.ehlo_hostname else {
            return self
                .reply("503", "5.5.1", "Polite people say EHLO first.")
                .await;
        };

        if self.data.mail_from.is_some() {
            return self
                .reply(
                    "503",
                    "5.5.1",
                    "Multiple MAIL FROM commands are not allowed.",
                )
                .await;
        }

        if (from.flags & (MAIL_BY_NOTIFY | MAIL_BY_RETURN)) != 0 {
            return self.ext_unsupported("DELIVERBY").await;
        }

        if from.mt_priority != 0 {
            return self.ext_unsupported("MT-PRIORITY").await;
        }

        if from.size > self.cfg.max_message_size {
            return self.message_too_big().await;
        }

        if from.hold_for != 0 || from.hold_until != 0 {
            return self.ext_unsupported("FUTURERELEASE").await;
        }

        if from.env_id.is_some() {
            return self.ext_unsupported("DSN").await;
        }

        // Validate address
        let Ok(address) = EmailAddress::from_str(&from.address) else {
            return self
                .reply("550", "5.7.1", "Sender address is incorrect.")
                .await;
        };

        // Validate reverse IP if configured
        if self.cfg.verify_reverse_ip {
            let result = self
                .cfg
                .authenticator
                .verify_iprev(Parameters::from(self.remote_ip))
                .await
                .result;

            if !matches!(result, IprevResult::Pass) {
                let (code, ext, msg) = if matches!(result, IprevResult::TempError(_)) {
                    ("451", "4.7.25", "Temporary error validating reverse DNS.")
                } else {
                    ("550", "5.7.25", "Reverse DNS validation failed.")
                };

                return self.reply(code, ext, msg).await;
            }
        }

        if self.cfg.verify_spf {
            let output = self
                .cfg
                .authenticator
                .verify_spf(SpfParameters::verify_mail_from(
                    self.remote_ip,
                    &helo_hostname.to_string(),
                    &self.cfg.hostname,
                    &from.address,
                ))
                .await;

            match output.result() {
                SpfResult::Pass | SpfResult::Neutral | SpfResult::None => {}
                SpfResult::TempError => {
                    return self
                        .reply("451", "4.7.24", "Temporary SPF validation error.")
                        .await;
                }
                SpfResult::Fail | SpfResult::PermError | SpfResult::SoftFail => {
                    let mut msg = "SPF validation failed".to_string();
                    if let Some(v) = output.explanation() {
                        write!(msg, ": {v}.").ok();
                    }
                    write!(msg, "\r\n").ok();

                    return self.reply("550", "5.7.23", &msg).await;
                }
            }
        }

        self.reply("250", "2.1.0", "OK").await?;
        self.data.mail_from = Some(address);
        Ok(())
    }
}
