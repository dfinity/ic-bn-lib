use std::{borrow::Cow, fmt::Write as _, net::IpAddr, str::FromStr};

use hickory_proto::rr::{
    Name, RData,
    rdata::{A, AAAA},
};
use hickory_resolver::net::NetError;
use mail_auth::{SpfResult, spf::verify::SpfParameters};
use smtp_proto::{MAIL_BY_NOTIFY, MAIL_BY_RETURN, MailFrom};
use tracing::{debug, info};

use crate::{
    http::dns::is_error_negative_lookup,
    network::AsyncReadWrite,
    smtp::{
        ProtocolError,
        address::EmailAddress,
        inbound::{Session, SessionResult},
    },
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles MAIL FROM command
    pub async fn handle_mail_from(&mut self, from: MailFrom<Cow<'_, str>>) -> SessionResult<()> {
        let Some(helo_hostname) = self.data.ehlo_hostname.as_ref().map(|x| x.to_string()) else {
            self.set_error(ProtocolError::InvalidSequenceOfCommands(
                "MAIL FROM before EHLO".into(),
            ));
            return self
                .reply("503", "5.5.1", "Polite people say EHLO first.")
                .await;
        };

        if self.data.mail_from.is_some() {
            self.set_error(ProtocolError::InvalidSequenceOfCommands(
                "Multiple MAIL FROM".into(),
            ));
            return self
                .reply(
                    "503",
                    "5.5.1",
                    "Multiple MAIL FROM commands are not allowed.",
                )
                .await;
        }

        if self.cfg.tls_mode.required() && self.tls_info.is_none() {
            return self
                .reply(
                    "503",
                    "5.5.1",
                    "TLS is required to submit mail on this server.",
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
            self.set_error(ProtocolError::MessageTooBig(format!(
                "MAIL FROM-specified size is too big: {} > {}",
                from.size, self.cfg.max_message_size
            )));
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
            info!("{self}: {}: incorrect sender address", from.address);
            self.set_error(ProtocolError::SenderValidationFailed(format!(
                "Incorrect sender address: {}",
                from.address
            )));
            return self
                .reply("550", "5.7.1", "Sender address is incorrect.")
                .await;
        };

        // Validate reverse IP if configured & not yet verified
        if self.cfg.verify_reverse_ip && !self.data.reverse_ip_verified {
            if !self.verify_reverse_ip().await? {
                return Ok(());
            }

            self.data.reverse_ip_verified = true;
            debug!("{self}: reverse IP verification succeeded");
        }

        if self.cfg.verify_sender_domain {
            if address.domain().depth() < 2 {
                info!("{self}: {address}: sender domain verification failed: not FQDN");
                self.set_error(ProtocolError::SenderValidationFailed(format!(
                    "Sender domain is not FQDN: {}",
                    address.domain()
                )));
                return self.reply("550", "5.7.2", "Sender must be an FQDN.").await;
            };

            match self
                .cfg
                .authenticator
                .resolver()
                .mx_lookup(&address.domain().to_string())
                .await
            {
                Ok(v) => {
                    if v.answers().is_empty() {
                        info!(
                            "{self}: {address}: sender domain verification failed: no MX records found"
                        );
                        self.set_error(ProtocolError::SenderValidationFailed(
                            "No MX records found".into(),
                        ));
                        return self
                            .reply(
                                "550",
                                "5.7.25",
                                "No MX record matching your sender domain found.",
                            )
                            .await;
                    }
                }
                Err(e) => {
                    if is_error_negative_lookup(&e) {
                        info!(
                            "{self}: {address}: sender domain verification failed: no MX records found"
                        );
                        self.set_error(ProtocolError::SenderValidationFailed(
                            "No MX records found".into(),
                        ));
                        return self
                            .reply(
                                "550",
                                "5.7.25",
                                "No MX record matching your sender domain found.",
                            )
                            .await;
                    } else {
                        info!(
                            "{self}: {address}: sender domain verification failed: temporary error: {e:#}"
                        );
                        self.set_error(ProtocolError::SenderValidationFailed(format!(
                            "Sender domain verification temporary error: {e:#}",
                        )));
                        return self
                            .reply("451", "4.7.25", "Temporary error validating sender domain.")
                            .await;
                    }
                }
            }

            debug!("{self}: sender domain verification succeeded");
        }

        if self.cfg.verify_spf {
            let output = self
                .cfg
                .authenticator
                .verify_spf(SpfParameters::verify_mail_from(
                    self.remote_ip,
                    &helo_hostname,
                    &self.cfg.hostname,
                    &from.address,
                ))
                .await;

            match output.result() {
                SpfResult::Pass | SpfResult::Neutral | SpfResult::None => {}
                SpfResult::TempError => {
                    info!(
                        "{self}: {address}: SPF validation failed: temporary error: {:?}",
                        output.explanation()
                    );
                    self.set_error(ProtocolError::SpfValidationFailed(format!(
                        "SPF validation temporary error: {:?}",
                        output.explanation()
                    )));
                    return self
                        .reply("451", "4.7.24", "Temporary SPF validation error.")
                        .await;
                }
                SpfResult::Fail | SpfResult::PermError | SpfResult::SoftFail => {
                    info!(
                        "{self}: {address}: SPF validation failed: permanent error: {:?}",
                        output.explanation()
                    );
                    self.set_error(ProtocolError::SpfValidationFailed(format!(
                        "SPF validation permanent error: {:?}",
                        output.explanation()
                    )));
                    return self
                        .reply_with("550", "5.7.23", |buf| {
                            write!(buf, "SPF validation failed")?;
                            if let Some(v) = output.explanation() {
                                write!(buf, ": {v}")?;
                            }
                            Ok(())
                        })
                        .await;
                }
            }

            debug!("{self}: {address}: SPF verification succeeded");
        }

        self.reply("250", "2.1.0", "OK").await?;
        self.data.mail_from = Some(address);

        Ok(())
    }

    /// Replies about failed reverse IP verification
    async fn verify_reverse_ip_reply(&mut self, permanent: bool, msg: &str) -> SessionResult<bool> {
        self.set_error(ProtocolError::ReverseIpValidationFailed(msg.into()));

        // Emit permanent errors only if in strict mode
        if permanent && self.cfg.verify_reverse_ip_strict {
            self.reply_with("550", "5.7.25", |buf| {
                write!(buf, "Reverse DNS validation failed: {msg}")
            })
            .await?;
        } else {
            self.reply_with("451", "4.7.25", |buf| {
                write!(buf, "Temporary error validating reverse DNS: {msg}")
            })
            .await?;
        }

        Ok(false)
    }

    /// Checks if given PTR resolves back to the client's IP
    async fn verify_reverse_ip_ptr(&self, ptr: Name) -> Result<bool, NetError> {
        let remote_ip = self.remote_ip;

        match remote_ip {
            IpAddr::V4(v4) => {
                let lookup = self.cfg.authenticator.resolver().ipv4_lookup(ptr).await?;

                // Check if any of the addresses match the client's
                if lookup.answers().iter().any(|x| x.data == RData::A(A(v4))) {
                    return Ok(true);
                }
            }

            IpAddr::V6(v6) => {
                let lookup = self.cfg.authenticator.resolver().ipv6_lookup(ptr).await?;

                // Check if any of the addresses match the client's
                if lookup
                    .answers()
                    .iter()
                    .any(|x| x.data == RData::AAAA(AAAA(v6)))
                {
                    return Ok(true);
                }
            }
        };

        Ok(false)
    }

    /// Verifies correctness of the client's reverse IP mapping
    async fn verify_reverse_ip(&mut self) -> SessionResult<bool> {
        let remote_ip = self.remote_ip;

        // Get PTR records
        let lookup = match self
            .cfg
            .authenticator
            .resolver()
            .reverse_lookup(remote_ip)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                info!("{self}: reverse IP verification failed: PTR lookup failed: {e:#}");
                return self
                    .verify_reverse_ip_reply(
                        is_error_negative_lookup(&e),
                        "unable to look up PTR record",
                    )
                    .await;
            }
        };

        if lookup.answers().is_empty() {
            info!("{self}: reverse IP verification failed: no PTR records");
            return self
                .verify_reverse_ip_reply(true, "no PTR records found")
                .await;
        }

        // In non-strict mode we're already happy
        if !self.cfg.verify_reverse_ip_strict {
            return Ok(true);
        }

        // Take max 3 PTRs from the response to avoid DoS.
        // Usually there should be only one anyway.
        let mut last_error = None;
        for ptr in lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.to_lowercase()),
                _ => None,
            })
            .take(3)
        {
            match self.verify_reverse_ip_ptr(ptr).await {
                Ok(v) => {
                    if v {
                        return Ok(true);
                    }
                }
                Err(e) => {
                    info!("{self}: reverse IP verification: PTR->IP lookup failed: {e:#}");
                    last_error = Some(e);
                }
            }
        }

        // Return the last error if there was any
        if let Some(e) = last_error {
            return self
                .verify_reverse_ip_reply(
                    is_error_negative_lookup(&e),
                    "unable to look up IP for the PTR record",
                )
                .await;
        }

        // Otherwise everything succeeded but no matches were found
        info!(
            "{self}: reverse IP verification failed: no addresses matching client's IP found after resolving PTR"
        );
        return self
            .verify_reverse_ip_reply(
                true,
                "no addresses matching client's IP found after resolving PTR",
            )
            .await;
    }
}
