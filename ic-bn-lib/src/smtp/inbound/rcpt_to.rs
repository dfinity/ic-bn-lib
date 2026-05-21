use std::{borrow::Cow, fmt::Write, str::FromStr};

use smtp_proto::{
    RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, RcptTo,
};

use crate::{
    network::AsyncReadWrite,
    smtp::{
        RecipientPolicy, RecipientResolveError,
        address::EmailAddress,
        inbound::{Session, SessionResult},
    },
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles RCPT TO command
    pub async fn handle_rcpt_to(&mut self, to: RcptTo<Cow<'_, str>>) -> SessionResult<()> {
        let Some(mail_from) = &self.data.mail_from else {
            return self
                .reply("503", "5.5.1", "MAIL FROM is required first.")
                .await;
        };

        // Check if DSN-related stuff was requested
        if (to.flags
            & (RCPT_NOTIFY_DELAY | RCPT_NOTIFY_NEVER | RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE))
            != 0
            || to.orcpt.is_some()
        {
            return self.ext_unsupported("DSN").await;
        }

        let Ok(address) = EmailAddress::from_str(&to.address) else {
            return self.reply("550", "5.1.2", "Incorrect address.").await;
        };

        if self.data.rcpt_to.contains(&address) {
            return self.reply("250", "2.1.5", "OK").await;
        }

        if self.data.rcpt_to.len() >= self.cfg.max_recipients {
            return self.reply("455", "4.5.3", "Too many recipients.").await;
        }

        match self
            .cfg
            .recipient_resolver
            .resolve_recipient(mail_from, &address)
            .await
        {
            Ok(v) => match v {
                RecipientPolicy::Accept => {
                    self.data.rcpt_to.push(address);
                }
                RecipientPolicy::Rewrite(new_address) => {
                    self.data.rcpt_to.push(new_address);
                }
                RecipientPolicy::Expand(additional_addresses) => {
                    self.data.rcpt_to.push(address);
                    self.data.rcpt_to.extend(additional_addresses);
                }
            },

            Err(e) => {
                let (code, ext, msg) = match e {
                    RecipientResolveError::UnknownDomain => {
                        ("550", "5.1.1", "Unknown recipient domain.")
                    }
                    RecipientResolveError::UnknownRecipient => {
                        ("550", "5.1.2", "Mailbox does not exist.")
                    }
                    RecipientResolveError::Temporary(v) => {
                        return self
                            .reply_with("451", "4.4.3", |buf| write!(buf, "Temporary error: {v}"))
                            .await;
                    }
                    RecipientResolveError::Permanent(v) => {
                        return self
                            .reply_with("550", "5.1.3", |buf| write!(buf, "Permanent error: {v}"))
                            .await;
                    }
                };

                return self.reply(code, ext, msg).await;
            }
        }

        self.reply("250", "2.1.5", "OK").await
    }
}
