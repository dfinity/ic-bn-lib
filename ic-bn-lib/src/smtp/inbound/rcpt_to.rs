use std::{borrow::Cow, str::FromStr};

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
        if self.data.mail_from.is_none() {
            return self
                .reply("503", "5.5.1", "MAIL FROM is required first.")
                .await;
        }

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
            .resolve_recipient(&address)
            .await
        {
            Ok(v) => match v {
                RecipientPolicy::Accept => {
                    self.data.rcpt_to.insert(address);
                }
                RecipientPolicy::Rewrite(new_address) => {
                    self.data.rcpt_to.insert(new_address);
                }
                RecipientPolicy::Expand(new_addresses) => {
                    self.data.rcpt_to.extend(new_addresses);
                }
            },

            Err(e) => match e {
                RecipientResolveError::UnknownDomain => {
                    return self
                        .reply("550", "5.1.2", "Unknown recipient domain.")
                        .await;
                }
                RecipientResolveError::UnknownRecipient => {
                    return self.reply("550", "5.1.2", "Mailbox does not exist.").await;
                }
                RecipientResolveError::Other(_) => {
                    return self
                        .reply("451", "4.4.3", "Unable to verify address at this time.")
                        .await;
                }
            },
        }

        self.reply("250", "2.1.5", "OK").await
    }
}
