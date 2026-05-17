use std::{
    borrow::Cow,
    time::{Duration, Instant},
};

use anyhow::Context;
use smtp_proto::{
    Error as SmtpError, Request,
    request::receiver::{BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};
use tokio_util::{sync::CancellationToken, time::FutureExt};
use uuid::Uuid;

use crate::{
    network::AsyncReadWrite,
    smtp::{
        DeliveryError, Message,
        inbound::{Session, SessionError, SessionResult, SessionState, SessionUpgrade},
    },
};

const MAX_REPLY_LEN: usize = 256;

#[allow(clippy::too_many_arguments)]
impl<S: AsyncReadWrite> Session<S> {
    /// Writes given bytes to the session & flushes the buffer
    pub async fn write(&mut self, bytes: &[u8]) -> SessionResult<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Replies with given codes & message.
    ///
    /// It accepts replies up to `MAX_REPLY_LEN` long since it uses
    /// a stack array to avoid heap allocation for performance reasons.
    /// If ever this module would need more - increase the constant.
    pub(crate) async fn reply(&mut self, code: &str, ext: &str, msg: &str) -> SessionResult<()> {
        let len = code.len() + ext.len() + msg.len() + 4;
        assert!(
            len <= MAX_REPLY_LEN,
            "Reply longer than supported - increase MAX_REPLY_LEN"
        );

        // Poor man's `format!`
        let mut buf = [0; MAX_REPLY_LEN];
        let (mut i, mut j) = (0, code.len());
        buf[i..j].copy_from_slice(code.as_bytes());
        buf[j] = b' ';
        i += code.len() + 1;
        j += ext.len() + 1;
        buf[i..j].copy_from_slice(ext.as_bytes());
        buf[j] = b' ';
        i += ext.len() + 1;
        j += msg.len() + 1;
        buf[i..j].copy_from_slice(msg.as_bytes());
        buf[j] = b'\r';
        buf[j + 1] = b'\n';

        self.write(&buf[..len]).await
    }

    pub(crate) async fn ext_unsupported(&mut self, ext: &str) -> SessionResult<()> {
        self.reply(
            "501",
            "5.5.4",
            &format!("{ext} extension is not supported."),
        )
        .await
    }

    pub(crate) async fn message_too_big(&mut self) -> SessionResult<()> {
        let msg = format!(
            "Message too big for, we accept up to {} bytes.",
            self.cfg.max_message_size
        );
        return self.reply("552", "5.3.4", &msg).await;
    }

    /// Sends greeting message
    async fn greeting(&mut self) -> SessionResult<()> {
        // If we have HELO delay configured - try to read from the stream for up to this duration.
        // The client needs to wait silently until we send our greeting.
        // If something comes in - then the client isn't respecting the protocol,
        // we consider him malicious and drop the connection.
        if let Some(v) = self.cfg.helo_delay {
            let mut buf = vec![0; 128];
            match self.stream.read(&mut buf).timeout(v).await {
                Ok(Ok(bytes_read)) => {
                    if bytes_read > 0 {
                        self.reply(
                            "501",
                            "5.7.1",
                            "Client sent command before greeting banner.",
                        )
                        .await?;
                        return Err(SessionError::SendsBeforeGreeting);
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {}
            }
        }

        self.write(&self.cfg.greeting.clone()).await
    }

    async fn handle_error(&mut self, error: SmtpError) -> SessionResult<()> {
        let (code, ext, msg) = match error {
            SmtpError::UnknownCommand | SmtpError::InvalidResponse { .. } => {
                ("500", "5.5.1", "Invalid command.".to_string())
            }
            SmtpError::InvalidSenderAddress => {
                ("501", "5.1.8", "Bad sender's system address.".to_string())
            }
            SmtpError::InvalidRecipientAddress => (
                "501",
                "5.1.3",
                "Bad destination mailbox address syntax.".to_string(),
            ),
            SmtpError::SyntaxError { syntax } => {
                ("501", "5.5.2", format!("Syntax error, expected: {syntax}"))
            }
            SmtpError::InvalidParameter { param } => {
                ("501", "5.5.4", format!("Invalid parameter {param:?}."))
            }
            SmtpError::UnsupportedParameter { param } => {
                ("504", "5.5.4", format!("Unsupported parameter {param:?}."))
            }
            // These are handled one level above
            SmtpError::ResponseTooLong | SmtpError::NeedsMoreData { .. } => unreachable!(),
        };

        self.counters.errors += 1;
        self.reply(code, ext, &msg).await
    }

    async fn handle_request(&mut self, req: Request<Cow<'_, str>>) -> SessionResult<()> {
        match req {
            Request::Ehlo { host } => {
                self.handle_ehlo(&host, true).await?;
            }
            Request::Helo { host } => {
                self.handle_ehlo(&host, false).await?;
            }
            Request::Mail { from } => {
                self.handle_mail_from(from).await?;
            }
            Request::Rcpt { to } => {
                self.handle_rcpt_to(to).await?;
            }
            Request::Rset => {
                self.reset_message();
                self.reply("250", "2.0.0", "OK").await?;
            }
            Request::Quit => {
                self.reply("221", "2.0.0", "Bye.").await?;
                return Err(SessionError::Quit);
            }
            Request::Noop { .. } => {
                self.reply("250", "2.0.0", "OK").await?;
            }
            _ => {
                self.reply("502", "5.5.1", "Command not implemented.")
                    .await?;
                self.counters.errors += 1;
            }
        }

        Ok(())
    }

    async fn ingest(&mut self, bytes: &[u8]) -> SessionResult<SessionUpgrade> {
        // Check if we are over session transfer quota
        if self.counters.bytes_ingested + bytes.len() >= self.cfg.max_session_data {
            self.reply("452", "4.7.28", "Session transfer quota exceeded.")
                .await?;
            return Err(SessionError::TransferQuotaExceeded(
                self.cfg.max_session_data,
            ));
        }

        // Check if we are over session time quota
        if Instant::now() > self.counters.valid_until {
            self.reply("452", "4.3.2", "Session open for too long.")
                .await?;
            return Err(SessionError::TtlExceeded(
                self.cfg.max_session_duration.as_secs(),
            ));
        }

        // Check if we are over error limit
        if self.counters.errors >= self.cfg.max_errors {
            self.reply("452", "4.3.2", "Too many errors.").await?;
            return Err(SessionError::TooManyErrors);
        }

        self.counters.bytes_ingested += bytes.len();
        let mut iter = bytes.iter();
        // We can't take mutable ref to self.state & self at the same time,
        // so we extract state temporarily.
        let mut state = std::mem::replace(&mut self.state, SessionState::None);

        loop {
            match &mut state {
                SessionState::Greeting => {
                    // This is handled separately
                    unreachable!();
                }
                SessionState::Request(rx) => {
                    match rx.ingest(&mut iter) {
                        Ok(request) => match request {
                            // ASCII data
                            Request::Data => {
                                if self.can_accept_message().await? {
                                    self.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                                        .await?;
                                    self.data.message = Vec::with_capacity(1024);
                                    state = SessionState::Data(DataReceiver::new());
                                    continue;
                                }
                            }
                            // Binary data
                            Request::Bdat {
                                chunk_size,
                                is_last,
                            } => {
                                // Check if we will be past max message limit with this chunk
                                state = if self.data.message.len() + chunk_size
                                    > self.cfg.max_message_size
                                {
                                    SessionState::DataTooLarge(DummyDataReceiver::new_bdat(
                                        chunk_size,
                                    ))
                                } else {
                                    // Allocate the needed capacity for the chunk
                                    let free =
                                        self.data.message.capacity() - self.data.message.len();
                                    if free < chunk_size {
                                        self.data.message.reserve(chunk_size - free);
                                    }

                                    SessionState::Bdat(BdatReceiver::new(chunk_size, is_last))
                                }
                            }
                            Request::StartTls => {
                                if self.tls_info.is_some() {
                                    self.reply("504", "5.7.4", "Already in TLS mode.").await?;
                                    self.counters.errors += 1;
                                } else if !self.cfg.tls_enabled() {
                                    self.reply("502", "5.7.0", "TLS not available.").await?;
                                    self.counters.errors += 1;
                                } else {
                                    self.reply("220", "2.0.0", "Ready to start TLS.").await?;
                                    return Ok(SessionUpgrade::StartTls);
                                }
                            }
                            other_request => {
                                self.handle_request(other_request).await?;
                            }
                        },
                        // In case of NeedsMoreData error we just leave
                        // and wait for new data to be ingested
                        Err(SmtpError::NeedsMoreData { .. }) => break,
                        Err(SmtpError::ResponseTooLong) => {
                            state = SessionState::RequestTooLarge(DummyLineReceiver::default());
                            continue;
                        }
                        Err(e) => {
                            self.handle_error(e).await?;
                        }
                    }
                }
                SessionState::Data(rx) => {
                    // Check if the message already exceeds allowed size
                    if self.data.message.len() + bytes.len() > self.cfg.max_message_size {
                        state = SessionState::DataTooLarge(DummyDataReceiver::new_data(rx));
                        continue;
                    } else if rx.ingest(&mut iter, &mut self.data.message) {
                        // The message is fully received, time to queue
                        self.queue_message().await?;
                        state = SessionState::default();
                    } else {
                        // No end-of-message marker found yet
                        break;
                    }
                }
                SessionState::Bdat(rx) => {
                    if rx.ingest(&mut iter, &mut self.data.message) {
                        if self.can_accept_message().await? {
                            if rx.is_last {
                                self.queue_message().await?;
                            } else {
                                self.reply("250", "2.6.0", "Chunk accepted.").await?;
                            }
                        } else {
                            self.data.message = Vec::with_capacity(0);
                        }
                        state = SessionState::default();
                    } else {
                        // Still some bytes left in the chunk
                        break;
                    }
                }
                SessionState::RequestTooLarge(rx) => {
                    // If line-feed found - issue error, otherwise keep ingesting
                    if rx.ingest(&mut iter) {
                        self.reply("554", "5.3.4", "Line is too long.").await?;
                        state = SessionState::default();
                        self.counters.errors += 1;
                    } else {
                        // No line-feed found yet
                        break;
                    }
                }
                SessionState::DataTooLarge(rx) => {
                    // If end-of-message marker found - issue error, otherwise keep ingesting
                    if rx.ingest(&mut iter) {
                        self.message_too_big().await?;
                        state = SessionState::default();
                        self.counters.errors += 1;
                    } else {
                        // No end-of-message marker found yet
                        break;
                    }
                }
                SessionState::None => unreachable!(),
            }
        }
        self.state = state;

        Ok(SessionUpgrade::No)
    }

    /// Drives the session forward
    pub async fn handle(
        &mut self,
        shutdown_token: CancellationToken,
    ) -> SessionResult<SessionUpgrade> {
        let mut buf = vec![0; 8192];

        if matches!(self.state, SessionState::Greeting) {
            self.greeting().await?;
            self.state = SessionState::default();
        }

        loop {
            select! {
                // Read from the client with a timeout
                res = self.stream.read(&mut buf).timeout(self.cfg.timeout) => {
                    match res {
                        Ok(Ok(bytes_read)) => {
                            self.ingest(&buf[..bytes_read]).await?;
                        }
                        Ok(Err(e)) => {
                            return Err(e.into());
                        }
                        Err(_) => {
                            self.reply("221", "2.0.0", "Disconnecting due to inactivity.").await?;
                            return Err(SessionError::Timeout);
                        }
                    }
                },

                () = shutdown_token.cancelled() => {
                    break;
                }
            }
        }

        Ok(SessionUpgrade::No)
    }

    async fn queue_message(&mut self) -> SessionResult<()> {
        #[cfg(not(test))]
        let id = Uuid::now_v7();
        #[cfg(test)]
        let id = Uuid::nil();

        let message_size = self.data.message.len();

        // SAFETY: Code makes sure these are all Some().
        // It's better to panic in tests if they are not.
        let message = Message {
            id,
            ehlo_hostname: self.data.ehlo_hostname.clone().unwrap(),
            mail_from: self.data.mail_from.take().unwrap(),
            rcpt_to: self.data.rcpt_to.drain().collect(),
            body: std::mem::take(&mut self.data.message),
        };

        if let Err(e) = self.cfg.delivery_agent.deliver_mail(message).await {
            let (code, ext, msg) = match e {
                DeliveryError::Permanent(v) => {
                    ("550", "5.5.0", format!("Permanent delivery error: {v}"))
                }
                DeliveryError::Temporary(v) => {
                    ("450", "4.5.0", format!("Temporary delivery error: {v}"))
                }
            };

            self.reply(code, ext, &msg).await?;
            self.reset_message();
            return Ok(());
        }

        self.reply(
            "250",
            "2.0.0",
            &format!("Message ({message_size} bytes) queued with id {id}"),
        )
        .await?;

        self.counters.messages_queued += 1;
        self.reset_message();
        Ok(())
    }

    async fn can_accept_message(&mut self) -> SessionResult<bool> {
        if self.counters.messages_queued >= self.cfg.max_messages_per_session {
            self.reply(
                "452",
                "4.4.5",
                "Maximum number of messages per session exceeded.",
            )
            .await?;
            return Err(SessionError::TooManyMessagesPerSession);
        } else if self.data.rcpt_to.is_empty() {
            self.reply("503", "5.5.1", "RCPT TO is required first.")
                .await?;
            self.counters.errors += 1;
            return Ok(false);
        }

        Ok(true)
    }

    /// Resets the message-related fields to their initial state
    pub(crate) fn reset_message(&mut self) {
        self.data.mail_from = None;
        self.data.rcpt_to.clear();
        self.data.message.clear();
    }

    /// Closes the connection
    pub async fn shutdown(&mut self) -> SessionResult<()> {
        self.stream
            .shutdown()
            .timeout(Duration::from_secs(10))
            .await
            .context("shutdown timed out")?
            .context("shutdown failed")?;

        Ok(())
    }
}
