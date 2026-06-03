use std::{
    borrow::Cow,
    fmt::{self, Write as _},
    io::Write as _,
    sync::Arc,
    time::Instant,
};

use arrayvec::ArrayString;
use mail_auth::{AuthenticatedMessage, DkimResult};
use smtp_proto::{
    Error as SmtpError, Request,
    request::receiver::{BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
};
use tokio_util::{sync::CancellationToken, time::FutureExt};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    network::AsyncReadWrite,
    smtp::{
        DeliveryError, EmailMessage, MessageError, ProtocolError,
        inbound::{
            MAX_REPLY_LEN, Session, SessionError, SessionResult, SessionState, SessionUpgrade,
            request_str,
        },
    },
};

impl<S: AsyncReadWrite> Session<S> {
    /// Writes given bytes to the session & flushes the buffer
    pub async fn write(&mut self, bytes: &[u8]) -> SessionResult<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;

        self.metrics
            .bytes_tx
            .with_label_values(&self.labels)
            .inc_by(bytes.len() as u64);
        self.counters.bytes_tx += bytes.len();

        Ok(())
    }

    /// Replies with given codes & message.
    ///
    /// It accepts replies up to `MAX_REPLY_LEN` long since it uses
    /// a stack array to avoid heap allocation for performance reasons.
    /// If ever this module would need more - increase the constant.
    pub(crate) async fn reply(&mut self, code: &str, ext: &str, msg: &str) -> SessionResult<()> {
        self.metrics
            .replies
            .with_label_values(&[self.labels[0], self.labels[1], code, ext])
            .inc();

        let len = code.len() + ext.len() + msg.len() + 4;
        assert!(
            len <= MAX_REPLY_LEN,
            "Reply longer than supported - increase MAX_REPLY_LEN"
        );

        let mut buf = [0; MAX_REPLY_LEN];
        write!(&mut buf[..], "{code} {ext} {msg}\r\n").ok();
        debug!("-> {code} {ext} {msg}");
        self.write(&buf[..len]).await
    }

    /// Replies with given codes & message.
    /// It takes a closure that should write a message to a buffer.
    /// Like reply() it accepts replies up to `MAX_REPLY_LEN`.
    pub(crate) async fn reply_with(
        &mut self,
        code: &str,
        ext: &str,
        msg_fn: impl FnOnce(&mut ArrayString<MAX_REPLY_LEN>) -> fmt::Result,
    ) -> SessionResult<()> {
        self.metrics
            .replies
            .with_label_values(&[self.labels[0], self.labels[1], code, ext])
            .inc();

        let mut buf = ArrayString::<MAX_REPLY_LEN>::new();

        write!(&mut buf, "{code} {ext} ")?;
        // Handle the fmt::Error or if the closure overflowed the buffer.
        // We need to send the SMTP reply anyway (even trucated) with correct CRLF termination.
        // This shouldn't happen (all our replies are smaller), but just in case.
        if msg_fn(&mut buf).is_err() || buf.len() > MAX_REPLY_LEN - 2 {
            self.write(buf.as_bytes()).await?;
            return self.write(b"\r\n").await;
        }

        debug!("-> {buf}");
        write!(&mut buf, "\r\n")?;
        self.write(buf.as_bytes()).await
    }

    pub(crate) async fn ext_unsupported(&mut self, ext: &str) -> SessionResult<()> {
        self.reply_with("501", "5.5.4", |buf| {
            write!(buf, "{ext} extension is not supported.")
        })
        .await
    }

    pub(crate) async fn message_too_big(&mut self) -> SessionResult<()> {
        let max_size = self.cfg.max_message_size;
        self.set_error(ProtocolError::MessageTooBig(format!(
            "{} > {}",
            self.data.message.len(),
            max_size
        )));
        self.reply_with("552", "5.3.4", |buf| {
            write!(buf, "Message too big, we accept up to {max_size} bytes.",)
        })
        .await
    }

    /// Sends greeting message
    async fn greeting(&mut self) -> SessionResult<()> {
        // If we have greeting delay configured - try to read from the stream for up to this duration.
        // The client needs to wait silently until we send our greeting.
        // If something comes in - then the client isn't respecting the protocol,
        // we consider him malicious and drop the connection.
        if let Some(v) = self.cfg.greeting_delay {
            let mut buf = [0; 256];
            match self.stream.read(&mut buf).timeout(v).await {
                Ok(Ok(bytes_read)) => {
                    if bytes_read > 0 {
                        self.metrics
                            .bytes_rx
                            .with_label_values(&self.labels)
                            .inc_by(bytes_read as u64);

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
        self.set_error(ProtocolError::SmtpError(error.to_string()));

        let (code, ext, msg) = match error {
            SmtpError::UnknownCommand | SmtpError::InvalidResponse { .. } => {
                ("500", "5.5.1", "Invalid command.")
            }
            SmtpError::InvalidSenderAddress => ("501", "5.1.8", "Bad sender's system address."),
            SmtpError::InvalidRecipientAddress => {
                ("501", "5.1.3", "Bad destination mailbox address syntax.")
            }
            SmtpError::SyntaxError { syntax } => {
                return self
                    .reply_with("501", "5.5.2", |buf| {
                        write!(buf, "Syntax error, expected: {syntax}")
                    })
                    .await;
            }
            SmtpError::InvalidParameter { param } => {
                return self
                    .reply_with("501", "5.5.4", |buf| {
                        write!(buf, "Invalid parameter {param:?}.")
                    })
                    .await;
            }
            SmtpError::UnsupportedParameter { param } => {
                return self
                    .reply_with("504", "5.5.4", |buf| {
                        write!(buf, "Unsupported parameter {param:?}.")
                    })
                    .await;
            }
            // These are handled one level above
            SmtpError::ResponseTooLong | SmtpError::NeedsMoreData { .. } => unreachable!(),
        };

        self.reply(code, ext, msg).await
    }

    async fn handle_request(&mut self, req: Request<Cow<'_, str>>) -> SessionResult<()> {
        match req {
            Request::Ehlo { host } => {
                debug!("{self}: <- EHLO {host}");
                self.handle_ehlo(&host, true).await?;
            }
            Request::Helo { host } => {
                debug!("{self}: <- HELO {host}");
                self.handle_ehlo(&host, false).await?;
            }
            Request::Mail { from } => {
                debug!("{self}: <- MAIL FROM: {}", from.address);
                self.handle_mail_from(from).await?;
            }
            Request::Rcpt { to } => {
                debug!("{self}: <- RCPT TO: {}", to.address);
                self.handle_rcpt_to(to).await?;
            }
            Request::Rset => {
                debug!("{self}: <- RSET");
                self.reset_message();
                self.reply("250", "2.0.0", "OK").await?;
            }
            Request::Quit => {
                debug!("{self}: <- QUIT");
                self.reply("221", "2.0.0", "Bye.").await?;
                return Err(SessionError::Quit);
            }
            Request::Noop { .. } => {
                debug!("{self}: <- NOOP");
                self.reply("250", "2.0.0", "OK").await?;
            }
            _ => {
                self.set_error(ProtocolError::SmtpError("Command not implemented".into()));
                self.reply("502", "5.5.1", "Command not implemented.")
                    .await?;
            }
        }

        Ok(())
    }

    /// Main SMTP state machine
    async fn ingest(&mut self, bytes: &[u8]) -> SessionResult<SessionUpgrade> {
        self.counters.bytes_rx += bytes.len();

        self.metrics
            .bytes_rx
            .with_label_values(&self.labels)
            .inc_by(bytes.len() as u64);

        // Check if we are over session transfer quota
        if self.counters.bytes_rx > self.cfg.max_session_data {
            self.reply("452", "4.7.28", "Session transfer quota exceeded.")
                .await?;
            return Err(SessionError::TransferQuotaExceeded(
                self.cfg.max_session_data,
            ));
        }

        // Check if we are over session time quota
        if Instant::now() > self.counters.started + self.cfg.max_session_duration {
            self.reply("452", "4.3.2", "Session open for too long.")
                .await?;
            return Err(SessionError::TtlExceeded(
                self.cfg.max_session_duration.as_secs(),
            ));
        }

        // Check if we are over error limit
        if self.counters.errors > self.cfg.max_errors {
            self.reply("452", "4.3.2", "Too many errors.").await?;
            return Err(SessionError::TooManyErrors);
        }

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
                        Ok(request) => {
                            self.metrics
                                .commands
                                .with_label_values(&[
                                    self.labels[0],
                                    self.labels[1],
                                    request_str(&request),
                                ])
                                .inc();
                            self.counters.commands += 1;

                            match request {
                                // ASCII data
                                Request::Data => {
                                    debug!("{self}: <- DATA");
                                    if self.can_accept_message().await? {
                                        self.write(
                                            b"354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                                        )
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
                                    debug!("{self}: <- BDAT");
                                    // Check if we will be past max message limit with this chunk
                                    state = if self.data.message.len() + chunk_size
                                        > self.cfg.max_message_size
                                    {
                                        SessionState::DataTooLarge(DummyDataReceiver::new_bdat(
                                            chunk_size,
                                        ))
                                    } else {
                                        // Preallocate the needed capacity for the chunk if need be
                                        let free =
                                            self.data.message.capacity() - self.data.message.len();
                                        if free < chunk_size {
                                            self.data.message.reserve(chunk_size - free);
                                        }

                                        SessionState::Bdat(BdatReceiver::new(chunk_size, is_last))
                                    }
                                }
                                Request::StartTls => {
                                    debug!("{self}: <- STARTTLS");
                                    if self.tls_info.is_some() {
                                        self.set_error(ProtocolError::InvalidSequenceOfCommands(
                                            "STARTTLS inside STARTTLS".into(),
                                        ));
                                        self.reply("504", "5.7.4", "Already in TLS mode.").await?;
                                    } else if !self.cfg.tls_mode.enabled() {
                                        self.set_error(ProtocolError::InvalidSequenceOfCommands(
                                            "STARTTLS without TLS enabled".into(),
                                        ));
                                        self.reply("502", "5.7.0", "TLS not available.").await?;
                                    } else {
                                        self.reply("220", "2.0.0", "Ready to start TLS.").await?;
                                        self.state = state;
                                        return Ok(SessionUpgrade::StartTls);
                                    }
                                }
                                other_request => {
                                    self.handle_request(other_request).await?;
                                }
                            }
                        }
                        Err(SmtpError::ResponseTooLong) => {
                            state = SessionState::RequestTooLarge(DummyLineReceiver::default());
                            continue;
                        }
                        // In case of NeedsMoreData error we just leave
                        // and wait for new data to be ingested
                        Err(SmtpError::NeedsMoreData { .. }) => break,

                        // Handle other errors separately
                        Err(e) => {
                            self.handle_error(e).await?;
                        }
                    }
                }
                SessionState::Data(rx) => {
                    // Check if the message already exceeds allowed size
                    if self.data.message.len() + iter.len() > self.cfg.max_message_size {
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
                        self.set_error(ProtocolError::SmtpError("Line is too long".into()));
                        self.reply("554", "5.3.4", "Line is too long.").await?;
                        state = SessionState::default();
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
                            let upgrade = self.ingest(&buf[..bytes_read]).await?;
                            if matches!(upgrade, SessionUpgrade::StartTls) {
                                return Ok(upgrade);
                            }
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

    /// Verifies the message body using various algorithms.
    /// TODO: Make it more testable.
    #[allow(unreachable_code)]
    async fn verify_message(
        &mut self,
        #[allow(unused_variables)] msg: &EmailMessage,
    ) -> SessionResult<Option<MessageError>> {
        #[cfg(test)]
        {
            return Ok(None);
        }

        let Some(auth_message) = AuthenticatedMessage::parse(&msg.body) else {
            info!(
                "{self}: {} -> {:?}: message parsing failed",
                msg.mail_from, msg.rcpt_to
            );
            self.reply("550", "5.7.7", "Failed to parse the message")
                .await?;
            return Ok(Some(MessageError::ParsingFailed));
        };

        if auth_message.received_headers_count() > self.cfg.max_received_headers {
            info!(
                "{self}: {} -> {:?}: message verification failed: too many 'Received' headers",
                msg.mail_from, msg.rcpt_to
            );
            self.reply(
                "450",
                "4.4.6",
                "Too many 'Received' headers. Possible loop detected.",
            )
            .await?;
            return Ok(Some(MessageError::TooManyReceivedHeaders));
        }

        if self.cfg.verify_dkim {
            let outputs = self.cfg.authenticator.verify_dkim(&auth_message).await;
            // Make borrow checker happy
            let strict = self.cfg.verify_dkim_strict;
            let log_name = self.to_string();

            // Replies with either a temporary or a permanent error code
            let mut reply = async |error: &str| -> SessionResult<()> {
                if outputs
                    .iter()
                    .any(|x| matches!(x.result(), DkimResult::TempError(_)))
                {
                    // If any of the signatures that failed with a temporary error - return temporary SMTP error code
                    info!(
                        "{log_name}: {} -> {:?}: DKIM verification temporary failure: {error}",
                        msg.mail_from, msg.rcpt_to
                    );
                    self.reply("451", "4.7.20", "DKIM validation temporary failure.")
                        .await
                } else {
                    // Otherwise permanent
                    info!(
                        "{log_name}: {} -> {:?}: DKIM verification failure: {error}",
                        msg.mail_from, msg.rcpt_to
                    );
                    self.reply("550", "5.7.20", "DKIM validation failed.").await
                }
            };

            let signatures_passed = outputs
                .iter()
                .filter(|x| matches!(x.result(), DkimResult::Pass | DkimResult::None))
                .count();

            // Get first validation error (if any)
            let first_error = outputs
                .iter()
                .filter_map(|x| match x.result() {
                    DkimResult::Fail(e) | DkimResult::PermError(e) | DkimResult::TempError(e) => {
                        Some(e.to_string())
                    }
                    _ => None,
                })
                .next();

            // Strict: Check that *all* signatures have passed validation (or there are none)
            // else: Check if *any* of the signatures have passed validation (or there are none)
            let is_valid = if strict {
                signatures_passed == outputs.len()
            } else {
                signatures_passed != 0 || outputs.is_empty()
            };

            if !is_valid {
                let error = first_error.unwrap_or_default();
                reply(&error).await?;
                return Ok(Some(MessageError::DkimValidationFailed(error)));
            }

            if signatures_passed > 0 {
                debug!(
                    "{log_name}: {} -> {:?}: DKIM validation succeeded ({signatures_passed}/{} signatures passed)",
                    msg.mail_from,
                    msg.rcpt_to,
                    outputs.len()
                );
            } else {
                debug!(
                    "{log_name}: {} -> {:?}: No DKIM signatures found",
                    msg.mail_from, msg.rcpt_to,
                );
            }
        }

        Ok(None)
    }

    async fn queue_message(&mut self) -> SessionResult<()> {
        let message_size = self.data.message.len();
        let id = self.data.message_id;

        // SAFETY: Code makes sure these are all Some().
        // It's better to panic in tests if they are not.
        let msg = Arc::new(EmailMessage {
            id,
            mail_from: self.data.mail_from.take().unwrap(),
            rcpt_to: std::mem::take(&mut self.data.rcpt_to),
            body: std::mem::take(&mut self.data.message).into(),
        });

        // Run configured verification steps on the message body
        if let Some(e) = self.verify_message(&msg).await? {
            self.notify_message(msg.clone(), Some(e));
            self.reset_message();
            return Ok(());
        }

        // Deliver the message.
        // Message cloning is rather lightweight (body is Bytes)
        if let Err(e) = self
            .cfg
            .delivery_agent
            .deliver_mail(self.meta(), msg.clone())
            .await
        {
            info!(
                "{self}: {} -> {:?}: message delivery failed: {e:#}",
                msg.mail_from, msg.rcpt_to
            );

            self.notify_message(msg.clone(), Some(MessageError::DeliveryFailed(e.clone())));
            self.reset_message();

            return match e {
                DeliveryError::Permanent(v) => {
                    self.reply_with("550", "5.5.0", |buf| {
                        write!(buf, "Permanent delivery error: {v}")
                    })
                    .await
                }
                DeliveryError::Temporary(v) => {
                    self.reply_with("450", "4.5.0", |buf| {
                        write!(buf, "Temporary delivery error: {v}")
                    })
                    .await
                }
            };
        }

        self.notify_message(msg.clone(), None);

        info!(
            "{self}: {} -> {:?}: message ({message_size} bytes) queued with id {id}",
            msg.mail_from, msg.rcpt_to
        );
        self.reply_with("250", "2.0.0", |buf| {
            write!(buf, "Message ({message_size} bytes) queued with id {id}")
        })
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
            self.set_error(ProtocolError::InvalidSequenceOfCommands(
                "DATA before RCPT TO".into(),
            ));
            self.reply("503", "5.5.1", "RCPT TO is required first.")
                .await?;
            return Ok(false);
        }

        Ok(true)
    }

    /// Resets the message-related fields to their initial state
    pub(crate) fn reset_message(&mut self) {
        #[cfg(not(test))]
        {
            self.data.message_id = Uuid::now_v7();
        }
        #[cfg(test)]
        {
            self.data.message_id = Uuid::nil();
        }

        self.data.mail_from = None;
        self.data.rcpt_to.clear();
        self.data.message.clear();
    }
}
