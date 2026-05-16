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

#[allow(clippy::too_many_arguments)]
impl<S: AsyncReadWrite> Session<S> {
    /// Writes given bytes to the session & flushes the buffer
    pub async fn write(&mut self, bytes: &[u8]) -> SessionResult<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
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
                        self.write(b"501 5.7.1 Client sent command before greeting banner.\r\n")
                            .await?;
                        return Err(SessionError::SendsBeforeGreeting);
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {}
            }
        }

        let greeting = format!("220 {} ESMTP IC SMTP Gateway\r\n", self.cfg.hostname);
        self.write(greeting.as_bytes()).await?;

        Ok(())
    }

    async fn handle_error(&mut self, error: SmtpError) -> SessionResult<()> {
        match error {
            SmtpError::UnknownCommand | SmtpError::InvalidResponse { .. } => {
                self.write(b"500 5.5.1 Invalid command.\r\n").await?;
            }
            SmtpError::InvalidSenderAddress => {
                self.write(b"501 5.1.8 Bad sender's system address.\r\n")
                    .await?;
            }
            SmtpError::InvalidRecipientAddress => {
                self.write(b"501 5.1.3 Bad destination mailbox address syntax.\r\n")
                    .await?;
            }
            SmtpError::SyntaxError { syntax } => {
                self.write(format!("501 5.5.2 Syntax error, expected: {syntax}\r\n").as_bytes())
                    .await?;
            }
            SmtpError::InvalidParameter { param } => {
                self.write(format!("501 5.5.4 Invalid parameter {param:?}.\r\n").as_bytes())
                    .await?;
            }
            SmtpError::UnsupportedParameter { param } => {
                self.write(format!("504 5.5.4 Unsupported parameter {param:?}.\r\n").as_bytes())
                    .await?;
            }
            SmtpError::ResponseTooLong => {
                self.state = SessionState::RequestTooLarge(DummyLineReceiver::default());
            }
            SmtpError::NeedsMoreData { .. } => {}
        }

        Ok(())
    }

    async fn handle_request(&mut self, req: Request<Cow<'_, str>>) -> SessionResult<()> {
        match req {
            Request::Ehlo { host } | Request::Helo { host } => {
                self.handle_ehlo(&host).await?;
            }
            Request::Mail { from } => {
                self.handle_mail_from(from).await?;
            }
            Request::Rcpt { to } => {
                self.handle_rcpt_to(to).await?;
            }
            Request::Rset => {
                self.reset_message();
                self.write(b"250 2.0.0 OK\r\n").await?;
            }
            Request::Quit => {
                self.write(b"221 2.0.0 Bye.\r\n").await?;
                return Err(SessionError::Quit);
            }
            Request::Noop { .. } => {
                self.write(b"250 2.0.0 OK\r\n").await?;
            }
            _ => {
                self.write(b"502 5.5.1 Command not implemented.\r\n")
                    .await?;
                self.counters.errors += 1;
            }
        }

        Ok(())
    }

    async fn ingest(&mut self, bytes: &[u8]) -> SessionResult<SessionUpgrade> {
        // Check if we are over session transfer quota
        if self.counters.bytes_ingested + bytes.len() >= self.cfg.max_session_data {
            self.write(b"452 4.7.28 Session transfer quota exceeded.\r\n")
                .await?;
            return Err(SessionError::TransferQuotaExceeded(
                self.cfg.max_session_data,
            ));
        }

        // Check if we are over session time quota
        if Instant::now() > self.counters.valid_until {
            self.write(b"452 4.3.2 Session open for too long.\r\n")
                .await?;
            return Err(SessionError::TtlExceeded(
                self.cfg.max_session_duration.as_secs(),
            ));
        }

        // Check if we are over error limit
        if self.counters.errors > self.cfg.max_errors {
            self.write(b"452 4.3.2 Too many errors.\r\n").await?;
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
                                    self.write(b"504 5.7.4 Already in TLS mode.\r\n").await?;
                                    self.counters.errors += 1;
                                } else if !self.cfg.tls_enabled() {
                                    self.write(b"502 5.7.0 TLS not available.\r\n").await?;
                                    self.counters.errors += 1;
                                } else {
                                    self.write(b"220 2.0.0 Ready to start TLS.\r\n").await?;
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
                        Err(e) => {
                            self.handle_error(e).await?;
                            self.counters.errors += 1;
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
                                self.write(b"250 2.6.0 Chunk accepted.\r\n").await?;
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
                        self.write(b"554 5.3.4 Line is too long.\r\n").await?;
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
                            self.write(b"221 2.0.0 Disconnecting due to inactivity.\r\n").await?;
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

    pub(crate) async fn ext_unsupported(&mut self, ext: &str) -> SessionResult<()> {
        self.write(b"501 5.5.4 ").await?;
        self.write(ext.as_bytes()).await?;
        return self.write(b" extension is not supported.\r\n").await;
    }

    pub(crate) async fn message_too_big(&mut self) -> SessionResult<()> {
        let msg = format!(
            "552 5.3.4 Message too big for, we accept up to {} bytes.\r\n",
            self.cfg.max_message_size
        );
        return self.write(msg.as_bytes()).await;
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
            let msg = match e {
                DeliveryError::Permanent(v) => {
                    format!("550 5.5.0 Permanent delivery error: {v}")
                }
                DeliveryError::Temporary(v) => {
                    format!("450 4.5.0 Temporary delivery error: {v}")
                }
            };

            self.write(msg.as_bytes()).await?;
            self.reset_message();
            return Ok(());
        }

        self.write(
            format!("250 2.0.0 Message ({message_size} bytes) queued with id {id}\r\n").as_bytes(),
        )
        .await?;

        self.counters.messages_queued += 1;
        self.reset_message();
        Ok(())
    }

    async fn can_accept_message(&mut self) -> SessionResult<bool> {
        if self.counters.messages_queued >= self.cfg.max_messages_per_session {
            self.write(b"452 4.4.5 Maximum number of messages per session exceeded.\r\n")
                .await?;
            return Err(SessionError::TooManyMessagesPerSession);
        } else if self.data.rcpt_to.is_empty() {
            self.write(b"503 5.5.1 RCPT TO is required first.\r\n")
                .await?;
            self.counters.errors += 1;
            return Ok(false);
        }

        Ok(true)
    }

    /// Resets the message-related fields to their initial state
    fn reset_message(&mut self) {
        self.data.mail_from = None;
        self.data.rcpt_to.clear();
        self.data.message.clear();
    }

    pub async fn shutdown(&mut self) -> SessionResult<()> {
        self.write(b"421 4.3.0 Server shutting down.\r\n").await?;

        self.stream
            .shutdown()
            .timeout(Duration::from_secs(10))
            .await
            .context("shutdown timed out")?
            .context("shutdown failed")?;

        Ok(())
    }
}
