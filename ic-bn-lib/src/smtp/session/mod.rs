pub mod helo;
pub mod mail_from;
pub mod rcpt_to;

use std::{io, net::IpAddr, sync::Arc, time::Duration};

use ahash::AHashSet;
use fqdn::FQDN;
use mail_auth::MessageAuthenticator;
use rustls::ServerConfig;
use smtp_proto::request::receiver::{
    BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver, RequestReceiver,
};
use strum::Display;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    time::{error::Elapsed, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    network::AsyncReadWrite,
    smtp::{ResolvesRecipient, address::EmailAddress},
};

/// SMTP session state
#[derive(Default, Display)]
pub enum SessionState {
    #[default]
    Init,
    Request(RequestReceiver),
    Data(DataReceiver),
    Done,
}

/// SMTP session data
#[derive(Debug, Default)]
pub struct SessionData {
    pub helo_hostname: Option<FQDN>,
    pub mail_from: Option<EmailAddress>,
    pub rcpt_to: AHashSet<EmailAddress>,
}

/// SMTP session parameters
#[derive(Debug)]
pub struct SessionParams {
    pub max_message_size: u64,
    pub max_recipients: usize,
    pub max_session_duration: Duration,
    pub verify_ehlo_hostname: bool,
    pub verify_spf: bool,
    pub verify_reverse_ip: bool,
    pub helo_delay: Duration,
    pub timeout: Duration,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            max_message_size: 10 * 1024 * 1024,
            max_recipients: 5,
            max_session_duration: Duration::from_secs(600),
            verify_ehlo_hostname: false,
            verify_reverse_ip: false,
            verify_spf: false,
            helo_delay: Duration::from_secs(3),
            timeout: Duration::from_secs(30),
        }
    }
}

/// SMTP Session
pub struct Session<S: AsyncReadWrite> {
    id: Uuid,
    hostname: String,
    remote_ip: IpAddr,
    stream: S,
    state: SessionState,
    data: SessionData,
    params: SessionParams,
    authenticator: Arc<MessageAuthenticator>,
    recipient_resolver: Arc<dyn ResolvesRecipient>,
    in_starttls: bool,
    tls_config: Option<ServerConfig>,
    shutdown_token: CancellationToken,
}

#[allow(clippy::too_many_arguments)]
impl<S: AsyncReadWrite> Session<S> {
    pub fn new(
        hostname: String,
        remote_ip: IpAddr,
        stream: S,
        params: SessionParams,
        authenticator: Arc<MessageAuthenticator>,
        recipient_resolver: Arc<dyn ResolvesRecipient>,
        tls_config: Option<ServerConfig>,
        shutdown_token: CancellationToken,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            hostname,
            remote_ip,
            stream,
            state: SessionState::default(),
            data: SessionData::default(),
            params,
            authenticator,
            recipient_resolver,
            in_starttls: false,
            tls_config,
            shutdown_token,
        }
    }

    /// Writes given bytes to the session & flushes the buffer
    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn ingest(&mut self, bytes: &[u8]) -> io::Result<()> {
        match &self.state {
            SessionState::Init => {
                // If we have HELO delay configured - try to read from the stream for up to this duration.
                // The client needs to wait silently until we send our greeting.
                // If something comes in - then the client isn't respecting the protocol and we consider him malicious.
                if self.params.helo_delay != Duration::ZERO {
                    if timeout(self.params.helo_delay, self.stream.read_u8())
                        .await
                        .is_ok()
                    {
                        self.write(b"").await?;
                    }
                }

                let greeting = format!("220 {} ESMTP IC SMTP Gateway\r\n", self.hostname);
                self.write(greeting.as_bytes()).await?;

                self.state = SessionState::Request(RequestReceiver::default())
            }

            SessionState::Request(rx) => {}
            SessionState::Data(rx) => {}
            SessionState::Done => {
                self.stream.shutdown().await.ok();
            }
        }

        Ok(())
    }

    pub async fn read(
        &mut self,
        buf: &mut [u8],
        res: Result<Result<usize, io::Error>, Elapsed>,
    ) -> io::Result<()> {
        match res {
            Ok(Ok(bytes_read)) => {
                self.ingest(&buf[..bytes_read]).await?;
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(e) => return Err(io::Error::other(e)),
        }

        Ok(())
    }

    /// Drives the session forward
    pub async fn handle(&mut self) {
        let mut buf = vec![0; 8192];

        loop {
            select! {
                res = timeout(self.params.timeout, self.stream.read(&mut buf)) => {
                    if let Err(e) = self.read(&mut buf, res).await {
                        info!("Session error: {e:#}");
                        break;
                    };
                },

                () = self.shutdown_token.cancelled() => {
                    break;
                }
            }
        }

        self.stream.shutdown().await.ok();
    }
}
