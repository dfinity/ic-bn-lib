pub mod helo;

use std::{io, net::IpAddr};

use fqdn::FQDN;
use mail_auth::MessageAuthenticator;
use rustls::ServerConfig;
use smtp_proto::request::receiver::{
    BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver, RequestReceiver,
};
use strum::Display;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{network::AsyncReadWrite, smtp::address::EmailAddress};

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
    pub rcpt_to: Option<EmailAddress>,
}

/// SMTP session params
#[derive(Debug, Default)]
pub struct SessionParams {
    pub max_message_size: u64,
    pub verify_ehlo_hostname: bool,
    pub verify_spf: bool,
    pub verify_reverse_ip: bool,
    pub dns_servers: Vec<IpAddr>,
}

pub struct Session<S: AsyncReadWrite> {
    id: Uuid,
    hostname: String,
    remote_ip: IpAddr,
    stream: S,
    state: SessionState,
    data: SessionData,
    params: SessionParams,
    authenticator: MessageAuthenticator,
    in_starttls: bool,
    tls_config: Option<ServerConfig>,
}

impl<S: AsyncReadWrite> Session<S> {
    pub fn new(
        hostname: String,
        remote_ip: IpAddr,
        stream: S,
        params: SessionParams,
        authenticator: MessageAuthenticator,
        tls_config: Option<ServerConfig>,
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
            in_starttls: false,
            tls_config,
        }
    }

    /// Writes given bytes to the session & flushes the buffer
    pub async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn process(&mut self) {
        match self.state {
            SessionState::Init => {
                let greeting = format!("220 {} ESMTP IC SMTP Gateway\r\n", self.hostname);
                self.write(greeting.as_bytes()).await;
            }

            _ => {}
        }
    }
}
