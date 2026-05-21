use std::time::Duration;

use anyhow::anyhow;
use clap::Args;
use humantime::parse_duration;
use ic_bn_lib_common::parse_size;

use crate::smtp::inbound::SessionConfig;

// #[derive(Clone)]
// pub struct SessionConfig {
//     hostname: String,
//     greeting: Bytes,
//     helo: Bytes,
//     ehlo: Bytes,
//     ehlo_tls: Bytes,

//     max_message_size: usize,
//     pub max_recipients: usize,
//     pub max_session_duration: Duration,
//     pub max_session_data: usize,
//     pub max_errors: usize,
//     pub max_messages_per_session: usize,

//     pub verify_ehlo_hostname: bool,
//     pub verify_sender_domain: bool,
//     pub verify_reverse_ip: bool,
//     pub verify_spf: bool,
//     pub helo_delay: Option<Duration>,

//     pub timeout: Duration,
//     pub tls_mode: SessionTlsMode,

//     pub authenticator: Arc<MessageAuthenticator>,
//     pub recipient_resolver: Arc<dyn ResolvesRecipient>,
//     pub delivery_agent: Arc<dyn DeliversMail>,
// }

/// SMTP Server CLI
#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerCli {
    /// SMTP server hostname to use.
    /// If specified - the SMTP feature is enabled.
    #[clap(env, long)]
    pub smtp_server_hostname: Option<String>,

    /// How long to wait before sending
    #[clap(env, long, default_value = "3s", value_parser = parse_duration)]
    pub smtp_server_greeting_delay: Duration,

    /// Maximum number of recipient per message
    #[clap(env, long, default_value = "10")]
    pub smtp_server_max_recipients: usize,

    /// Maximum number of messages per single SMTP session
    #[clap(env, long, default_value = "5")]
    pub smtp_server_max_messages_per_session: usize,

    /// Maximum number of errors per single SMTP session
    #[clap(env, long, default_value = "5")]
    pub smtp_server_max_errors_per_session: usize,

    /// Maximum message body size
    #[clap(env, long, default_value = "2MB", value_parser = parse_size)]
    pub smtp_server_max_message_size: usize,

    /// How much data can be ingested during a single SMTP session
    #[clap(env, long, default_value = "50MB", value_parser = parse_size)]
    pub smtp_server_max_session_data: usize,

    /// Maximum time that the session is allowed to be open
    #[clap(env, long, default_value = "2m", value_parser = parse_duration)]
    pub smtp_server_max_session_duration: Duration,

    /// Timeout for SMTP read calls (how long to keep idle session open)
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub smtp_server_timeout: Duration,

    /// Whether to verify client's EHLO hostname (A record)
    #[clap(env, long)]
    pub smtp_server_verify_ehlo_hostname: bool,

    /// Whether to verify reverse IP of the SMTP clients.
    /// It should resolve to a hostname and that hostname should resolve back to the same IP.
    /// Also an IP should match the client's IP.
    #[clap(env, long)]
    pub smtp_server_verify_reverse_ip: bool,

    /// Whether to verify the sender's domain (A and MX records)
    #[clap(env, long)]
    pub smtp_server_verify_sender_domain: bool,

    /// Whether to verify the SPF records
    #[clap(env, long)]
    pub smtp_server_verify_spf: bool,
}

impl TryFrom<&SmtpServerCli> for SessionConfig {
    type Error = anyhow::Error;

    fn try_from(v: &SmtpServerCli) -> Result<Self, Self::Error> {
        let Some(hostname) = &v.smtp_server_hostname else {
            return Err(anyhow!("`smtp_server_hostname` is required"));
        };

        let mut cfg = Self::new(hostname, v.smtp_server_max_message_size);
        cfg.greeting_delay = Some(v.smtp_server_greeting_delay);

        cfg.max_errors = v.smtp_server_max_errors_per_session;
        cfg.max_messages_per_session = v.smtp_server_max_messages_per_session;
        cfg.max_recipients = v.smtp_server_max_recipients;
        cfg.max_session_data = v.smtp_server_max_session_data;
        cfg.max_session_duration = v.smtp_server_max_session_duration;

        cfg.timeout = v.smtp_server_timeout;

        cfg.verify_ehlo_hostname = v.smtp_server_verify_ehlo_hostname;
        cfg.verify_reverse_ip = v.smtp_server_verify_reverse_ip;
        cfg.verify_sender_domain = v.smtp_server_verify_sender_domain;
        cfg.verify_spf = v.smtp_server_verify_spf;

        Ok(cfg)
    }
}
