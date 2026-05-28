use std::{net::SocketAddr, time::Duration};

use anyhow::anyhow;
use clap::Args;
use humantime::parse_duration;
use ic_bn_lib_common::parse_size;

use crate::smtp::inbound::SessionConfig;

/// SMTP Server CLI
#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct SmtpServerCli {
    /// Where to listen for SMTP connections.
    /// If specified - the SMTP feature is enabled.
    #[clap(env, long, requires = "smtp_server_hostname")]
    pub smtp_server_listen: Option<SocketAddr>,

    /// SMTP server hostname to use in greeting messages etc.
    /// Required if `smtp_server_listen` is specified.
    #[clap(env, long, requires = "smtp_server_listen")]
    pub smtp_server_hostname: Option<String>,

    /// Base domain to execute IC HTTP queries.
    /// Used when resolving SMTP canisters mapping.
    #[clap(env, long, default_value = "icp0.io")]
    pub smtp_server_ic_base_domain: String,

    /// How long to wait before sending greeting banner.
    /// This helps identify spammy clients that don't follow the protocol -
    /// if they send us anything before the banner - they get disconnected.
    #[clap(env, long, default_value = "2s", value_parser = parse_duration)]
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
    pub smtp_server_max_message_size: u64,

    /// How much data can be ingested during a single SMTP session
    #[clap(env, long, default_value = "50MB", value_parser = parse_size)]
    pub smtp_server_max_session_data: u64,

    /// Maximum time that the session is allowed to be open
    #[clap(env, long, default_value = "2m", value_parser = parse_duration)]
    pub smtp_server_max_session_duration: Duration,

    /// Timeout for SMTP read calls (how long to keep idle session open)
    #[clap(env, long, default_value = "30s", value_parser = parse_duration)]
    pub smtp_server_timeout: Duration,

    /// For how long to cache Canister SMTP mappings
    #[clap(env, long, default_value = "10m", value_parser = parse_duration)]
    pub smtp_server_canister_cache_ttl: Duration,

    /// Maximum number of Canister SMTP mappings to keep in cache
    #[clap(env, long, default_value = "100k", value_parser = parse_size)]
    pub smtp_server_canister_cache_capacity: u64,

    /// Whether to enforce usage of STARTTLS.
    /// Be advised that it's effectively against standards/RFCs to do that.
    #[clap(env, long)]
    pub smtp_server_tls_required: bool,

    /// Whether to verify client's EHLO hostname (A record)
    #[clap(env, long)]
    pub smtp_server_verify_ehlo_hostname: bool,

    /// Whether to verify reverse IP of the SMTP clients.
    /// It should resolve to a hostname and that hostname should resolve back to the same IP.
    /// Also an IP should match the client's IP.
    #[clap(env, long)]
    pub smtp_server_verify_reverse_ip: bool,

    /// Whether to verify the sender's domain (check FQDN and lookup MX records)
    #[clap(env, long)]
    pub smtp_server_verify_sender_domain: bool,

    /// Whether to verify the SPF records
    #[clap(env, long)]
    pub smtp_server_verify_spf: bool,

    /// Whether to verify the DKIM signatures
    #[clap(env, long)]
    pub smtp_server_verify_dkim: bool,

    /// Whether to require all DKIM signatures in the message to be valid.
    /// If disabled - at least one valid signature is enough to pass the DKIM
    /// validation.
    #[clap(env, long)]
    pub smtp_server_verify_dkim_strict: bool,
}

impl TryFrom<&SmtpServerCli> for SessionConfig {
    type Error = anyhow::Error;

    fn try_from(v: &SmtpServerCli) -> Result<Self, Self::Error> {
        let Some(hostname) = &v.smtp_server_hostname else {
            return Err(anyhow!("`smtp_server_hostname` is required"));
        };

        let mut cfg = Self::new(hostname, v.smtp_server_max_message_size as usize);
        cfg.greeting_delay = Some(v.smtp_server_greeting_delay);

        cfg.max_errors = v.smtp_server_max_errors_per_session;
        cfg.max_messages_per_session = v.smtp_server_max_messages_per_session;
        cfg.max_recipients = v.smtp_server_max_recipients;
        cfg.max_session_data = v.smtp_server_max_session_data as usize;
        cfg.max_session_duration = v.smtp_server_max_session_duration;

        cfg.timeout = v.smtp_server_timeout;

        cfg.verify_ehlo_hostname = v.smtp_server_verify_ehlo_hostname;
        cfg.verify_reverse_ip = v.smtp_server_verify_reverse_ip;
        cfg.verify_sender_domain = v.smtp_server_verify_sender_domain;
        cfg.verify_spf = v.smtp_server_verify_spf;
        cfg.verify_dkim = v.smtp_server_verify_dkim;
        cfg.verify_dkim_strict = v.smtp_server_verify_dkim_strict;

        Ok(cfg)
    }
}
