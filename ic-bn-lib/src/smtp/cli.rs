use std::{net::SocketAddr, time::Duration};

use anyhow::anyhow;
use clap::Args;
use humantime::parse_duration;
use url::Url;

use crate::{parse_size, smtp::inbound::SessionConfig};

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

    /// Maximum message body size.
    /// Default accounts for max IC message size + some overhead.
    #[clap(env, long, default_value = "1950KB", value_parser = parse_size)]
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

    /// Whether to verify client's EHLO hostname.
    /// Checks that it's an FQDN & that an A/AAAA record exists.
    #[clap(env, long)]
    pub smtp_server_verify_ehlo_hostname: bool,

    /// Whether to verify reverse IP of SMTP clients.
    /// The IP needs to have a PTR record present.
    #[clap(env, long)]
    pub smtp_server_verify_reverse_ip: bool,

    /// Whether to apply stricter rules to the reverse IP of SMTP clients.
    /// The PTR record should resolve back to the client's IP.
    /// This also maps permanent validation errors to the permanent SMTP failures (5xx).
    #[clap(env, long)]
    pub smtp_server_verify_reverse_ip_strict: bool,

    /// Whether to verify the sender's domain (check it's an FQDN and look up MX records)
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

    /// Setting this enables logging of SMTP sessions/messages/errors to Vector using native protocol.
    /// The rest of the options are used from LOG_VECTOR_* parameters.
    #[clap(env, long)]
    pub smtp_server_vector_url: Option<Url>,

    /// SMTP Vector username
    #[clap(env, long)]
    pub smtp_server_vector_user: Option<String>,

    /// SMTP Vector password
    #[clap(env, long)]
    pub smtp_server_vector_pass: Option<String>,
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
        cfg.verify_reverse_ip_strict = v.smtp_server_verify_reverse_ip_strict;
        cfg.verify_sender_domain = v.smtp_server_verify_sender_domain;
        cfg.verify_spf = v.smtp_server_verify_spf;
        cfg.verify_dkim = v.smtp_server_verify_dkim;
        cfg.verify_dkim_strict = v.smtp_server_verify_dkim_strict;

        Ok(cfg)
    }
}

#[cfg(test)]
mod test {
    use clap::{CommandFactory, Parser};

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        smtp: SmtpServerCli,
    }

    fn parse(args: &[&str]) -> SmtpServerCli {
        let mut v = vec!["test"];
        v.extend_from_slice(args);
        Cli::try_parse_from(v).unwrap().smtp
    }

    fn try_parse(args: &[&str]) -> Result<SmtpServerCli, clap::Error> {
        let mut v = vec!["test"];
        v.extend_from_slice(args);
        Cli::try_parse_from(v).map(|x| x.smtp)
    }

    #[test]
    fn test_cli_definition_is_valid() {
        // Catches e.g. a `requires` pointing at a non-existent argument id
        Cli::command().debug_assert();
    }

    #[test]
    fn test_defaults() {
        let c = parse(&[]);

        assert_eq!(c.smtp_server_listen, None);
        assert_eq!(c.smtp_server_hostname, None);
        assert_eq!(c.smtp_server_ic_base_domain, "icp0.io");
        assert_eq!(c.smtp_server_greeting_delay, Duration::from_secs(2));
        assert_eq!(c.smtp_server_max_recipients, 10);
        assert_eq!(c.smtp_server_max_messages_per_session, 5);
        assert_eq!(c.smtp_server_max_errors_per_session, 5);
        // Sizes are parsed with binary multipliers
        assert_eq!(c.smtp_server_max_message_size, 1950 * 1024);
        assert_eq!(c.smtp_server_max_session_data, 50 * 1024 * 1024);
        assert_eq!(c.smtp_server_max_session_duration, Duration::from_secs(120));
        assert_eq!(c.smtp_server_timeout, Duration::from_secs(30));
        assert_eq!(c.smtp_server_canister_cache_ttl, Duration::from_secs(600));
        assert_eq!(c.smtp_server_canister_cache_capacity, 100 * 1024);

        assert!(!c.smtp_server_tls_required);
        assert!(!c.smtp_server_verify_ehlo_hostname);
        assert!(!c.smtp_server_verify_reverse_ip);
        assert!(!c.smtp_server_verify_reverse_ip_strict);
        assert!(!c.smtp_server_verify_sender_domain);
        assert!(!c.smtp_server_verify_spf);
        assert!(!c.smtp_server_verify_dkim);
        assert!(!c.smtp_server_verify_dkim_strict);

        assert_eq!(c.smtp_server_vector_url, None);
        assert_eq!(c.smtp_server_vector_user, None);
        assert_eq!(c.smtp_server_vector_pass, None);

        // Parsing the same (empty) args twice yields an equal struct
        assert_eq!(c, parse(&[]));
    }

    #[test]
    fn test_listen_requires_hostname() {
        // Both of these are mutually required
        assert!(try_parse(&["--smtp-server-listen", "127.0.0.1:2525"]).is_err());
        assert!(try_parse(&["--smtp-server-hostname", "mx.foo.bar"]).is_err());

        let c = parse(&[
            "--smtp-server-listen",
            "127.0.0.1:2525",
            "--smtp-server-hostname",
            "mx.foo.bar",
        ]);
        assert_eq!(
            c.smtp_server_listen,
            Some("127.0.0.1:2525".parse().unwrap())
        );
        assert_eq!(c.smtp_server_hostname.as_deref(), Some("mx.foo.bar"));
    }

    #[test]
    fn test_explicit_values() {
        let c = parse(&[
            "--smtp-server-listen",
            "[::1]:1025",
            "--smtp-server-hostname",
            "mx.example.com",
            "--smtp-server-ic-base-domain",
            "ic0.app",
            "--smtp-server-greeting-delay",
            "500ms",
            "--smtp-server-max-recipients",
            "1",
            "--smtp-server-max-messages-per-session",
            "0",
            "--smtp-server-max-errors-per-session",
            "100",
            "--smtp-server-max-message-size",
            "1KB",
            "--smtp-server-max-session-data",
            "3MB",
            "--smtp-server-max-session-duration",
            "1h30m",
            "--smtp-server-timeout",
            "1s",
            "--smtp-server-canister-cache-ttl",
            "0s",
            "--smtp-server-canister-cache-capacity",
            "4096",
            "--smtp-server-tls-required",
            "--smtp-server-verify-ehlo-hostname",
            "--smtp-server-verify-reverse-ip",
            "--smtp-server-verify-reverse-ip-strict",
            "--smtp-server-verify-sender-domain",
            "--smtp-server-verify-spf",
            "--smtp-server-verify-dkim",
            "--smtp-server-verify-dkim-strict",
            "--smtp-server-vector-url",
            "http://127.0.0.1:9999/vector",
            "--smtp-server-vector-user",
            "user",
            "--smtp-server-vector-pass",
            "pass",
        ]);

        assert_eq!(c.smtp_server_listen, Some("[::1]:1025".parse().unwrap()));
        assert_eq!(c.smtp_server_hostname.as_deref(), Some("mx.example.com"));
        assert_eq!(c.smtp_server_ic_base_domain, "ic0.app");
        assert_eq!(c.smtp_server_greeting_delay, Duration::from_millis(500));
        assert_eq!(c.smtp_server_max_recipients, 1);
        assert_eq!(c.smtp_server_max_messages_per_session, 0);
        assert_eq!(c.smtp_server_max_errors_per_session, 100);
        assert_eq!(c.smtp_server_max_message_size, 1024);
        assert_eq!(c.smtp_server_max_session_data, 3 * 1024 * 1024);
        assert_eq!(
            c.smtp_server_max_session_duration,
            Duration::from_secs(5400)
        );
        assert_eq!(c.smtp_server_timeout, Duration::from_secs(1));
        assert_eq!(c.smtp_server_canister_cache_ttl, Duration::ZERO);
        assert_eq!(c.smtp_server_canister_cache_capacity, 4096);

        assert!(c.smtp_server_tls_required);
        assert!(c.smtp_server_verify_ehlo_hostname);
        assert!(c.smtp_server_verify_reverse_ip);
        assert!(c.smtp_server_verify_reverse_ip_strict);
        assert!(c.smtp_server_verify_sender_domain);
        assert!(c.smtp_server_verify_spf);
        assert!(c.smtp_server_verify_dkim);
        assert!(c.smtp_server_verify_dkim_strict);

        assert_eq!(
            c.smtp_server_vector_url,
            Some(Url::parse("http://127.0.0.1:9999/vector").unwrap())
        );
        assert_eq!(c.smtp_server_vector_user.as_deref(), Some("user"));
        assert_eq!(c.smtp_server_vector_pass.as_deref(), Some("pass"));

        assert_ne!(c, parse(&[]));
    }

    #[test]
    fn test_invalid_values() {
        // Not a socket address (missing port)
        assert!(
            try_parse(&[
                "--smtp-server-listen",
                "127.0.0.1",
                "--smtp-server-hostname",
                "mx",
            ])
            .is_err()
        );
        // Not a duration
        assert!(try_parse(&["--smtp-server-timeout", "soon"]).is_err());
        assert!(try_parse(&["--smtp-server-timeout", "30"]).is_err());
        // Not a size
        assert!(try_parse(&["--smtp-server-max-message-size", "big"]).is_err());
        // Not a number
        assert!(try_parse(&["--smtp-server-max-recipients", "-1"]).is_err());
        // Not a URL
        assert!(try_parse(&["--smtp-server-vector-url", "not a url"]).is_err());
        // Flags take no value
        assert!(try_parse(&["--smtp-server-verify-spf", "true"]).is_err());
        // Unknown argument
        assert!(try_parse(&["--smtp-server-nonexistent"]).is_err());
    }

    #[test]
    fn test_session_config_requires_hostname() {
        let cli = parse(&[]);
        let Err(err) = SessionConfig::try_from(&cli) else {
            panic!("SessionConfig must not be built without a hostname");
        };
        assert_eq!(err.to_string(), "`smtp_server_hostname` is required");
    }

    #[test]
    fn test_session_config_mapping() {
        let cli = parse(&[
            "--smtp-server-listen",
            "127.0.0.1:2525",
            "--smtp-server-hostname",
            "mx.example.com",
            "--smtp-server-greeting-delay",
            "3s",
            "--smtp-server-max-recipients",
            "7",
            "--smtp-server-max-messages-per-session",
            "8",
            "--smtp-server-max-errors-per-session",
            "9",
            "--smtp-server-max-session-data",
            "1KB",
            "--smtp-server-max-session-duration",
            "42s",
            "--smtp-server-timeout",
            "11s",
            "--smtp-server-verify-ehlo-hostname",
            "--smtp-server-verify-spf",
            "--smtp-server-verify-dkim-strict",
        ]);

        let cfg = SessionConfig::try_from(&cli).unwrap();

        assert_eq!(cfg.greeting_delay, Some(Duration::from_secs(3)));
        assert_eq!(cfg.max_recipients, 7);
        assert_eq!(cfg.max_messages_per_session, 8);
        assert_eq!(cfg.max_errors, 9);
        assert_eq!(cfg.max_session_data, 1024);
        assert_eq!(cfg.max_session_duration, Duration::from_secs(42));
        assert_eq!(cfg.timeout, Duration::from_secs(11));

        assert!(cfg.verify_ehlo_hostname);
        assert!(cfg.verify_spf);
        assert!(cfg.verify_dkim_strict);
        // Not requested - must stay off
        assert!(!cfg.verify_reverse_ip);
        assert!(!cfg.verify_reverse_ip_strict);
        assert!(!cfg.verify_sender_domain);
        assert!(!cfg.verify_dkim);

        // Not wired through the CLI - keeps the `SessionConfig::new()` default
        assert_eq!(cfg.max_received_headers, 50);
        // TLS mode is set up elsewhere (needs a cert resolver)
        assert!(!cfg.tls_mode.enabled());
    }

    #[test]
    fn test_session_config_mapping_defaults() {
        let cli = parse(&[
            "--smtp-server-listen",
            "127.0.0.1:2525",
            "--smtp-server-hostname",
            "mx.example.com",
        ]);
        let cfg = SessionConfig::try_from(&cli).unwrap();

        // The CLI always sets an explicit greeting delay, even the default one
        assert_eq!(cfg.greeting_delay, Some(Duration::from_secs(2)));
        assert_eq!(cfg.max_recipients, 10);
        assert_eq!(cfg.max_session_data, 50 * 1024 * 1024);
        assert_eq!(cfg.max_session_duration, Duration::from_secs(120));
        assert_eq!(cfg.timeout, Duration::from_secs(30));
    }
    /// `SessionConfig`'s `max_message_size` field is private and `SessionConfig`
    /// has no `Debug`, so the only way to observe that the CLI actually wires
    /// `--smtp-server-max-message-size` into it is the `SIZE` capability that a
    /// session advertises in its EHLO response.
    #[tokio::test]
    async fn test_session_config_max_message_size_is_advertised() {
        use prometheus::Registry;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio_util::sync::CancellationToken;

        use crate::{
            network::{ListenerOpts, listener::listen_tcp},
            smtp::{Metrics, server::Server},
        };

        let cli = parse(&[
            "--smtp-server-listen",
            "127.0.0.1:2525",
            "--smtp-server-hostname",
            "mx.example.com",
            "--smtp-server-max-message-size",
            "12KB",
            // Deliberately different from the message size so that mixing the
            // two options up is caught
            "--smtp-server-max-session-data",
            "7MB",
            "--smtp-server-greeting-delay",
            "0s",
        ]);
        assert_eq!(cli.smtp_server_max_message_size, 12 * 1024);
        assert_eq!(cli.smtp_server_max_session_data, 7 * 1024 * 1024);

        let cfg = SessionConfig::try_from(&cli).unwrap();

        let listener = listen_tcp("127.0.0.1:0".parse().unwrap(), ListenerOpts::default()).unwrap();
        let addr = listener.local_addr().unwrap();
        let server =
            Server::new_with_listener(listener, cfg, Metrics::new(&Registry::new())).unwrap();

        let token = CancellationToken::new();
        let handle = tokio::spawn({
            let token = token.child_token();
            async move { server.serve(token).await }
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0; 4096];

        let n = stream.read(&mut buf).await.unwrap();
        let greeting = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            greeting.starts_with("220 mx.example.com"),
            "hostname must come from the CLI, got: {greeting:?}"
        );

        stream
            .write_all(b"EHLO client.example.com\r\n")
            .await
            .unwrap();

        // The EHLO reply is multi-line; the last line starts with "250 "
        let mut reply = String::new();
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            reply.push_str(&String::from_utf8_lossy(&buf[..n]));
            if reply.lines().any(|x| x.starts_with("250 ")) {
                break;
            }
        }

        assert!(
            reply.contains("SIZE 12288"),
            "EHLO must advertise the CLI's max message size (12288), got:\n{reply}"
        );
        assert!(
            !reply.contains("7340032"),
            "max_session_data must not be advertised as SIZE, got:\n{reply}"
        );

        token.cancel();
        handle.await.unwrap().unwrap();
    }
}
