use std::str::FromStr;

use fqdn::FQDN;
use tracing::{debug, info};

use crate::{
    dns::is_error_negative_lookup,
    network::AsyncReadWrite,
    smtp::{
        ProtocolError,
        inbound::{Session, SessionResult},
    },
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles EHLO/HELO commands
    pub async fn handle_ehlo(&mut self, host: &str, extended: bool) -> SessionResult<()> {
        // Validate hostname
        let Ok(ehlo_hostname) = FQDN::from_str(host) else {
            info!("{self}: {host}: Invalid EHLO hostname");
            self.set_error(ProtocolError::InvalidEhloHostname(format!(
                "{host}: incorrect hostname"
            )));
            return self.reply("550", "5.5.0", "Invalid EHLO hostname.").await;
        };

        // If EHLO hostname is already set to the same value - just reply directly,
        // avoid redundant checks
        if let Some(v) = &self.data.ehlo_hostname
            && v == &ehlo_hostname
        {
            return self.send_ehlo(extended).await;
        }

        if ehlo_hostname.depth() < 2 {
            info!("{self}: {host}: EHLO is not FQDN");
            self.set_error(ProtocolError::InvalidEhloHostname(format!(
                "{host}: not FQDN"
            )));
            return self
                .reply("550", "5.5.0", "EHLO hostname must be an FQDN.")
                .await;
        };

        // Check if EHLO hostname resolves if configured
        if self.cfg.verify_ehlo_hostname {
            match self.cfg.authenticator.resolver().lookup_ip(host).await {
                Ok(v) => match v.iter().next() {
                    Some(v) => {
                        debug!("{self}: {host}: EHLO hostname found in DNS: {v}");
                    }
                    None => {
                        info!("{self}: {host}: EHLO not found in DNS");
                        self.set_error(ProtocolError::InvalidEhloHostname(format!(
                            "{host}: not found in DNS"
                        )));
                        return self
                            .reply("550", "5.5.0", "EHLO hostname not found in DNS.")
                            .await;
                    }
                },

                Err(e) => {
                    info!("{self}: {host}: EHLO not found in DNS: {e:#}");

                    if is_error_negative_lookup(&e) {
                        self.set_error(ProtocolError::InvalidEhloHostname(format!(
                            "{host}: not found in DNS: {e:#}"
                        )));

                        return self
                            .reply("550", "5.5.0", "EHLO hostname not found in DNS.")
                            .await;
                    }

                    return self
                        .reply("451", "4.7.25", "Temporary error validating EHLO hostname.")
                        .await;
                }
            }
        }

        self.reset_message();
        self.data.ehlo_hostname = Some(ehlo_hostname);

        return self.send_ehlo(extended).await;
    }

    async fn send_ehlo(&mut self, extended: bool) -> SessionResult<()> {
        let buf = if !extended {
            &self.cfg.helo
        } else if self.tls_info.is_none() && self.cfg.tls_mode.enabled() {
            &self.cfg.ehlo_tls
        } else {
            &self.cfg.ehlo
        };

        self.write(&buf.clone()).await
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::RecordType;

    use crate::smtp::inbound::{
        SessionConfig, SessionTlsMode,
        mail_from::test::{
            Capture, dns,
            dns::{Answer, FakeDns},
            fake_tls_info, new_session, test_config, tls_server_config,
        },
    };

    use super::*;

    /// Config with EHLO-hostname verification pointed at the given fake zone
    fn verify_config(dns: &dns::RunningDns) -> SessionConfig {
        let mut cfg = test_config();
        cfg.verify_ehlo_hostname = true;
        cfg.authenticator = dns.authenticator.clone();
        cfg
    }

    /// Everything that `FQDN` itself refuses
    #[tokio::test]
    async fn test_ehlo_invalid_hostname() {
        for host in ["foo..bar", "foo bar", "a\"b.com"] {
            let (mut session, out) = new_session(test_config());

            // Pretend there's a transaction in progress - a failed EHLO must not touch it
            session.data.mail_from = Some("a@example.com".try_into().unwrap());

            session.handle_ehlo(host, true).await.unwrap();

            assert_eq!(
                out.take(),
                "550 5.5.0 Invalid EHLO hostname.\r\n",
                "host={host:?}"
            );
            assert!(session.data.ehlo_hostname.is_none());
            assert!(session.data.mail_from.is_some());
            assert_eq!(session.counters.errors, 1);
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::InvalidEhloHostname(ref v))
                    if v == &format!("{host}: incorrect hostname")
            ));
        }
    }

    /// Syntactically valid but shallower than two labels
    #[tokio::test]
    async fn test_ehlo_must_be_fqdn() {
        // "" and "." both parse into the root domain, which has depth 0
        for host in ["localhost", "", ".", "com."] {
            let (mut session, out) = new_session(test_config());
            session.handle_ehlo(host, true).await.unwrap();

            assert_eq!(
                out.take(),
                "550 5.5.0 EHLO hostname must be an FQDN.\r\n",
                "host={host:?}"
            );
            assert!(session.data.ehlo_hostname.is_none());
            assert_eq!(session.counters.errors, 1);
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::InvalidEhloHostname(ref v)) if v == &format!("{host}: not FQDN")
            ));
        }

        // Two labels is the minimum accepted
        let (mut session, out) = new_session(test_config());
        session.handle_ehlo("foo.bar", true).await.unwrap();
        assert!(out.take().starts_with("250-"));
        assert_eq!(session.counters.errors, 0);
    }

    #[tokio::test]
    async fn test_helo_gets_a_single_line_reply() {
        let (mut session, out) = new_session(test_config());
        session.handle_ehlo("foo.bar", false).await.unwrap();

        assert_eq!(out.take(), "250 test you had me at HELO\r\n");
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "foo.bar"
        );
    }

    #[tokio::test]
    async fn test_ehlo_advertises_capabilities() {
        // The advertised SIZE must follow the configured message limit
        let (mut session, out) = new_session(SessionConfig::new("mx.example.com", 1234));
        session.handle_ehlo("foo.bar", true).await.unwrap();

        assert_eq!(
            out.take(),
            concat!(
                "250-mx.example.com you had me at EHLO\r\n",
                "250-SMTPUTF8\r\n",
                "250-SIZE 1234\r\n",
                "250-PIPELINING\r\n",
                "250-ENHANCEDSTATUSCODES\r\n",
                "250-CHUNKING\r\n",
                "250 8BITMIME\r\n",
            )
        );
    }

    #[tokio::test]
    async fn test_ehlo_advertises_starttls_only_before_tls() {
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Allowed(tls_server_config());
        let (mut session, out) = new_session(cfg);

        session.handle_ehlo("foo.bar", true).await.unwrap();
        let reply = out.take();
        assert!(reply.contains("250-STARTTLS\r\n"), "{reply}");

        // Inside a TLS session STARTTLS must be gone
        session.tls_info = Some(fake_tls_info());
        session.handle_ehlo("foo.bar", true).await.unwrap();
        let reply = out.take();
        assert!(!reply.contains("STARTTLS"), "{reply}");
        assert!(
            reply.starts_with("250-test you had me at EHLO\r\n"),
            "{reply}"
        );

        // HELO never advertises anything, with or without TLS
        session.handle_ehlo("foo.bar", false).await.unwrap();
        assert_eq!(out.take(), "250 test you had me at HELO\r\n");
    }

    /// With TLS switched off entirely STARTTLS is never offered
    #[tokio::test]
    async fn test_ehlo_no_starttls_when_tls_disabled() {
        let (mut session, out) = new_session(test_config());
        session.handle_ehlo("foo.bar", true).await.unwrap();

        let reply = out.take();
        assert!(!reply.contains("STARTTLS"), "{reply}");
    }

    #[tokio::test]
    async fn test_ehlo_resets_the_transaction_only_on_a_new_hostname() {
        let (mut session, out) = new_session(test_config());
        session.handle_ehlo("foo.bar", true).await.unwrap();
        out.take();

        fn stage_transaction(session: &mut Session<Capture>) {
            session.data.mail_from = Some("a@example.com".try_into().unwrap());
            session
                .data
                .rcpt_to
                .push("b@example.com".try_into().unwrap());
            session.data.message.extend_from_slice(b"partial");
        }
        stage_transaction(&mut session);

        // Repeating the same hostname (case-insensitively) short-circuits and
        // must leave the in-progress transaction alone
        session.handle_ehlo("FOO.BAR", true).await.unwrap();
        assert!(out.take().starts_with("250-"));
        assert!(session.data.mail_from.is_some());
        assert_eq!(session.data.rcpt_to.len(), 1);
        assert_eq!(session.data.message.as_slice(), b"partial");

        // A different hostname resets it (RFC 5321 4.1.1.1)
        session.handle_ehlo("other.host", true).await.unwrap();
        assert!(out.take().starts_with("250-"));
        assert!(session.data.mail_from.is_none());
        assert!(session.data.rcpt_to.is_empty());
        assert!(session.data.message.is_empty());
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "other.host"
        );

        // Switching from EHLO to HELO with the same hostname is also a no-op
        stage_transaction(&mut session);
        session.handle_ehlo("other.host", false).await.unwrap();
        assert_eq!(out.take(), "250 test you had me at HELO\r\n");
        assert!(session.data.mail_from.is_some());
    }

    #[tokio::test]
    async fn test_ehlo_normalizes_the_stored_hostname() {
        let (mut session, out) = new_session(test_config());
        session.handle_ehlo("Foo.BAR.", true).await.unwrap();

        assert!(out.take().starts_with("250-"));
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "foo.bar"
        );
    }

    /// `Required` is also "enabled", so STARTTLS has to be advertised - otherwise
    /// a client could never satisfy the requirement
    #[tokio::test]
    async fn test_ehlo_advertises_starttls_when_tls_is_required() {
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Required(tls_server_config());
        let (mut session, out) = new_session(cfg);

        session.handle_ehlo("foo.bar", true).await.unwrap();
        let reply = out.take();
        assert!(reply.contains("250-STARTTLS\r\n"), "{reply}");

        // HELO still gets the plain one-liner
        session.handle_ehlo("foo.bar", false).await.unwrap();
        assert_eq!(out.take(), "250 test you had me at HELO\r\n");
    }

    /// The advertised capability list is exactly the one built by the config, i.e.
    /// `send_ehlo` picks the pre-rendered `ehlo_tls` body & not a rebuilt one
    #[tokio::test]
    async fn test_ehlo_body_comes_from_the_config() {
        let mut cfg = SessionConfig::new("mx.example.com", 42);
        cfg.tls_mode = SessionTlsMode::Allowed(tls_server_config());
        let (ehlo, ehlo_tls) = (cfg.ehlo.clone(), cfg.ehlo_tls.clone());
        let (mut session, out) = new_session(cfg);

        session.handle_ehlo("foo.bar", true).await.unwrap();
        assert_eq!(out.take().as_bytes(), &ehlo_tls[..]);

        session.tls_info = Some(fake_tls_info());
        session.handle_ehlo("foo.bar", true).await.unwrap();
        assert_eq!(out.take().as_bytes(), &ehlo[..]);
        assert_ne!(ehlo, ehlo_tls);
    }

    #[tokio::test]
    async fn test_ehlo_dns_verification_success() {
        let dns = FakeDns::new()
            .a("foo.bar", &[Ipv4Addr::new(1, 2, 3, 4)])
            .spawn()
            .await;

        let (mut session, out) = new_session(verify_config(&dns));
        session.handle_ehlo("foo.bar", true).await.unwrap();

        assert!(out.take().starts_with("250-test you had me at EHLO\r\n"));
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "foo.bar"
        );
        assert_eq!(session.counters.errors, 0);
    }

    /// A negative answer is permanent
    #[tokio::test]
    async fn test_ehlo_dns_verification_not_found() {
        for answer in [Answer::NxDomain, Answer::Empty] {
            let dns = FakeDns::new()
                .answer("foo.bar", RecordType::A, answer)
                .spawn()
                .await;

            let (mut session, out) = new_session(verify_config(&dns));
            session.handle_ehlo("foo.bar", true).await.unwrap();

            assert_eq!(out.take(), "550 5.5.0 EHLO hostname not found in DNS.\r\n");
            assert!(session.data.ehlo_hostname.is_none());
            assert_eq!(session.counters.errors, 1);
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::InvalidEhloHostname(ref v))
                    if v.starts_with("foo.bar: not found in DNS")
            ));
        }
    }

    /// A broken resolver is retryable - and this branch replies without recording
    /// a protocol error, so the client isn't pushed towards the error limit
    #[tokio::test]
    async fn test_ehlo_dns_verification_temporary_error() {
        for answer in [Answer::ServFail, Answer::Drop] {
            let dns = FakeDns::new()
                .answer("foo.bar", RecordType::A, answer)
                .spawn()
                .await;

            let (mut session, out) = new_session(verify_config(&dns));
            session.handle_ehlo("foo.bar", true).await.unwrap();

            assert_eq!(
                out.take(),
                "451 4.7.25 Temporary error validating EHLO hostname.\r\n"
            );
            assert!(session.data.ehlo_hostname.is_none());
            assert_eq!(session.counters.errors, 0);
            assert!(session.data.last_error.is_none());
        }
    }

    /// The lookup uses the hostname as it came off the wire, so the comparison has
    /// to survive the case & the trailing dot
    #[tokio::test]
    async fn test_ehlo_dns_verification_is_case_insensitive() {
        let dns = FakeDns::new()
            .a("foo.bar", &[Ipv4Addr::new(1, 2, 3, 4)])
            .spawn()
            .await;

        let (mut session, out) = new_session(verify_config(&dns));
        session.handle_ehlo("FOO.BAR.", true).await.unwrap();

        assert!(out.take().starts_with("250-"));
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "foo.bar"
        );
    }

    /// Repeating the hostname short-circuits before the DNS check, so a zone that
    /// would reject it doesn't invalidate an already-accepted session
    #[tokio::test]
    async fn test_ehlo_repeated_hostname_skips_the_dns_check() {
        // Empty zone - any lookup would come back NXDOMAIN
        let dns = FakeDns::new().spawn().await;

        let (mut session, out) = new_session(verify_config(&dns));
        session.data.ehlo_hostname = Some(FQDN::from_str("foo.bar").unwrap());
        session.data.mail_from = Some("a@example.com".try_into().unwrap());

        session.handle_ehlo("FOO.BAR", true).await.unwrap();
        assert!(out.take().starts_with("250-"));
        assert_eq!(session.counters.errors, 0);
        assert!(session.data.mail_from.is_some());
    }

    /// A rejected EHLO must leave both the stored hostname & the in-flight
    /// transaction exactly as they were - `reset_message()` runs only on success
    #[tokio::test]
    async fn test_ehlo_dns_failure_keeps_the_previous_state() {
        let dns = FakeDns::new().spawn().await;

        let (mut session, out) = new_session(verify_config(&dns));
        session.data.ehlo_hostname = Some(FQDN::from_str("foo.bar").unwrap());
        session.data.mail_from = Some("a@example.com".try_into().unwrap());
        session
            .data
            .rcpt_to
            .push("b@example.com".try_into().unwrap());
        session.data.message.extend_from_slice(b"partial");

        session.handle_ehlo("other.host", true).await.unwrap();

        assert_eq!(out.take(), "550 5.5.0 EHLO hostname not found in DNS.\r\n");
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "foo.bar"
        );
        assert!(session.data.mail_from.is_some());
        assert_eq!(session.data.rcpt_to.len(), 1);
        assert_eq!(session.data.message.as_slice(), b"partial");
    }

    /// Nothing is looked up while `verify_ehlo_hostname` is off
    #[tokio::test]
    async fn test_ehlo_verification_disabled_skips_the_lookup() {
        let dns = FakeDns::new().spawn().await;

        let mut cfg = verify_config(&dns);
        cfg.verify_ehlo_hostname = false;
        let (mut session, out) = new_session(cfg);
        session.handle_ehlo("foo.bar", true).await.unwrap();

        assert!(out.take().starts_with("250-"));
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "foo.bar"
        );
    }

    /// The FQDN check happens before the DNS one, so a single-label hostname is
    /// never looked up
    #[tokio::test]
    async fn test_ehlo_fqdn_check_precedes_the_dns_check() {
        let dns = FakeDns::new()
            .a("localhost", &[Ipv4Addr::new(1, 2, 3, 4)])
            .spawn()
            .await;

        let (mut session, out) = new_session(verify_config(&dns));
        session.handle_ehlo("localhost", true).await.unwrap();

        assert_eq!(out.take(), "550 5.5.0 EHLO hostname must be an FQDN.\r\n");
        assert!(matches!(
            session.data.last_error,
            Some(ProtocolError::InvalidEhloHostname(ref v)) if v == "localhost: not FQDN"
        ));
    }

    /// A deep hostname is fine, and the trailing dot is not counted as a label
    #[tokio::test]
    async fn test_ehlo_accepts_deep_hostnames() {
        let (mut session, out) = new_session(test_config());
        session
            .handle_ehlo("a.b.c.d.e.f.example.com.", true)
            .await
            .unwrap();

        assert!(out.take().starts_with("250-"));
        assert_eq!(
            session.data.ehlo_hostname.as_ref().unwrap().to_string(),
            "a.b.c.d.e.f.example.com"
        );
    }
}
