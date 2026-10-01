use std::{borrow::Cow, fmt::Write as _, str::FromStr};

use smtp_proto::{
    RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS, RcptTo,
};
use tracing::{debug, info};

use crate::{
    network::AsyncReadWrite,
    smtp::{
        ProtocolError, RecipientPolicy, RecipientResolveError,
        address::EmailAddress,
        inbound::{MAX_REPLY_LEN, Session, SessionResult},
    },
    truncate,
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles RCPT TO command
    pub async fn handle_rcpt_to(&mut self, to: RcptTo<Cow<'_, str>>) -> SessionResult<()> {
        let Some(mail_from) = &self.data.mail_from else {
            self.set_error(ProtocolError::InvalidSequenceOfCommands(
                "RCPT TO before MAIL FROM".into(),
            ));
            return self
                .reply("503", "5.5.1", "MAIL FROM is required first.")
                .await;
        };

        // Check if DSN-related stuff was requested
        if (to.flags
            & (RCPT_NOTIFY_DELAY | RCPT_NOTIFY_NEVER | RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE))
            != 0
            || to.orcpt.is_some()
        {
            return self.ext_unsupported("DSN").await;
        }

        let Ok(address) = EmailAddress::from_str(&to.address) else {
            info!("{self}: {}: incorrect address", to.address);
            self.set_error(ProtocolError::RecipientValidationFailed(format!(
                "Incorrect address: {}",
                to.address
            )));
            return self.reply("550", "5.1.2", "Incorrect address.").await;
        };

        if self.data.rcpt_to.contains(&address) {
            return self.reply("250", "2.1.5", "OK").await;
        }

        if self.data.rcpt_to.len() >= self.cfg.max_recipients {
            info!("{self}: {}: too many recipients", to.address);
            self.set_error(ProtocolError::RecipientValidationFailed(format!(
                "Too many recipients: {} > {}",
                self.data.rcpt_to.len(),
                self.cfg.max_recipients
            )));
            return self.reply("455", "4.5.3", "Too many recipients.").await;
        }

        match self
            .cfg
            .recipient_resolver
            .resolve_recipient(mail_from, &address)
            .await
        {
            Ok(v) => {
                debug!("{self}: {}: recipient resolved: {v}", to.address);

                // If the sender told us how big the message is, and this
                // recipient's backend cannot take it, fail here rather
                // than after the whole body has been transferred. Other
                // recipients in the same transaction are unaffected.
                if let Some(declared) = self.data.declared_size
                    && let Some(limit) = self
                        .cfg
                        .recipient_resolver
                        .recipient_max_message_size(&address)
                        .await
                    && declared > limit
                {
                    info!(
                        "{self}: {}: declared size {declared} exceeds recipient limit {limit}",
                        to.address
                    );

                    self.set_error(ProtocolError::MessageTooBig(format!(
                        "{declared} > {limit} for {}",
                        to.address
                    )));

                    return self
                        .reply_with("552", "5.3.4", |buf| {
                            write!(buf, "Recipient accepts at most {limit} bytes.")
                        })
                        .await;
                }

                match v {
                    RecipientPolicy::Accept => {
                        self.data.rcpt_to.push(address);
                    }
                    RecipientPolicy::Rewrite(new_address) => {
                        self.data.rcpt_to.push(new_address);
                    }
                    RecipientPolicy::Expand(additional_addresses) => {
                        self.data.rcpt_to.push(address);
                        self.data.rcpt_to.extend(additional_addresses);
                    }
                }
            }

            Err(e) => {
                info!("{self}: {}: recipient resolution error: {e:#}", to.address);
                self.set_error(ProtocolError::RecipientValidationFailed(format!(
                    "Recipient resolution failed: {e:#}",
                )));

                return match e {
                    RecipientResolveError::UnknownDomain => {
                        self.reply("550", "5.1.1", "Unknown recipient domain.")
                            .await
                    }
                    RecipientResolveError::UnknownRecipient => {
                        self.reply("550", "5.1.2", "Mailbox does not exist.").await
                    }
                    // Truncate the errors so that they don't overflow the reply buffer
                    RecipientResolveError::Temporary(v) => {
                        self.reply_with("451", "4.4.3", |buf| {
                            write!(buf, "Temporary error: {}", truncate(&v, MAX_REPLY_LEN - 32))
                        })
                        .await
                    }
                    RecipientResolveError::Permanent(v) => {
                        self.reply_with("550", "5.1.3", |buf| {
                            write!(buf, "Permanent error: {}", truncate(&v, MAX_REPLY_LEN - 32))
                        })
                        .await
                    }
                };
            }
        }

        self.reply("250", "2.1.5", "OK").await
    }
}

#[cfg(test)]
mod test {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use smtp_proto::{RCPT_CONNEG, RCPT_RRVS_REJECT};

    use crate::smtp::{
        ResolvesRecipient,
        inbound::mail_from::test::{
            Capture, mail_from, new_session, session_with_ehlo, test_config,
        },
    };

    use super::*;

    /// What the stub resolver should answer with
    #[derive(Debug, Clone)]
    enum Outcome {
        Accept,
        Rewrite(EmailAddress),
        Expand(Vec<EmailAddress>),
        UnknownDomain,
        UnknownRecipient,
        Temporary(String),
        Permanent(String),
    }

    #[derive(Debug)]
    struct StubRecipientResolver {
        outcome: Outcome,
        seen: Mutex<Vec<String>>,
        calls: AtomicUsize,
    }

    impl StubRecipientResolver {
        fn new(outcome: Outcome) -> Arc<Self> {
            Arc::new(Self {
                outcome,
                seen: Mutex::new(vec![]),
                calls: AtomicUsize::new(0),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ResolvesRecipient for StubRecipientResolver {
        async fn resolve_recipient(
            &self,
            from: &EmailAddress,
            rcpt: &EmailAddress,
        ) -> Result<RecipientPolicy, RecipientResolveError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(format!("{from} -> {rcpt}"));

            match &self.outcome {
                Outcome::Accept => Ok(RecipientPolicy::Accept),
                Outcome::Rewrite(v) => Ok(RecipientPolicy::Rewrite(v.clone())),
                Outcome::Expand(v) => Ok(RecipientPolicy::Expand(v.clone())),
                Outcome::UnknownDomain => Err(RecipientResolveError::UnknownDomain),
                Outcome::UnknownRecipient => Err(RecipientResolveError::UnknownRecipient),
                Outcome::Temporary(v) => Err(RecipientResolveError::Temporary(v.clone())),
                Outcome::Permanent(v) => Err(RecipientResolveError::Permanent(v.clone())),
            }
        }
    }

    /// Bare `RCPT TO:<address>` without any ESMTP parameters
    fn rcpt_to(address: &str) -> RcptTo<Cow<'_, str>> {
        RcptTo {
            address: Cow::Borrowed(address),
            ..Default::default()
        }
    }

    /// Session that already accepted `MAIL FROM:<sender@example.com>`
    async fn session_ready(
        outcome: Outcome,
        max_recipients: usize,
    ) -> (Session<Capture>, Capture, Arc<StubRecipientResolver>) {
        let resolver = StubRecipientResolver::new(outcome);

        let mut cfg = test_config();
        cfg.max_recipients = max_recipients;
        cfg.recipient_resolver = resolver.clone();

        let (mut session, out) = session_with_ehlo(cfg);
        session
            .handle_mail_from(mail_from("sender@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");

        (session, out, resolver)
    }

    #[tokio::test]
    async fn test_rcpt_to_before_mail_from() {
        let (mut session, out) = session_with_ehlo(test_config());
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "503 5.5.1 MAIL FROM is required first.\r\n");
        assert!(session.data.rcpt_to.is_empty());
        assert_eq!(session.counters.errors, 1);
        assert!(matches!(
            session.data.last_error,
            Some(ProtocolError::InvalidSequenceOfCommands(ref v)) if v == "RCPT TO before MAIL FROM"
        ));
    }

    /// Even before EHLO the missing MAIL FROM is what's reported
    #[tokio::test]
    async fn test_rcpt_to_before_ehlo() {
        let (mut session, out) = new_session(test_config());
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "503 5.5.1 MAIL FROM is required first.\r\n");
    }

    #[tokio::test]
    async fn test_rcpt_to_dsn_unsupported() {
        for flags in [
            RCPT_NOTIFY_SUCCESS,
            RCPT_NOTIFY_FAILURE,
            RCPT_NOTIFY_DELAY,
            RCPT_NOTIFY_NEVER,
            RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_DELAY,
        ] {
            let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
            let mut to = rcpt_to("a@example.com");
            to.flags = flags;

            session.handle_rcpt_to(to).await.unwrap();
            assert_eq!(
                out.take(),
                "501 5.5.4 DSN extension is not supported.\r\n",
                "flags={flags}"
            );
            assert!(session.data.rcpt_to.is_empty());
            assert_eq!(resolver.calls(), 0);
        }

        // ORCPT belongs to DSN as well
        let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
        let mut to = rcpt_to("a@example.com");
        to.orcpt = Some(Cow::Borrowed("a@example.com"));
        session.handle_rcpt_to(to).await.unwrap();
        assert_eq!(out.take(), "501 5.5.4 DSN extension is not supported.\r\n");
        assert_eq!(resolver.calls(), 0);
    }

    /// RRVS/CONNEG flags sit outside the rejected DSN mask & must not trip it
    #[tokio::test]
    async fn test_rcpt_to_non_dsn_flags_are_ignored() {
        let (mut session, out, _) = session_ready(Outcome::Accept, 5).await;
        let mut to = rcpt_to("a@example.com");
        to.flags = RCPT_RRVS_REJECT | RCPT_CONNEG;
        to.rrvs = 1_577_836_800;

        session.handle_rcpt_to(to).await.unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(session.data.rcpt_to.len(), 1);
    }

    #[tokio::test]
    async fn test_rcpt_to_invalid_address() {
        for address in ["", "nodomain", "a@", "a@b c", "a@foo..bar"] {
            let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
            session.handle_rcpt_to(rcpt_to(address)).await.unwrap();

            assert_eq!(
                out.take(),
                "550 5.1.2 Incorrect address.\r\n",
                "address={address:?}"
            );
            assert!(session.data.rcpt_to.is_empty());
            assert_eq!(resolver.calls(), 0);
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::RecipientValidationFailed(ref v))
                    if v == &format!("Incorrect address: {address}")
            ));
        }
    }

    #[tokio::test]
    async fn test_rcpt_to_passes_the_sender_to_the_resolver() {
        let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(resolver.seen(), ["sender@example.com -> a@example.com"]);
        assert_eq!(
            session
                .data
                .rcpt_to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["a@example.com"]
        );
    }

    #[tokio::test]
    async fn test_rcpt_to_deduplicates() {
        let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;

        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");

        // The domain is compared case-insensitively, so this is the same recipient
        session
            .handle_rcpt_to(rcpt_to("a@EXAMPLE.COM"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(session.data.rcpt_to.len(), 1);
        assert_eq!(resolver.calls(), 1);

        // ...but the local part is case-sensitive, so this one is new
        session
            .handle_rcpt_to(rcpt_to("A@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(session.data.rcpt_to.len(), 2);
        assert_eq!(resolver.calls(), 2);
    }

    #[tokio::test]
    async fn test_rcpt_to_max_recipients() {
        let (mut session, out, resolver) = session_ready(Outcome::Accept, 2).await;

        for address in ["a@example.com", "b@example.com"] {
            session.handle_rcpt_to(rcpt_to(address)).await.unwrap();
            assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        }

        session
            .handle_rcpt_to(rcpt_to("c@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "455 4.5.3 Too many recipients.\r\n");
        assert_eq!(session.data.rcpt_to.len(), 2);
        // The rejected recipient never reaches the resolver
        assert_eq!(resolver.calls(), 2);
        assert!(matches!(
            session.data.last_error,
            Some(ProtocolError::RecipientValidationFailed(ref v))
                if v == "Too many recipients: 2 > 2"
        ));

        // An already-accepted recipient is still fine at the limit,
        // because the duplicate check runs before the limit check
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(session.data.rcpt_to.len(), 2);
    }

    #[tokio::test]
    async fn test_rcpt_to_max_recipients_zero_rejects_everything() {
        let (mut session, out, resolver) = session_ready(Outcome::Accept, 0).await;
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "455 4.5.3 Too many recipients.\r\n");
        assert!(session.data.rcpt_to.is_empty());
        assert_eq!(resolver.calls(), 0);
    }

    #[tokio::test]
    async fn test_rcpt_to_resolver_errors() {
        for (outcome, expected) in [
            (
                Outcome::UnknownDomain,
                "550 5.1.1 Unknown recipient domain.\r\n",
            ),
            (
                Outcome::UnknownRecipient,
                "550 5.1.2 Mailbox does not exist.\r\n",
            ),
            (
                Outcome::Temporary("backend is busy".into()),
                "451 4.4.3 Temporary error: backend is busy\r\n",
            ),
            (
                Outcome::Permanent("mailbox is closed".into()),
                "550 5.1.3 Permanent error: mailbox is closed\r\n",
            ),
        ] {
            let (mut session, out, _) = session_ready(outcome.clone(), 5).await;
            session
                .handle_rcpt_to(rcpt_to("a@example.com"))
                .await
                .unwrap();

            assert_eq!(out.take(), expected, "outcome={outcome:?}");
            assert!(session.data.rcpt_to.is_empty());
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::RecipientValidationFailed(_))
            ));
        }
    }

    /// Resolver-supplied text is truncated so that it can't overflow the reply buffer
    #[tokio::test]
    async fn test_rcpt_to_resolver_error_is_truncated() {
        let (mut session, out, _) = session_ready(Outcome::Temporary("x".repeat(1000)), 5).await;
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();

        let reply = out.take();
        assert!(
            reply.len() <= MAX_REPLY_LEN,
            "reply is {} bytes",
            reply.len()
        );
        assert!(reply.ends_with("\r\n"));
        assert_eq!(
            reply,
            format!(
                "451 4.4.3 Temporary error: {}\r\n",
                "x".repeat(MAX_REPLY_LEN - 32)
            )
        );
    }

    /// Truncation happens on a char boundary, not a byte one
    #[tokio::test]
    async fn test_rcpt_to_resolver_error_truncated_on_char_boundary() {
        let (mut session, out, _) = session_ready(Outcome::Permanent("€".repeat(500)), 5).await;
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();

        // 224 bytes hold 74 whole 3-byte chars, the 75th would be cut in half
        assert_eq!(
            out.take(),
            format!("550 5.1.3 Permanent error: {}\r\n", "€".repeat(74))
        );
    }

    #[tokio::test]
    async fn test_rcpt_to_rewrite_replaces_the_recipient() {
        let (mut session, out, _) =
            session_ready(Outcome::Rewrite("new@example.com".try_into().unwrap()), 5).await;
        session
            .handle_rcpt_to(rcpt_to("old@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(
            session
                .data
                .rcpt_to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["new@example.com"]
        );
    }

    /// `Expand` keeps the original recipient and appends the extra ones,
    /// which can push the list past `max_recipients`
    #[tokio::test]
    async fn test_rcpt_to_expand_can_exceed_max_recipients() {
        let (mut session, out, _) = session_ready(
            Outcome::Expand(vec![
                "b@example.com".try_into().unwrap(),
                "c@example.com".try_into().unwrap(),
            ]),
            1,
        )
        .await;
        session
            .handle_rcpt_to(rcpt_to("list@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(
            session
                .data
                .rcpt_to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["list@example.com", "b@example.com", "c@example.com"]
        );
    }

    /// Parses a raw command line into the `RcptTo` the handler receives
    fn parse_rcpt(line: &str) -> RcptTo<Cow<'_, str>> {
        let mut iter = line.as_bytes().iter();
        match smtp_proto::Request::parse(&mut iter) {
            Ok(smtp_proto::Request::Rcpt { to }) => to,
            _ => panic!("{line:?} must parse as RCPT TO"),
        }
    }

    fn recipients(session: &Session<Capture>) -> Vec<String> {
        session
            .data
            .rcpt_to
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The null forward path is not a thing - `RCPT TO:<>` parses into an empty
    /// address and is refused
    #[tokio::test]
    async fn test_rcpt_to_null_forward_path_is_rejected() {
        let to = parse_rcpt("RCPT TO:<>\r\n");
        assert_eq!(to.address, "");

        let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
        session.handle_rcpt_to(to).await.unwrap();

        assert_eq!(out.take(), "550 5.1.2 Incorrect address.\r\n");
        assert!(session.data.rcpt_to.is_empty());
        assert_eq!(resolver.calls(), 0);
    }

    /// Control characters, non-ASCII mailboxes & RFC 5321 address literals are all
    /// refused, a bare IP as the domain is not
    #[tokio::test]
    async fn test_rcpt_to_address_edge_cases() {
        for (address, expected) in [
            ("a\rb@example.com", "550 5.1.2 Incorrect address.\r\n"),
            ("a\nb@example.com", "550 5.1.2 Incorrect address.\r\n"),
            ("üser@example.com", "550 5.1.2 Incorrect address.\r\n"),
            ("a@[1.2.3.4]", "550 5.1.2 Incorrect address.\r\n"),
            ("a@example.com..", "550 5.1.2 Incorrect address.\r\n"),
            ("a@1.2.3.4", "250 2.1.5 OK\r\n"),
            // Single-label domains are fine for a recipient, unlike for a sender
            ("a@localhost", "250 2.1.5 OK\r\n"),
            // The rightmost @ is the separator
            ("a@b@example.com", "250 2.1.5 OK\r\n"),
        ] {
            let (mut session, out, _) = session_ready(Outcome::Accept, 5).await;
            session.handle_rcpt_to(rcpt_to(address)).await.unwrap();
            assert_eq!(out.take(), expected, "address={address:?}");
        }
    }

    /// There's no length cap on the recipient, and a huge one must not overflow
    /// the fixed-size reply buffer
    #[tokio::test]
    async fn test_rcpt_to_oversized_address_is_accepted() {
        let address = format!("{}@{}com", "l".repeat(1000), "xxxxxxxxx.".repeat(26));
        assert!(address.len() > MAX_REPLY_LEN);

        let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
        session.handle_rcpt_to(rcpt_to(&address)).await.unwrap();

        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(resolver.calls(), 1);
        assert_eq!(session.data.rcpt_to.len(), 1);
    }

    /// The DSN check runs before the address is even parsed
    #[tokio::test]
    async fn test_rcpt_to_dsn_check_precedes_address_validation() {
        let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
        let mut to = rcpt_to("this-is-not-an-address");
        to.flags = RCPT_NOTIFY_NEVER;

        session.handle_rcpt_to(to).await.unwrap();
        assert_eq!(out.take(), "501 5.5.4 DSN extension is not supported.\r\n");
        assert_eq!(resolver.calls(), 0);
        // Unsupported extensions aren't counted as protocol errors
        assert_eq!(session.counters.errors, 0);
    }

    /// ...and the missing MAIL FROM beats even that
    #[tokio::test]
    async fn test_rcpt_to_sequence_check_precedes_dsn() {
        let (mut session, out) = session_with_ehlo(test_config());
        let mut to = rcpt_to("a@example.com");
        to.flags = RCPT_NOTIFY_SUCCESS;

        session.handle_rcpt_to(to).await.unwrap();
        assert_eq!(out.take(), "503 5.5.1 MAIL FROM is required first.\r\n");
    }

    /// The DSN parameters as they actually arrive off the wire
    #[tokio::test]
    async fn test_rcpt_to_dsn_parameters_from_the_wire() {
        for line in [
            "RCPT TO:<a@example.com> NOTIFY=SUCCESS,FAILURE\r\n",
            "RCPT TO:<a@example.com> NOTIFY=NEVER\r\n",
            "RCPT TO:<a@example.com> ORCPT=rfc822;b@example.com\r\n",
        ] {
            let (mut session, out, resolver) = session_ready(Outcome::Accept, 5).await;
            session.handle_rcpt_to(parse_rcpt(line)).await.unwrap();

            assert_eq!(
                out.take(),
                "501 5.5.4 DSN extension is not supported.\r\n",
                "line={line:?}"
            );
            assert_eq!(resolver.calls(), 0);
        }

        // Unknown parameters don't even parse, so the handler never sees them
        let mut iter = "RCPT TO:<a@example.com> FOO=BAR\r\n".as_bytes().iter();
        assert!(smtp_proto::Request::parse(&mut iter).is_err());

        // A plain RCPT TO goes through
        let (mut session, out, _) = session_ready(Outcome::Accept, 5).await;
        session
            .handle_rcpt_to(parse_rcpt("RCPT TO:<a@example.com>\r\n"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
    }

    /// `Rewrite` pushes the new address without re-checking for duplicates, so the
    /// same target can end up in the list twice.
    ///
    /// NOTE: documents the current behaviour. Two aliases resolving to one mailbox
    /// therefore yield two entries (and, depending on the delivery agent, two
    /// copies) - if the duplicate check ever moves after the resolution, update
    /// this expectation.
    #[tokio::test]
    async fn test_rcpt_to_rewrite_bypasses_the_duplicate_check() {
        let (mut session, out, resolver) =
            session_ready(Outcome::Rewrite("new@example.com".try_into().unwrap()), 5).await;

        for address in ["a@example.com", "b@example.com"] {
            session.handle_rcpt_to(rcpt_to(address)).await.unwrap();
            assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        }

        assert_eq!(resolver.calls(), 2);
        assert_eq!(recipients(&session), ["new@example.com", "new@example.com"]);

        // The dedup check looks at the *rewritten* list, so repeating the original
        // address still reaches the resolver
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(resolver.calls(), 3);
        assert_eq!(session.data.rcpt_to.len(), 3);
    }

    /// An empty expansion list leaves just the original recipient
    #[tokio::test]
    async fn test_rcpt_to_expand_with_an_empty_list() {
        let (mut session, out, _) = session_ready(Outcome::Expand(vec![]), 5).await;
        session
            .handle_rcpt_to(rcpt_to("list@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(recipients(&session), ["list@example.com"]);
    }

    /// Expanded addresses count towards the limit for every *later* recipient
    #[tokio::test]
    async fn test_rcpt_to_expanded_addresses_count_towards_the_limit() {
        let (mut session, out, resolver) = session_ready(
            Outcome::Expand(vec![
                "b@example.com".try_into().unwrap(),
                "c@example.com".try_into().unwrap(),
            ]),
            3,
        )
        .await;

        session
            .handle_rcpt_to(rcpt_to("list@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(session.data.rcpt_to.len(), 3);

        session
            .handle_rcpt_to(rcpt_to("d@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "455 4.5.3 Too many recipients.\r\n");
        assert_eq!(resolver.calls(), 1);
        assert!(matches!(
            session.data.last_error,
            Some(ProtocolError::RecipientValidationFailed(ref v))
                if v == "Too many recipients: 3 > 3"
        ));

        // An address that the expansion already added is a duplicate, so it's
        // accepted even though the list is full
        session
            .handle_rcpt_to(rcpt_to("c@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(session.data.rcpt_to.len(), 3);
        assert_eq!(resolver.calls(), 1);
    }

    /// `MAX_REPLY_LEN - 32` bytes of resolver text still fit verbatim
    #[tokio::test]
    async fn test_rcpt_to_resolver_error_truncation_boundary() {
        let limit = MAX_REPLY_LEN - 32;

        for (len, expected_len) in [(limit - 1, limit - 1), (limit, limit), (limit + 1, limit)] {
            let (mut session, out, _) = session_ready(Outcome::Temporary("x".repeat(len)), 5).await;
            session
                .handle_rcpt_to(rcpt_to("a@example.com"))
                .await
                .unwrap();

            let reply = out.take();
            assert_eq!(
                reply,
                format!(
                    "451 4.4.3 Temporary error: {}\r\n",
                    "x".repeat(expected_len)
                ),
                "len={len}"
            );
            assert!(reply.len() <= MAX_REPLY_LEN, "len={len}");
        }
    }

    /// The resolver's message is passed through to the client verbatim - it is only
    /// length-clamped, never escaped.
    ///
    /// NOTE: documents the current behaviour. The text comes from the locally
    /// configured `ResolvesRecipient`, so a control character in it is an operator
    /// problem rather than a remote one - but if the reply text ever gets
    /// sanitised, update this expectation.
    #[tokio::test]
    async fn test_rcpt_to_resolver_error_text_is_passed_through_verbatim() {
        let (mut session, out, _) =
            session_ready(Outcome::Permanent("boom\r\n250 hacked".into()), 5).await;
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();

        // NOTE: documents the current behaviour - the CRLF goes straight through.
        // If the reply text ever gets sanitised, update this expectation.
        assert_eq!(
            out.take(),
            "550 5.1.3 Permanent error: boom\r\n250 hacked\r\n"
        );
    }

    /// The recipient list survives a rejected recipient untouched
    #[tokio::test]
    async fn test_rcpt_to_rejection_does_not_disturb_the_list() {
        let (mut session, out, _) = session_ready(Outcome::Accept, 5).await;
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");

        // Swap the resolver for a rejecting one & try another recipient
        let mut cfg = test_config();
        cfg.max_recipients = 5;
        cfg.recipient_resolver = StubRecipientResolver::new(Outcome::UnknownRecipient);
        session.cfg = Arc::new(cfg);

        session
            .handle_rcpt_to(rcpt_to("b@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "550 5.1.2 Mailbox does not exist.\r\n");
        assert_eq!(recipients(&session), ["a@example.com"]);
    }

    /// Resolver that accepts everyone but caps how much each recipient can take.
    #[derive(Debug)]
    struct SizeLimitedResolver {
        limits: Vec<(String, Option<usize>)>,
        size_calls: AtomicUsize,
    }

    impl SizeLimitedResolver {
        fn new(limits: &[(&str, Option<usize>)]) -> Arc<Self> {
            Arc::new(Self {
                limits: limits.iter().map(|(a, l)| ((*a).to_string(), *l)).collect(),
                size_calls: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait]
    impl ResolvesRecipient for SizeLimitedResolver {
        async fn resolve_recipient(
            &self,
            _from: &EmailAddress,
            _rcpt: &EmailAddress,
        ) -> Result<RecipientPolicy, RecipientResolveError> {
            Ok(RecipientPolicy::Accept)
        }

        async fn recipient_max_message_size(&self, rcpt: &EmailAddress) -> Option<usize> {
            self.size_calls.fetch_add(1, Ordering::SeqCst);
            self.limits
                .iter()
                .find(|(a, _)| *a == rcpt.to_string())
                .and_then(|(_, l)| *l)
        }
    }

    async fn session_with_declared_size(
        resolver: Arc<SizeLimitedResolver>,
        size: usize,
    ) -> (Session<Capture>, Capture) {
        let mut cfg = test_config();
        cfg.max_recipients = 10;
        cfg.recipient_resolver = resolver;

        let (mut session, out) = session_with_ehlo(cfg);

        let mut from = mail_from("sender@example.com");
        from.size = size;
        session.handle_mail_from(from).await.unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");

        (session, out)
    }

    /// A recipient whose backend cannot take the declared size is refused with
    /// 552 - and only that recipient. The rest of the transaction proceeds, which
    /// is exactly what RFC 1870 provides a per-recipient 552 for.
    #[tokio::test]
    async fn test_rcpt_to_per_recipient_size_limit() {
        let resolver = SizeLimitedResolver::new(&[
            ("small@example.com", Some(100)),
            ("big@example.com", Some(500)),
            ("unknown@example.com", None),
        ]);
        let (mut session, out) = session_with_declared_size(resolver.clone(), 300).await;

        // Too big for this one
        session
            .handle_rcpt_to(rcpt_to("small@example.com"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            "552 5.3.4 Recipient accepts at most 100 bytes.\r\n"
        );
        assert!(session.data.rcpt_to.is_empty());
        assert!(matches!(
            session.data.last_error,
            Some(ProtocolError::MessageTooBig(_))
        ));

        // Fine for this one
        session
            .handle_rcpt_to(rcpt_to("big@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");

        // Unknown limit means nothing is enforced
        session
            .handle_rcpt_to(rcpt_to("unknown@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");

        assert_eq!(
            session
                .data
                .rcpt_to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["big@example.com", "unknown@example.com"]
        );
    }

    /// Without a declared SIZE there is nothing to compare against, so the hook
    /// must not even be consulted.
    #[tokio::test]
    async fn test_rcpt_to_size_limit_not_checked_without_declared_size() {
        let resolver = SizeLimitedResolver::new(&[("small@example.com", Some(1))]);
        let (mut session, out) = session_with_declared_size(resolver.clone(), 0).await;

        session
            .handle_rcpt_to(rcpt_to("small@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.5 OK\r\n");
        assert_eq!(resolver.size_calls.load(Ordering::SeqCst), 0);
        assert_eq!(session.data.rcpt_to.len(), 1);
    }

    /// Exactly at the limit is accepted.
    #[tokio::test]
    async fn test_rcpt_to_size_limit_boundary() {
        let resolver = SizeLimitedResolver::new(&[("a@example.com", Some(200))]);
        let (mut session, out) = session_with_declared_size(resolver.clone(), 200).await;

        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.5 OK\r\n");

        let (mut session, out) = session_with_declared_size(resolver, 201).await;
        session
            .handle_rcpt_to(rcpt_to("a@example.com"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            "552 5.3.4 Recipient accepts at most 200 bytes.\r\n"
        );
    }
}
