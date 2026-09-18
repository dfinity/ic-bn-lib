use std::{
    fmt::{Debug, Display},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use fqdn::FQDN;
use itertools::Itertools;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, Registry, register_histogram_vec_with_registry,
    register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
};
use serde_with::SerializeDisplay;
use strum::{Display, IntoStaticStr};
use tracing::warn;
use uuid::Uuid;

use crate::{
    network::TlsInfo,
    smtp::{address::EmailAddress, inbound::SessionError},
};

pub mod address;
pub mod cli;
pub mod ic;
pub mod inbound;
pub mod server;

/// Recipient resolution policy
#[derive(Debug, Clone, Eq, PartialEq, Display, SerializeDisplay)]
pub enum RecipientPolicy {
    #[strum(to_string = "Accept")]
    Accept,
    #[strum(to_string = "Rewrite({0})")]
    Rewrite(EmailAddress),
    #[strum(to_string = "Expand({0:?})")]
    Expand(Vec<EmailAddress>),
}

/// Recipient resolution error
#[derive(thiserror::Error, Debug, IntoStaticStr, SerializeDisplay)]
#[strum(serialize_all = "snake_case")]
pub enum RecipientResolveError {
    #[error("Unknown recipient")]
    UnknownRecipient,
    #[error("Unknown domain")]
    UnknownDomain,
    #[error("{0}")]
    Temporary(String),
    #[error("{0}")]
    Permanent(String),
}

/// Delivery error
#[derive(thiserror::Error, Clone, Debug, IntoStaticStr, SerializeDisplay)]
#[strum(serialize_all = "snake_case")]
pub enum DeliveryError {
    #[error("{0}")]
    Temporary(String),
    #[error("{0}")]
    Permanent(String),
}

/// Error that might happen during message validation or delivery
#[derive(thiserror::Error, Clone, Debug, IntoStaticStr, SerializeDisplay)]
#[strum(serialize_all = "snake_case")]
pub enum MessageError {
    #[error("Delivery failed: {0}")]
    DeliveryFailed(#[from] DeliveryError),
    #[error("Parsing failed")]
    ParsingFailed,
    #[error("Too many 'Received' headers")]
    TooManyReceivedHeaders,
    #[error("DKIM validation failed: {0}")]
    DkimValidationFailed(String),
}

/// Error that might happen during SMTP exchange
#[derive(thiserror::Error, Clone, Debug, IntoStaticStr, SerializeDisplay)]
#[strum(serialize_all = "snake_case")]
pub enum ProtocolError {
    #[error("Invalid EHLO hostname: {0}")]
    InvalidEhloHostname(String),
    #[error("Invalid command sequence: {0}")]
    InvalidSequenceOfCommands(String),
    #[error("Sender validation failed: {0}")]
    SenderValidationFailed(String),
    #[error("Recipient validation failed: {0}")]
    RecipientValidationFailed(String),
    #[error("Reverse IP validation failed: {0}")]
    ReverseIpValidationFailed(String),
    #[error("SPF validation failed: {0}")]
    SpfValidationFailed(String),
    #[error("Message too big: {0}")]
    MessageTooBig(String),
    #[error("SMTP protocol error: {0}")]
    SmtpError(String),
}

/// Low-level E-Mail representation
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct EmailMessage {
    pub id: Uuid,
    pub mail_from: EmailAddress,
    pub rcpt_to: Vec<EmailAddress>,
    pub body: Bytes,
}

impl Display for EmailMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "id: {}, from: {}, to: {}, msg: {}",
            self.id,
            self.mail_from,
            self.rcpt_to.iter().map(|x| x.to_string()).join(", "),
            String::from_utf8_lossy(&self.body)
                .replace('\n', "\\n")
                .replace('\r', "\\r")
        )
    }
}

/// Looks up the given recipient & applies `RecipientPolicy` policy
#[async_trait]
pub trait ResolvesRecipient: Send + Sync + Debug {
    async fn resolve_recipient(
        &self,
        from: &EmailAddress,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError>;
}

/// Gets notifications about events
#[async_trait]
pub trait ReceivesSmtpNotifications: Send + Sync + Debug {
    /// Notify when the message is queued or the validation failed
    async fn notify_message(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
        latency: Duration,
        error: Option<MessageError>,
    );
    /// Notify when the protocol error happens
    async fn notify_protocol_error(&self, meta: SessionMeta, error: ProtocolError);
    /// Notify when the session is finished
    async fn notify_session_finish(&self, meta: SessionMeta, error: Option<SessionError>);
}

/// Delivers the E-Mail message
#[async_trait]
pub trait DeliversMail: Send + Sync + Debug {
    async fn deliver_mail(
        &self,
        meta: SessionMeta,
        message: Arc<EmailMessage>,
    ) -> Result<(), DeliveryError>;
}

/// SMTP session counters
#[derive(Clone, Debug)]
pub struct SessionCounters {
    pub started: Instant,
    pub bytes_rx: usize,
    pub bytes_tx: usize,
    pub commands: usize,
    pub messages_queued: usize,
    pub errors: usize,
}

impl SessionCounters {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes_rx: 0,
            bytes_tx: 0,
            commands: 0,
            messages_queued: 0,
            errors: 0,
        }
    }
}

/// Session metadata for logging/notification purposes
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub id: Uuid,
    pub message_id: Uuid,
    pub remote_ip: IpAddr,
    pub tls_info: Option<TlsInfo>,
    pub counters: SessionCounters,
    pub last_error: Option<ProtocolError>,
    pub ehlo_hostname: Option<FQDN>,
    pub mail_from: Option<EmailAddress>,
    pub rcpt_to: Vec<EmailAddress>,
}

#[derive(Clone)]
pub struct Metrics {
    bytes_rx: IntCounterVec,
    bytes_tx: IntCounterVec,
    commands: IntCounterVec,
    replies: IntCounterVec,
    messages: IntCounterVec,
    protocol_errors: IntCounterVec,
    sessions_open: IntGaugeVec,
    sessions_processed: IntCounterVec,
    session_duration: HistogramVec,
    message_size: HistogramVec,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        const LABELS: &[&str] = &["ip_family", "tls_proto"];

        Self {
            bytes_rx: register_int_counter_vec_with_registry!(
                format!("smtp_bytes_rx"),
                format!("Number of bytes received"),
                LABELS,
                registry
            )
            .unwrap(),

            bytes_tx: register_int_counter_vec_with_registry!(
                format!("smtp_bytes_tx"),
                format!("Number of bytes sent"),
                LABELS,
                registry
            )
            .unwrap(),

            commands: register_int_counter_vec_with_registry!(
                format!("smtp_commands"),
                format!("Number of SMTP commands received"),
                &[LABELS[0], LABELS[1], "command"],
                registry
            )
            .unwrap(),

            replies: register_int_counter_vec_with_registry!(
                format!("smtp_replies"),
                format!("Number of SMTP replies sent"),
                &[LABELS[0], LABELS[1], "code", "ext"],
                registry
            )
            .unwrap(),

            messages: register_int_counter_vec_with_registry!(
                format!("smtp_messages"),
                format!("Number of SMTP messages submitted"),
                &[LABELS[0], LABELS[1], "error"],
                registry
            )
            .unwrap(),

            message_size: register_histogram_vec_with_registry!(
                format!("smtp_message_size"),
                format!("Size of the SMTP messages in bytes"),
                LABELS,
                vec![1024.0, 16384.0, 131072.0, 524288.0, 2097152.0],
                registry
            )
            .unwrap(),

            protocol_errors: register_int_counter_vec_with_registry!(
                format!("smtp_protocol_errors"),
                format!("Number of SMTP protocol errors"),
                &[LABELS[0], LABELS[1], "error"],
                registry
            )
            .unwrap(),

            sessions_open: register_int_gauge_vec_with_registry!(
                format!("smtp_sessions_open"),
                format!("Number of SMTP sessions currently open"),
                &[LABELS[0]],
                registry
            )
            .unwrap(),

            sessions_processed: register_int_counter_vec_with_registry!(
                format!("smtp_sessions_processed"),
                format!("Number of SMTP sessions processed"),
                &[LABELS[0], LABELS[1], "error"],
                registry
            )
            .unwrap(),

            session_duration: register_histogram_vec_with_registry!(
                format!("smtp_session_duration"),
                format!("Time in seconds that the session was open"),
                LABELS,
                vec![5.0, 10.0, 30.0, 60.0, 120.0],
                registry
            )
            .unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct DummyRecipientResolver;

#[async_trait]
impl ResolvesRecipient for DummyRecipientResolver {
    async fn resolve_recipient(
        &self,
        from: &EmailAddress,
        rcpt: &EmailAddress,
    ) -> Result<RecipientPolicy, RecipientResolveError> {
        warn!("DummyRecipientResolver: from: {from}, to: {rcpt}");
        Ok(RecipientPolicy::Accept)
    }
}

#[derive(Debug)]
pub struct DummyDeliveryAgent;

#[async_trait]
impl DeliversMail for DummyDeliveryAgent {
    async fn deliver_mail(
        &self,
        _meta: SessionMeta,
        message: Arc<EmailMessage>,
    ) -> Result<(), DeliveryError> {
        warn!("DummyDeliveryAgent: {message}");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use prometheus::Registry;

    use super::*;
    use crate::email;

    fn message(body: &'static [u8]) -> EmailMessage {
        EmailMessage {
            id: Uuid::nil(),
            mail_from: email!("john@doe.com"),
            rcpt_to: vec![email!("a@b.com"), email!("c@d.com")],
            body: Bytes::from_static(body),
        }
    }

    #[test]
    fn test_recipient_policy_display() {
        assert_eq!(RecipientPolicy::Accept.to_string(), "Accept");
        assert_eq!(
            RecipientPolicy::Rewrite(email!("foo@bar.com")).to_string(),
            "Rewrite(foo@bar.com)"
        );
        assert_eq!(
            RecipientPolicy::Expand(vec![]).to_string(),
            "Expand([])",
            "empty expansion"
        );
        assert_eq!(
            RecipientPolicy::Expand(vec![email!("a@b.com"), email!("c@d.com")]).to_string(),
            "Expand([a@b.com, c@d.com])"
        );
    }

    #[test]
    fn test_recipient_policy_eq_and_serde() {
        assert_eq!(RecipientPolicy::Accept, RecipientPolicy::Accept);
        assert_ne!(
            RecipientPolicy::Accept,
            RecipientPolicy::Rewrite(email!("a@b.com"))
        );
        assert_ne!(
            RecipientPolicy::Rewrite(email!("a@b.com")),
            RecipientPolicy::Rewrite(email!("a@b.org"))
        );
        assert_ne!(
            RecipientPolicy::Expand(vec![email!("a@b.com")]),
            RecipientPolicy::Expand(vec![email!("a@b.com"), email!("c@d.com")])
        );

        // Serialized through Display
        assert_eq!(
            serde_json::to_string(&RecipientPolicy::Accept).unwrap(),
            r#""Accept""#
        );
        assert_eq!(
            serde_json::to_string(&RecipientPolicy::Rewrite(email!("foo@bar.com"))).unwrap(),
            r#""Rewrite(foo@bar.com)""#
        );
    }

    #[test]
    fn test_recipient_resolve_error() {
        let cases: [(RecipientResolveError, &str, &str); 4] = [
            (
                RecipientResolveError::UnknownRecipient,
                "Unknown recipient",
                "unknown_recipient",
            ),
            (
                RecipientResolveError::UnknownDomain,
                "Unknown domain",
                "unknown_domain",
            ),
            (
                RecipientResolveError::Temporary("db is down".into()),
                "db is down",
                "temporary",
            ),
            (
                RecipientResolveError::Permanent("no such mailbox".into()),
                "no such mailbox",
                "permanent",
            ),
        ];

        for (err, display, label) in cases {
            assert_eq!(err.to_string(), display);
            assert_eq!(
                serde_json::to_string(&err).unwrap(),
                format!("\"{display}\"")
            );
            let static_str: &'static str = (&err).into();
            assert_eq!(static_str, label);
        }
    }

    #[test]
    fn test_delivery_error() {
        let cases: [(DeliveryError, &str, &str); 2] = [
            (
                DeliveryError::Temporary("canister is busy".into()),
                "canister is busy",
                "temporary",
            ),
            (
                DeliveryError::Permanent("rejected".into()),
                "rejected",
                "permanent",
            ),
        ];

        for (err, display, label) in cases {
            assert_eq!(err.to_string(), display);
            assert_eq!(
                serde_json::to_string(&err).unwrap(),
                format!("\"{display}\"")
            );
            let static_str: &'static str = (&err).into();
            assert_eq!(static_str, label);
            // Errors are cloneable so they can be handed to notification handlers
            assert_eq!(err.clone().to_string(), display);
        }

        // Empty message still renders as an empty string
        assert_eq!(DeliveryError::Temporary(String::new()).to_string(), "");
    }

    #[test]
    fn test_message_error() {
        let cases: [(MessageError, &str, &str); 5] = [
            (
                MessageError::DeliveryFailed(DeliveryError::Temporary("busy".into())),
                "Delivery failed: busy",
                "delivery_failed",
            ),
            (
                MessageError::DeliveryFailed(DeliveryError::Permanent("nope".into())),
                "Delivery failed: nope",
                "delivery_failed",
            ),
            (
                MessageError::ParsingFailed,
                "Parsing failed",
                "parsing_failed",
            ),
            (
                MessageError::TooManyReceivedHeaders,
                "Too many 'Received' headers",
                "too_many_received_headers",
            ),
            (
                MessageError::DkimValidationFailed("bad signature".into()),
                "DKIM validation failed: bad signature",
                "dkim_validation_failed",
            ),
        ];

        for (err, display, label) in cases {
            assert_eq!(err.to_string(), display);
            assert_eq!(
                serde_json::to_string(&err).unwrap(),
                format!("\"{display}\"")
            );
            let static_str: &'static str = (&err).into();
            assert_eq!(static_str, label);
        }
    }

    #[test]
    fn test_message_error_from_delivery_error() {
        // `?` on a `DeliveryError` must produce a `DeliveryFailed`
        let err: MessageError = DeliveryError::Permanent("gone".into()).into();
        assert!(matches!(
            err,
            MessageError::DeliveryFailed(DeliveryError::Permanent(ref s)) if s == "gone"
        ));
        assert_eq!(err.to_string(), "Delivery failed: gone");
        // ...and the source chain must be preserved
        assert_eq!(std::error::Error::source(&err).unwrap().to_string(), "gone");
        assert!(std::error::Error::source(&MessageError::ParsingFailed).is_none());
    }

    #[test]
    fn test_protocol_error() {
        let cases: [(ProtocolError, &str, &str); 8] = [
            (
                ProtocolError::InvalidEhloHostname("foo".into()),
                "Invalid EHLO hostname: foo",
                "invalid_ehlo_hostname",
            ),
            (
                ProtocolError::InvalidSequenceOfCommands("DATA".into()),
                "Invalid command sequence: DATA",
                "invalid_sequence_of_commands",
            ),
            (
                ProtocolError::SenderValidationFailed("spf".into()),
                "Sender validation failed: spf",
                "sender_validation_failed",
            ),
            (
                ProtocolError::RecipientValidationFailed("unknown".into()),
                "Recipient validation failed: unknown",
                "recipient_validation_failed",
            ),
            (
                ProtocolError::ReverseIpValidationFailed("no ptr".into()),
                "Reverse IP validation failed: no ptr",
                "reverse_ip_validation_failed",
            ),
            (
                ProtocolError::SpfValidationFailed("fail".into()),
                "SPF validation failed: fail",
                "spf_validation_failed",
            ),
            (
                ProtocolError::MessageTooBig("1234".into()),
                "Message too big: 1234",
                "message_too_big",
            ),
            (
                ProtocolError::SmtpError("syntax".into()),
                "SMTP protocol error: syntax",
                "smtp_error",
            ),
        ];

        for (err, display, label) in cases {
            assert_eq!(err.to_string(), display);
            assert_eq!(
                serde_json::to_string(&err).unwrap(),
                format!("\"{display}\"")
            );
            let static_str: &'static str = (&err).into();
            assert_eq!(static_str, label);
        }
    }

    #[test]
    fn test_email_message_display_escapes_newlines() {
        let msg = message(b"Subject: hi\r\n\r\nbody\n");
        assert_eq!(
            msg.to_string(),
            "id: 00000000-0000-0000-0000-000000000000, from: john@doe.com, \
             to: a@b.com, c@d.com, msg: Subject: hi\\r\\n\\r\\nbody\\n"
        );
    }

    #[test]
    fn test_email_message_display_edge_cases() {
        // No recipients
        let msg = EmailMessage {
            id: Uuid::nil(),
            mail_from: email!("john@doe.com"),
            rcpt_to: vec![],
            body: Bytes::new(),
        };
        assert_eq!(
            msg.to_string(),
            "id: 00000000-0000-0000-0000-000000000000, from: john@doe.com, to: , msg: "
        );

        // Single recipient - no separator
        let msg = EmailMessage {
            rcpt_to: vec![email!("only@one.com")],
            ..message(b"x")
        };
        assert!(msg.to_string().ends_with("to: only@one.com, msg: x"));

        // Invalid UTF-8 is replaced rather than panicking
        let msg = EmailMessage {
            body: Bytes::from_static(&[0xff, 0xfe]),
            ..message(b"")
        };
        assert!(msg.to_string().ends_with("msg: \u{fffd}\u{fffd}"));
    }

    #[test]
    fn test_email_message_eq_hash() {
        let a = message(b"body");
        let b = message(b"body");
        assert_eq!(a, b);

        let c = EmailMessage {
            body: Bytes::from_static(b"other"),
            ..message(b"body")
        };
        assert_ne!(a, c);

        let d = EmailMessage {
            id: Uuid::from_u128(1),
            ..message(b"body")
        };
        assert_ne!(a, d);

        let set = HashSet::from([a, b, c, d]);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn test_session_counters_new() {
        let c = SessionCounters::new();
        assert_eq!(c.bytes_rx, 0);
        assert_eq!(c.bytes_tx, 0);
        assert_eq!(c.commands, 0);
        assert_eq!(c.messages_queued, 0);
        assert_eq!(c.errors, 0);
        assert!(c.started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_metrics() {
        let registry = Registry::new();
        let m = Metrics::new(&registry);

        // Touching every metric also asserts the label cardinality,
        // since `with_label_values` panics on a mismatch.
        m.bytes_rx.with_label_values(&["v4", "TLSv1.3"]).inc_by(10);
        m.bytes_tx.with_label_values(&["v4", "TLSv1.3"]).inc_by(20);
        m.commands.with_label_values(&["v4", "", "EHLO"]).inc();
        m.replies
            .with_label_values(&["v4", "", "250", "2.0.0"])
            .inc();
        m.messages.with_label_values(&["v4", "", ""]).inc();
        m.protocol_errors
            .with_label_values(&["v6", "", "smtp_error"])
            .inc();
        m.sessions_open.with_label_values(&["v6"]).set(3);
        m.sessions_processed
            .with_label_values(&["v6", "", "quit"])
            .inc();
        m.session_duration
            .with_label_values(&["v4", ""])
            .observe(1.0);
        m.message_size.with_label_values(&["v4", ""]).observe(100.0);

        let families = registry.gather();
        let mut names = families.iter().map(|x| x.name()).collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "smtp_bytes_rx",
                "smtp_bytes_tx",
                "smtp_commands",
                "smtp_message_size",
                "smtp_messages",
                "smtp_protocol_errors",
                "smtp_replies",
                "smtp_session_duration",
                "smtp_sessions_open",
                "smtp_sessions_processed",
            ]
        );

        let family = |name: &str| {
            families
                .iter()
                .find(|x| x.name() == name)
                .unwrap_or_else(|| panic!("{name} not registered"))
        };

        // Values & label names make it through
        let f = family("smtp_bytes_rx");
        assert_eq!(f.help(), "Number of bytes received");
        assert_eq!(f.get_metric().len(), 1);
        assert_eq!(f.get_metric()[0].get_counter().value, Some(10.0));
        let labels = f.get_metric()[0]
            .get_label()
            .iter()
            .map(|x| (x.name(), x.value()))
            .collect::<Vec<_>>();
        assert_eq!(labels, vec![("ip_family", "v4"), ("tls_proto", "TLSv1.3")]);

        assert_eq!(
            family("smtp_bytes_tx").get_metric()[0].get_counter().value,
            Some(20.0)
        );
        assert_eq!(
            family("smtp_sessions_open").get_metric()[0]
                .get_gauge()
                .value,
            Some(3.0)
        );

        // Extra labels on the more detailed metrics
        let mut labels = family("smtp_replies").get_metric()[0]
            .get_label()
            .iter()
            .map(|x| x.name())
            .collect::<Vec<_>>();
        labels.sort_unstable();
        assert_eq!(labels, vec!["code", "ext", "ip_family", "tls_proto"]);

        let mut labels = family("smtp_sessions_open").get_metric()[0]
            .get_label()
            .iter()
            .map(|x| x.name())
            .collect::<Vec<_>>();
        labels.sort_unstable();
        assert_eq!(labels, vec!["ip_family"]);

        // Histograms got their observations & their buckets
        let text = prometheus::TextEncoder::new()
            .encode_to_string(&families)
            .unwrap();
        let line = |prefix: &str| {
            text.lines()
                .find(|x| x.starts_with(prefix))
                .unwrap_or_else(|| panic!("no line starting with {prefix} in:\n{text}"))
                .to_string()
        };

        assert!(line("smtp_message_size_count").ends_with(" 1"));
        assert!(line("smtp_message_size_sum").ends_with(" 100"));
        assert!(line("smtp_session_duration_count").ends_with(" 1"));
        assert!(line("smtp_session_duration_sum").ends_with(" 1"));

        // The buckets defined for the message size
        for le in ["1024", "16384", "131072", "524288", "2097152"] {
            assert!(
                text.lines()
                    .any(|x| x.starts_with("smtp_message_size_bucket")
                        && x.contains(&format!("le=\"{le}\""))),
                "bucket {le} missing from:\n{text}"
            );
        }
        // ...and for the session duration
        for le in ["5", "10", "30", "60", "120"] {
            assert!(
                text.lines()
                    .any(|x| x.starts_with("smtp_session_duration_bucket")
                        && x.contains(&format!("le=\"{le}\""))),
                "bucket {le} missing from:\n{text}"
            );
        }
    }

    #[test]
    fn test_metrics_separate_registries_dont_share_state() {
        // Registering twice into the same registry would panic,
        // but separate registries must work & stay independent.
        let r1 = Registry::new();
        let r2 = Registry::new();
        let m1 = Metrics::new(&r1);
        let m2 = Metrics::new(&r2);

        m1.bytes_rx.with_label_values(&["v4", ""]).inc_by(7);
        m2.bytes_rx.with_label_values(&["v4", ""]).inc_by(1);

        let value = |r: &Registry| {
            r.gather()
                .iter()
                .find(|x| x.name() == "smtp_bytes_rx")
                .expect("smtp_bytes_rx not registered")
                .get_metric()[0]
                .get_counter()
                .value
        };

        assert_eq!(value(&r1), Some(7.0));
        assert_eq!(value(&r2), Some(1.0));
    }

    #[tokio::test]
    async fn test_dummy_recipient_resolver() {
        let r = DummyRecipientResolver;
        assert_eq!(
            r.resolve_recipient(&email!("a@b.com"), &email!("c@d.com"))
                .await
                .unwrap(),
            RecipientPolicy::Accept
        );
        // Accepts anything
        assert_eq!(
            r.resolve_recipient(&email!("@x.com"), &email!("nobody@nowhere.net"))
                .await
                .unwrap(),
            RecipientPolicy::Accept
        );
        assert_eq!(format!("{r:?}"), "DummyRecipientResolver");
    }

    #[tokio::test]
    async fn test_dummy_delivery_agent() {
        let a = DummyDeliveryAgent;
        let meta = SessionMeta {
            id: Uuid::nil(),
            message_id: Uuid::nil(),
            remote_ip: "127.0.0.1".parse().unwrap(),
            tls_info: None,
            counters: SessionCounters::new(),
            last_error: None,
            ehlo_hostname: None,
            mail_from: None,
            rcpt_to: vec![],
        };

        assert!(
            a.deliver_mail(meta, Arc::new(message(b"body")))
                .await
                .is_ok()
        );
        assert_eq!(format!("{a:?}"), "DummyDeliveryAgent");
    }
}
