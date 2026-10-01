use std::{borrow::Cow, fmt::Write as _, net::IpAddr, str::FromStr};

use hickory_proto::rr::{
    Name, RData,
    rdata::{A, AAAA},
};
use hickory_resolver::net::NetError;
use mail_auth::{SpfResult, spf::verify::SpfParameters};
use smtp_proto::{MAIL_BY_NOTIFY, MAIL_BY_RETURN, MailFrom};
use tracing::{debug, info};

use crate::{
    dns::is_error_negative_lookup,
    network::AsyncReadWrite,
    smtp::{
        ProtocolError,
        address::EmailAddress,
        inbound::{Session, SessionResult},
    },
};

impl<S: AsyncReadWrite> Session<S> {
    /// Handles MAIL FROM command
    pub async fn handle_mail_from(&mut self, from: MailFrom<Cow<'_, str>>) -> SessionResult<()> {
        let Some(helo_hostname) = self.data.ehlo_hostname.as_ref().map(|x| x.to_string()) else {
            self.set_error(ProtocolError::InvalidSequenceOfCommands(
                "MAIL FROM before EHLO".into(),
            ));
            return self
                .reply("503", "5.5.1", "Polite people say EHLO first.")
                .await;
        };

        if self.data.mail_from.is_some() {
            self.set_error(ProtocolError::InvalidSequenceOfCommands(
                "Multiple MAIL FROM".into(),
            ));
            return self
                .reply(
                    "503",
                    "5.5.1",
                    "Multiple MAIL FROM commands are not allowed.",
                )
                .await;
        }

        if self.cfg.tls_mode.required() && self.tls_info.is_none() {
            return self
                .reply(
                    "503",
                    "5.5.1",
                    "TLS is required to submit mail on this server.",
                )
                .await;
        }

        if (from.flags & (MAIL_BY_NOTIFY | MAIL_BY_RETURN)) != 0 {
            return self.ext_unsupported("DELIVERBY").await;
        }

        if from.mt_priority != 0 {
            return self.ext_unsupported("MT-PRIORITY").await;
        }

        // Save the size for the per-recipient check in RCPT TO.
        // `0` means "not declared".
        self.data.declared_size = (from.size > 0).then_some(from.size);

        if from.size > self.cfg.max_message_size {
            self.set_error(ProtocolError::MessageTooBig(format!(
                "MAIL FROM-specified size is too big: {} > {}",
                from.size, self.cfg.max_message_size
            )));

            return self.message_too_big().await;
        }

        if from.hold_for != 0 || from.hold_until != 0 {
            return self.ext_unsupported("FUTURERELEASE").await;
        }

        if from.env_id.is_some() {
            return self.ext_unsupported("DSN").await;
        }

        // Validate address
        let Ok(address) = EmailAddress::from_str(&from.address) else {
            info!("{self}: {}: incorrect sender address", from.address);
            self.set_error(ProtocolError::SenderValidationFailed(format!(
                "Incorrect sender address: {}",
                from.address
            )));
            return self
                .reply("550", "5.7.1", "Sender address is incorrect.")
                .await;
        };

        // Validate reverse IP if configured & not yet verified
        if self.cfg.verify_reverse_ip && !self.data.reverse_ip_verified {
            if !self.verify_reverse_ip().await? {
                return Ok(());
            }

            self.data.reverse_ip_verified = true;
            debug!("{self}: reverse IP verification succeeded");
        }

        if self.cfg.verify_sender_domain {
            if address.domain().depth() < 2 {
                info!("{self}: {address}: sender domain verification failed: not FQDN");
                self.set_error(ProtocolError::SenderValidationFailed(format!(
                    "Sender domain is not FQDN: {}",
                    address.domain()
                )));
                return self.reply("550", "5.7.2", "Sender must be an FQDN.").await;
            };

            match self
                .cfg
                .authenticator
                .resolver()
                .mx_lookup(&address.domain().to_string())
                .await
            {
                Ok(v) => {
                    if v.answers().is_empty() {
                        info!(
                            "{self}: {address}: sender domain verification failed: no MX records found"
                        );
                        self.set_error(ProtocolError::SenderValidationFailed(
                            "No MX records found".into(),
                        ));
                        return self
                            .reply(
                                "550",
                                "5.7.25",
                                "No MX record matching your sender domain found.",
                            )
                            .await;
                    }
                }
                Err(e) => {
                    if is_error_negative_lookup(&e) {
                        info!(
                            "{self}: {address}: sender domain verification failed: no MX records found"
                        );
                        self.set_error(ProtocolError::SenderValidationFailed(
                            "No MX records found".into(),
                        ));
                        return self
                            .reply(
                                "550",
                                "5.7.25",
                                "No MX record matching your sender domain found.",
                            )
                            .await;
                    } else {
                        info!(
                            "{self}: {address}: sender domain verification failed: temporary error: {e:#}"
                        );
                        self.set_error(ProtocolError::SenderValidationFailed(format!(
                            "Sender domain verification temporary error: {e:#}",
                        )));
                        return self
                            .reply("451", "4.7.25", "Temporary error validating sender domain.")
                            .await;
                    }
                }
            }

            debug!("{self}: sender domain verification succeeded");
        }

        if self.cfg.verify_spf {
            let output = self
                .cfg
                .authenticator
                .verify_spf(SpfParameters::verify_mail_from(
                    self.remote_ip,
                    &helo_hostname,
                    &self.cfg.hostname,
                    &from.address,
                ))
                .await;

            match output.result() {
                SpfResult::Pass | SpfResult::Neutral | SpfResult::None => {}
                SpfResult::TempError => {
                    info!(
                        "{self}: {address}: SPF validation failed: temporary error: {:?}",
                        output.explanation()
                    );
                    self.set_error(ProtocolError::SpfValidationFailed(format!(
                        "SPF validation temporary error: {:?}",
                        output.explanation()
                    )));
                    return self
                        .reply("451", "4.7.24", "Temporary SPF validation error.")
                        .await;
                }
                SpfResult::Fail | SpfResult::PermError | SpfResult::SoftFail => {
                    info!(
                        "{self}: {address}: SPF validation failed: permanent error: {:?}",
                        output.explanation()
                    );
                    self.set_error(ProtocolError::SpfValidationFailed(format!(
                        "SPF validation permanent error: {:?}",
                        output.explanation()
                    )));
                    return self
                        .reply_with("550", "5.7.23", |buf| {
                            write!(buf, "SPF validation failed")?;
                            if let Some(v) = output.explanation() {
                                write!(buf, ": {v}")?;
                            }
                            Ok(())
                        })
                        .await;
                }
            }

            debug!("{self}: {address}: SPF verification succeeded");
        }

        self.reply("250", "2.1.0", "OK").await?;
        self.data.mail_from = Some(address);

        Ok(())
    }

    /// Replies about failed reverse IP verification
    async fn verify_reverse_ip_reply(&mut self, permanent: bool, msg: &str) -> SessionResult<bool> {
        self.set_error(ProtocolError::ReverseIpValidationFailed(msg.into()));

        // Emit permanent errors only if in strict mode
        if permanent && self.cfg.verify_reverse_ip_strict {
            self.reply_with("550", "5.7.25", |buf| {
                write!(buf, "Reverse DNS validation failed: {msg}")
            })
            .await?;
        } else {
            self.reply_with("451", "4.7.25", |buf| {
                write!(buf, "Temporary error validating reverse DNS: {msg}")
            })
            .await?;
        }

        Ok(false)
    }

    /// Checks if given PTR resolves back to the client's IP
    async fn verify_reverse_ip_ptr(&self, ptr: Name) -> Result<bool, NetError> {
        let remote_ip = self.remote_ip;

        match remote_ip {
            IpAddr::V4(v4) => {
                let lookup = self.cfg.authenticator.resolver().ipv4_lookup(ptr).await?;

                // Check if any of the addresses match the client's
                if lookup.answers().iter().any(|x| x.data == RData::A(A(v4))) {
                    return Ok(true);
                }
            }

            IpAddr::V6(v6) => {
                let lookup = self.cfg.authenticator.resolver().ipv6_lookup(ptr).await?;

                // Check if any of the addresses match the client's
                if lookup
                    .answers()
                    .iter()
                    .any(|x| x.data == RData::AAAA(AAAA(v6)))
                {
                    return Ok(true);
                }
            }
        };

        Ok(false)
    }

    /// Verifies correctness of the client's reverse IP mapping
    async fn verify_reverse_ip(&mut self) -> SessionResult<bool> {
        let remote_ip = self.remote_ip;

        // Get PTR records
        let lookup = match self
            .cfg
            .authenticator
            .resolver()
            .reverse_lookup(remote_ip)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                info!("{self}: reverse IP verification failed: PTR lookup failed: {e:#}");
                return self
                    .verify_reverse_ip_reply(
                        is_error_negative_lookup(&e),
                        "unable to look up PTR record",
                    )
                    .await;
            }
        };

        if lookup.answers().is_empty() {
            info!("{self}: reverse IP verification failed: no PTR records");
            return self
                .verify_reverse_ip_reply(true, "no PTR records found")
                .await;
        }

        // In non-strict mode we're already happy
        if !self.cfg.verify_reverse_ip_strict {
            return Ok(true);
        }

        // Take max 3 PTRs from the response to avoid DoS.
        // Usually there should be only one anyway.
        let mut last_error = None;
        for ptr in lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.to_lowercase()),
                _ => None,
            })
            .take(3)
        {
            match self.verify_reverse_ip_ptr(ptr).await {
                Ok(v) => {
                    if v {
                        return Ok(true);
                    }
                }
                Err(e) => {
                    info!("{self}: reverse IP verification: PTR->IP lookup failed: {e:#}");
                    last_error = Some(e);
                }
            }
        }

        // Return the last error if there was any
        if let Some(e) = last_error {
            return self
                .verify_reverse_ip_reply(
                    is_error_negative_lookup(&e),
                    "unable to look up IP for the PTR record",
                )
                .await;
        }

        // Otherwise everything succeeded but no matches were found
        info!(
            "{self}: reverse IP verification failed: no addresses matching client's IP found after resolving PTR"
        );
        return self
            .verify_reverse_ip_reply(
                true,
                "no addresses matching client's IP found after resolving PTR",
            )
            .await;
    }
}

#[cfg(test)]
pub mod test {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr},
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Duration,
    };

    use fqdn::FQDN;
    use hickory_proto::rr::RecordType;
    use prometheus::Registry;
    use rustls::{CipherSuite, ProtocolVersion, ServerConfig};
    use smtp_proto::{MAIL_BODY_8BITMIME, MAIL_BY_TRACE, MAIL_REQUIRETLS, MAIL_SMTPUTF8, Request};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use crate::{
        network::TlsInfo,
        smtp::{
            Metrics,
            inbound::{MAX_REPLY_LEN, SessionConfig, SessionTlsMode},
        },
        tests::{TEST_CERT_1, TEST_KEY_1},
        tls::resolver::StubResolver,
    };

    use super::*;

    /// A stub stream that reads EOF straight away and records everything written to it.
    /// Clones share the same buffer, so the test can keep one side to inspect the replies.
    #[derive(Clone, Default)]
    pub struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        /// Drains the buffer and returns what was written since the last call
        pub fn take(&self) -> String {
            let mut buf = self.0.lock().unwrap();
            let out = String::from_utf8(buf.clone()).expect("replies must be valid UTF-8");
            buf.clear();
            out
        }
    }

    impl AsyncRead for Capture {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Nothing read == EOF
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Capture {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Baseline config: hostname `test`, 512-byte message limit, all verification off
    pub fn test_config() -> SessionConfig {
        SessionConfig::new("test", 512)
    }

    /// Rustls server config using the shared test certificate
    pub fn tls_server_config() -> Arc<ServerConfig> {
        // Idempotent, rustls 0.23+ needs a process-wide provider
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(
                    StubResolver::new(TEST_CERT_1.as_bytes(), TEST_KEY_1.as_bytes()).unwrap(),
                )),
        )
    }

    /// Synthetic `TlsInfo` to pretend the session is already inside TLS
    pub fn fake_tls_info() -> TlsInfo {
        TlsInfo {
            sni: None,
            alpn: None,
            protocol: ProtocolVersion::TLSv1_3,
            cipher: CipherSuite::TLS13_AES_128_GCM_SHA256,
            handshake_dur: Duration::ZERO,
        }
    }

    /// The remote address every session gets unless the test says otherwise
    pub const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    /// Fresh session (no EHLO yet) plus a handle to read its replies
    pub fn new_session(cfg: SessionConfig) -> (Session<Capture>, Capture) {
        new_session_ip(cfg, TEST_IP)
    }

    /// Same as `new_session`, but from an arbitrary remote address
    pub fn new_session_ip(cfg: SessionConfig, remote_ip: IpAddr) -> (Session<Capture>, Capture) {
        let out = Capture::default();
        let session = Session::new(
            remote_ip,
            out.clone(),
            Arc::new(cfg),
            Metrics::new(&Registry::new()),
        );

        (session, out)
    }

    /// Session that already greeted us with `EHLO foo.bar`
    pub fn session_with_ehlo(cfg: SessionConfig) -> (Session<Capture>, Capture) {
        session_with_ehlo_ip(cfg, TEST_IP)
    }

    /// Same as `session_with_ehlo`, but from an arbitrary remote address
    pub fn session_with_ehlo_ip(
        cfg: SessionConfig,
        remote_ip: IpAddr,
    ) -> (Session<Capture>, Capture) {
        let (mut session, out) = new_session_ip(cfg, remote_ip);
        session.data.ehlo_hostname = Some(FQDN::from_str("foo.bar").unwrap());
        (session, out)
    }

    /// Config with SPF verification pointed at the given fake zone
    pub fn spf_config(dns: &dns::RunningDns) -> SessionConfig {
        let mut cfg = test_config();
        cfg.verify_spf = true;
        cfg.authenticator = dns.authenticator.clone();
        cfg
    }

    /// Config with sender-domain (MX) verification pointed at the given fake zone
    pub fn sender_domain_config(dns: &dns::RunningDns) -> SessionConfig {
        let mut cfg = test_config();
        cfg.verify_sender_domain = true;
        cfg.authenticator = dns.authenticator.clone();
        cfg
    }

    /// Config with reverse-IP verification pointed at the given fake zone
    pub fn reverse_ip_config(dns: &dns::RunningDns, strict: bool) -> SessionConfig {
        let mut cfg = test_config();
        cfg.verify_reverse_ip = true;
        cfg.verify_reverse_ip_strict = strict;
        cfg.authenticator = dns.authenticator.clone();
        cfg
    }

    /// Bare `MAIL FROM:<address>` without any ESMTP parameters
    pub fn mail_from(address: &str) -> MailFrom<Cow<'_, str>> {
        MailFrom {
            address: Cow::Borrowed(address),
            ..Default::default()
        }
    }

    /// A throwaway UDP DNS server on loopback that answers from a fixed table.
    /// It lets the SPF/MX/PTR branches be driven deterministically, without real DNS.
    pub mod dns {
        use std::{
            collections::HashMap,
            net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
            sync::Arc,
            time::Duration,
        };

        use hickory_proto::{
            op::{Message, ResponseCode},
            rr::{
                Name, RData, Record, RecordType,
                rdata::{A, AAAA, MX, PTR, TXT},
            },
        };
        use hickory_resolver::config::{
            ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
            ResolverOpts,
        };
        use mail_auth::MessageAuthenticator;
        use tokio::{net::UdpSocket, task::JoinHandle};

        /// What the server answers with for a given (owner name, record type)
        #[derive(Clone, Debug)]
        pub enum Answer {
            /// NOERROR carrying these records
            Records(Vec<Record>),
            /// NOERROR with an empty answer section
            Empty,
            /// NXDOMAIN - a negative, i.e. permanent, answer
            NxDomain,
            /// SERVFAIL - a retryable, i.e. temporary, failure
            ServFail,
            /// Stay silent so that the client times out
            Drop,
        }

        fn fqdn(v: &str) -> Name {
            Name::from_utf8(v).unwrap()
        }

        /// `4.3.2.1.in-addr.arpa` / `...ip6.arpa` for the given address
        pub fn reverse_name(ip: IpAddr) -> String {
            match ip {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
                }
                IpAddr::V6(v6) => {
                    let mut out = String::new();
                    for b in v6.octets().iter().rev() {
                        out.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
                    }
                    out.push_str("ip6.arpa");
                    out
                }
            }
        }

        #[derive(Clone, Default)]
        pub struct FakeDns(HashMap<(String, RecordType), Answer>);

        impl FakeDns {
            pub fn new() -> Self {
                Self::default()
            }

            /// Answers the given (name, type) with whatever `answer` says
            pub fn answer(mut self, owner: &str, rtype: RecordType, answer: Answer) -> Self {
                self.0
                    .insert((owner.trim_end_matches('.').to_lowercase(), rtype), answer);
                self
            }

            fn records(self, owner: &str, rtype: RecordType, data: Vec<RData>) -> Self {
                let records = data
                    .into_iter()
                    .map(|x| Record::from_rdata(fqdn(owner), 60, x))
                    .collect();
                self.answer(owner, rtype, Answer::Records(records))
            }

            pub fn txt(self, owner: &str, value: &str) -> Self {
                self.records(
                    owner,
                    RecordType::TXT,
                    vec![RData::TXT(TXT::new(vec![value.into()]))],
                )
            }

            pub fn mx(self, owner: &str, exchange: &str) -> Self {
                self.records(
                    owner,
                    RecordType::MX,
                    vec![RData::MX(MX::new(10, fqdn(exchange)))],
                )
            }

            pub fn a(self, owner: &str, addrs: &[Ipv4Addr]) -> Self {
                self.records(
                    owner,
                    RecordType::A,
                    addrs.iter().map(|x| RData::A(A(*x))).collect(),
                )
            }

            pub fn aaaa(self, owner: &str, addrs: &[Ipv6Addr]) -> Self {
                self.records(
                    owner,
                    RecordType::AAAA,
                    addrs.iter().map(|x| RData::AAAA(AAAA(*x))).collect(),
                )
            }

            /// PTR records for the reverse zone of `ip`
            pub fn ptr(self, ip: IpAddr, hosts: &[&str]) -> Self {
                let owner = reverse_name(ip);
                self.records(
                    &owner,
                    RecordType::PTR,
                    hosts.iter().map(|x| RData::PTR(PTR(fqdn(x)))).collect(),
                )
            }

            /// Binds the server & returns a `MessageAuthenticator` pointed at it
            pub async fn spawn(self) -> RunningDns {
                let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = socket.local_addr().unwrap().port();
                let zone = self.0;

                let task = tokio::spawn(async move {
                    let mut buf = vec![0; 4096];

                    loop {
                        let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                            return;
                        };
                        let Ok(request) = Message::from_vec(&buf[..n]) else {
                            continue;
                        };
                        let Some(query) = request.queries.first().cloned() else {
                            continue;
                        };

                        let key = (
                            query
                                .name()
                                .to_string()
                                .trim_end_matches('.')
                                .to_lowercase(),
                            query.query_type(),
                        );
                        let answer = zone.get(&key).cloned().unwrap_or(Answer::NxDomain);

                        let mut response =
                            Message::response(request.metadata.id, request.metadata.op_code);
                        response.metadata.recursion_desired = request.metadata.recursion_desired;
                        response.metadata.recursion_available = true;
                        response.metadata.authoritative = true;
                        response.queries = request.queries.clone();

                        match answer {
                            Answer::Records(v) => response.answers = v,
                            Answer::Empty => {}
                            Answer::NxDomain => {
                                response.metadata.response_code = ResponseCode::NXDomain;
                            }
                            Answer::ServFail => {
                                response.metadata.response_code = ResponseCode::ServFail;
                            }
                            Answer::Drop => continue,
                        }

                        if let Ok(v) = response.to_vec() {
                            socket.send_to(&v, peer).await.ok();
                        }
                    }
                });

                let mut connection = ConnectionConfig::udp();
                connection.port = port;
                let name_server =
                    NameServerConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST), true, vec![connection]);

                let mut opts = ResolverOpts::default();
                opts.use_hosts_file = ResolveHosts::Never;
                opts.preserve_intermediates = false;
                opts.try_tcp_on_error = false;
                opts.validate = false;
                opts.ip_strategy = LookupIpStrategy::Ipv4Only;
                // Keep the `Answer::Drop` cases quick
                opts.timeout = Duration::from_millis(250);
                opts.attempts = 1;

                let authenticator = MessageAuthenticator::new(
                    ResolverConfig::from_parts(None, vec![], vec![name_server]),
                    opts,
                )
                .unwrap();

                RunningDns {
                    authenticator: Arc::new(authenticator),
                    task,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                }
            }
        }

        pub struct RunningDns {
            pub authenticator: Arc<MessageAuthenticator>,
            pub addr: SocketAddr,
            task: JoinHandle<()>,
        }

        impl Drop for RunningDns {
            fn drop(&mut self) {
                self.task.abort();
            }
        }
    }

    #[tokio::test]
    async fn test_mail_from_before_ehlo() {
        let (mut session, out) = new_session(test_config());
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "503 5.5.1 Polite people say EHLO first.\r\n");
        assert!(session.data.mail_from.is_none());
        assert_eq!(session.counters.errors, 1);
        assert!(matches!(
            session.data.last_error,
            Some(ProtocolError::InvalidSequenceOfCommands(ref v)) if v == "MAIL FROM before EHLO"
        ));
    }

    #[tokio::test]
    async fn test_mail_from_duplicate_keeps_the_first_sender() {
        let (mut session, out) = session_with_ehlo(test_config());

        session
            .handle_mail_from(mail_from("first@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");

        session
            .handle_mail_from(mail_from("second@example.com"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            "503 5.5.1 Multiple MAIL FROM commands are not allowed.\r\n"
        );

        assert_eq!(
            session.data.mail_from.as_ref().unwrap().to_string(),
            "first@example.com"
        );
        assert!(matches!(
            session.data.last_error,
            Some(ProtocolError::InvalidSequenceOfCommands(ref v)) if v == "Multiple MAIL FROM"
        ));
    }

    #[tokio::test]
    async fn test_mail_from_requires_tls() {
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Required(tls_server_config());
        let (mut session, out) = session_with_ehlo(cfg);

        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            "503 5.5.1 TLS is required to submit mail on this server.\r\n"
        );
        assert!(session.data.mail_from.is_none());
        // This particular branch replies without recording a protocol error
        assert_eq!(session.counters.errors, 0);
        assert!(session.data.last_error.is_none());

        // Once TLS is up the very same command goes through
        session.tls_info = Some(fake_tls_info());
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert_eq!(
            session.data.mail_from.as_ref().unwrap().to_string(),
            "a@example.com"
        );
    }

    #[tokio::test]
    async fn test_mail_from_tls_only_required_when_configured() {
        // `Allowed` is not `Required`, so plaintext submission stays fine
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Allowed(tls_server_config());
        let (mut session, out) = session_with_ehlo(cfg);

        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
    }

    #[tokio::test]
    async fn test_mail_from_deliverby_unsupported() {
        for flags in [
            MAIL_BY_NOTIFY,
            MAIL_BY_RETURN,
            MAIL_BY_NOTIFY | MAIL_BY_RETURN,
        ] {
            let (mut session, out) = session_with_ehlo(test_config());
            let mut from = mail_from("a@example.com");
            from.flags = flags;
            from.by = 100;

            session.handle_mail_from(from).await.unwrap();
            assert_eq!(
                out.take(),
                "501 5.5.4 DELIVERBY extension is not supported.\r\n"
            );
            assert!(session.data.mail_from.is_none());
            // No protocol error is recorded for unsupported extensions
            assert_eq!(session.counters.errors, 0);
        }

        // `BY=...;T` only sets the trace bit, which is outside the rejected mask
        let (mut session, out) = session_with_ehlo(test_config());
        let mut from = mail_from("a@example.com");
        from.flags = MAIL_BY_TRACE;
        from.by = 100;
        session.handle_mail_from(from).await.unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
    }

    #[tokio::test]
    async fn test_mail_from_mt_priority_unsupported() {
        // Both positive & negative priorities are refused, zero means "not given"
        for (priority, expected) in [
            (3, "501 5.5.4 MT-PRIORITY extension is not supported.\r\n"),
            (-3, "501 5.5.4 MT-PRIORITY extension is not supported.\r\n"),
            (0, "250 2.1.0 OK\r\n"),
        ] {
            let (mut session, out) = session_with_ehlo(test_config());
            let mut from = mail_from("a@example.com");
            from.mt_priority = priority;

            session.handle_mail_from(from).await.unwrap();
            assert_eq!(out.take(), expected, "mt_priority={priority}");
        }
    }

    #[tokio::test]
    async fn test_mail_from_size_boundary() {
        // Exactly at the limit is still accepted
        let (mut session, out) = session_with_ehlo(test_config());
        let mut from = mail_from("a@example.com");
        from.size = 512;
        session.handle_mail_from(from).await.unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert!(session.data.mail_from.is_some());

        // One byte over is not
        let (mut session, out) = session_with_ehlo(test_config());
        let mut from = mail_from("a@example.com");
        from.size = 513;
        session.handle_mail_from(from).await.unwrap();
        assert_eq!(
            out.take(),
            "552 5.3.4 Message too big, we accept up to 512 bytes.\r\n"
        );
        assert!(session.data.mail_from.is_none());
        // Both the MAIL FROM-specific error & the generic one from `message_too_big()`
        assert_eq!(session.counters.errors, 2);
        assert!(matches!(
            session.data.last_error,
            // Nothing has been received yet, hence 0
            Some(ProtocolError::MessageTooBig(ref v)) if v == "0 > 512"
        ));
    }

    #[tokio::test]
    async fn test_mail_from_size_is_checked_before_the_address() {
        let (mut session, out) = session_with_ehlo(test_config());
        let mut from = mail_from("this-is-not-an-address");
        from.size = 100_000;

        session.handle_mail_from(from).await.unwrap();
        assert_eq!(
            out.take(),
            "552 5.3.4 Message too big, we accept up to 512 bytes.\r\n"
        );
    }

    #[tokio::test]
    async fn test_mail_from_future_release_unsupported() {
        for (hold_for, hold_until) in [(100, 0), (0, 100), (100, 100)] {
            let (mut session, out) = session_with_ehlo(test_config());
            let mut from = mail_from("a@example.com");
            from.hold_for = hold_for;
            from.hold_until = hold_until;

            session.handle_mail_from(from).await.unwrap();
            assert_eq!(
                out.take(),
                "501 5.5.4 FUTURERELEASE extension is not supported.\r\n"
            );
            assert!(session.data.mail_from.is_none());
        }
    }

    #[tokio::test]
    async fn test_mail_from_dsn_unsupported() {
        let (mut session, out) = session_with_ehlo(test_config());
        let mut from = mail_from("a@example.com");
        from.env_id = Some(Cow::Borrowed("deadbeef"));

        session.handle_mail_from(from).await.unwrap();
        assert_eq!(out.take(), "501 5.5.4 DSN extension is not supported.\r\n");
        assert!(session.data.mail_from.is_none());
    }

    #[tokio::test]
    async fn test_mail_from_invalid_address() {
        for address in ["", "nodomain", "a@", "a@b c", "a@foo..bar"] {
            let (mut session, out) = session_with_ehlo(test_config());
            session.handle_mail_from(mail_from(address)).await.unwrap();

            assert_eq!(
                out.take(),
                "550 5.7.1 Sender address is incorrect.\r\n",
                "address={address:?}"
            );
            assert!(session.data.mail_from.is_none());
            assert_eq!(session.counters.errors, 1);
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::SenderValidationFailed(ref v))
                    if v == &format!("Incorrect sender address: {address}")
            ));
        }
    }

    /// The null reverse-path `MAIL FROM:<>` that RFC 5321 4.5.5 reserves for bounces
    /// and DSNs is parsed as an empty address and rejected by the address validation.
    #[tokio::test]
    async fn test_mail_from_null_reverse_path_is_rejected() {
        let mut iter = b"MAIL FROM:<>\r\n".iter();
        let Ok(Request::Mail { from }) = Request::parse(&mut iter) else {
            panic!("MAIL FROM:<> must parse");
        };
        assert_eq!(from.address, "");

        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from).await.unwrap();

        assert_eq!(out.take(), "550 5.7.1 Sender address is incorrect.\r\n");
        assert!(session.data.mail_from.is_none());
    }

    #[tokio::test]
    async fn test_mail_from_accepts_known_esmtp_params() {
        let (mut session, out) = session_with_ehlo(test_config());

        let mut from = mail_from("a@example.com");
        // SMTPUTF8 & BODY=8BITMIME are advertised, REQUIRETLS is silently tolerated
        from.flags = MAIL_SMTPUTF8 | MAIL_BODY_8BITMIME | MAIL_REQUIRETLS;
        from.size = 10;
        from.auth = Some(Cow::Borrowed("<>"));
        from.trans_id = Some(Cow::Borrowed("ignored"));
        from.solicit = Some(Cow::Borrowed("ignored"));

        session.handle_mail_from(from).await.unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert_eq!(
            session.data.mail_from.as_ref().unwrap().to_string(),
            "a@example.com"
        );
        assert_eq!(session.counters.errors, 0);
        assert!(session.data.rcpt_to.is_empty());
    }

    #[tokio::test]
    async fn test_mail_from_normalizes_the_domain_case() {
        let (mut session, out) = session_with_ehlo(test_config());
        session
            .handle_mail_from(mail_from("John.Doe@EXAMPLE.COM"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        // Domain is lowercased, the local part is kept verbatim
        assert_eq!(
            session.data.mail_from.as_ref().unwrap().to_string(),
            "John.Doe@example.com"
        );
    }

    /// A trailing dot is part of a valid FQDN on the wire but must not survive
    /// into the stored address
    #[tokio::test]
    async fn test_mail_from_strips_the_trailing_dot() {
        let (mut session, out) = session_with_ehlo(test_config());
        session
            .handle_mail_from(mail_from("a@example.com."))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert_eq!(
            session.data.mail_from.as_ref().unwrap().to_string(),
            "a@example.com"
        );
    }

    /// Parses a raw command line into the `MailFrom` the handler receives
    fn parse_mail(line: &str) -> MailFrom<Cow<'_, str>> {
        let mut iter = line.as_bytes().iter();
        match Request::parse(&mut iter) {
            Ok(Request::Mail { from }) => from,
            _ => panic!("{line:?} must parse as MAIL FROM"),
        }
    }

    /// The doc comment promises that everything to the right of the *rightmost*
    /// `@` is the domain, so an unquoted `@` in the local part is kept as-is
    #[tokio::test]
    async fn test_mail_from_rightmost_at_separates_the_domain() {
        let (mut session, out) = session_with_ehlo(test_config());
        session
            .handle_mail_from(mail_from("a@b@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        let address = session.data.mail_from.as_ref().unwrap();
        assert_eq!(address.local(), "a@b");
        assert_eq!(address.domain().to_string(), "example.com");
    }

    /// RFC 5321 address literals (`user@[10.0.0.1]`) are not supported, while a
    /// bare IP is indistinguishable from a domain name and goes through
    #[tokio::test]
    async fn test_mail_from_address_literals_are_rejected() {
        let (mut session, out) = session_with_ehlo(test_config());
        session
            .handle_mail_from(mail_from("a@[1.2.3.4]"))
            .await
            .unwrap();
        assert_eq!(out.take(), "550 5.7.1 Sender address is incorrect.\r\n");
        assert!(session.data.mail_from.is_none());

        let (mut session, out) = session_with_ehlo(test_config());
        session
            .handle_mail_from(mail_from("a@1.2.3.4"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert_eq!(
            session.data.mail_from.as_ref().unwrap().to_string(),
            "a@1.2.3.4"
        );
    }

    /// Control characters in the local part would allow header/reply injection
    /// downstream, and non-ASCII is refused even though we advertise SMTPUTF8
    #[tokio::test]
    async fn test_mail_from_rejects_control_and_non_ascii_local_parts() {
        for address in [
            "a\rb@example.com",
            "a\nb@example.com",
            "a\0b@example.com",
            "a\tb@example.com",
            "üser@example.com",
            "日本@example.com",
        ] {
            let (mut session, out) = session_with_ehlo(test_config());
            session.handle_mail_from(mail_from(address)).await.unwrap();

            assert_eq!(
                out.take(),
                "550 5.7.1 Sender address is incorrect.\r\n",
                "address={address:?}"
            );
            assert!(session.data.mail_from.is_none());
        }
    }

    /// `SMTPUTF8` is advertised by the EHLO banner, but a UTF-8 mailbox is still
    /// rejected by the address validation
    #[tokio::test]
    async fn test_mail_from_smtputf8_does_not_permit_utf8_mailboxes() {
        let from = parse_mail("MAIL FROM:<üser@example.com> SMTPUTF8\r\n");
        assert_eq!(from.flags, MAIL_SMTPUTF8);
        assert_eq!(from.address, "üser@example.com");

        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from).await.unwrap();
        assert_eq!(out.take(), "550 5.7.1 Sender address is incorrect.\r\n");
    }

    /// There is no length cap on the address, so an absurdly long one is accepted -
    /// the important part is that it can't overflow the fixed-size reply buffer
    #[tokio::test]
    async fn test_mail_from_oversized_address_is_accepted_and_does_not_break_the_reply() {
        let address = format!("{}@{}com", "l".repeat(1000), "xxxxxxxxx.".repeat(26));
        assert!(address.len() > MAX_REPLY_LEN);

        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(mail_from(&address)).await.unwrap();

        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert_eq!(session.data.mail_from.as_ref().unwrap().local().len(), 1000);
    }

    /// The ESMTP parameters that reach the handler come from `smtp_proto`, so drive
    /// the whole thing from the raw command line
    #[tokio::test]
    async fn test_mail_from_esmtp_parameters_from_the_wire() {
        for (line, expected) in [
            // The space after the colon is tolerated
            ("MAIL FROM: <a@example.com>\r\n", "250 2.1.0 OK\r\n"),
            (
                "MAIL FROM:<a@example.com> SIZE=512 BODY=8BITMIME SMTPUTF8 AUTH=<>\r\n",
                "250 2.1.0 OK\r\n",
            ),
            // SIZE is compared against `max_message_size` (512)
            (
                "MAIL FROM:<a@example.com> SIZE=513\r\n",
                "552 5.3.4 Message too big, we accept up to 512 bytes.\r\n",
            ),
            // A repeated parameter: the last one wins
            (
                "MAIL FROM:<a@example.com> SIZE=99999 SIZE=1\r\n",
                "250 2.1.0 OK\r\n",
            ),
            (
                "MAIL FROM:<a@example.com> SIZE=1 SIZE=99999\r\n",
                "552 5.3.4 Message too big, we accept up to 512 bytes.\r\n",
            ),
            // BINARYMIME isn't advertised (no BINARYMIME in the EHLO banner) but
            // the flag is ignored rather than refused
            (
                "MAIL FROM:<a@example.com> BODY=BINARYMIME\r\n",
                "250 2.1.0 OK\r\n",
            ),
            // DSN, DELIVERBY & FUTURERELEASE are all refused
            (
                "MAIL FROM:<a@example.com> ENVID=QQ314159\r\n",
                "501 5.5.4 DSN extension is not supported.\r\n",
            ),
            (
                "MAIL FROM:<a@example.com> BY=120;R\r\n",
                "501 5.5.4 DELIVERBY extension is not supported.\r\n",
            ),
            (
                "MAIL FROM:<a@example.com> HOLDFOR=60\r\n",
                "501 5.5.4 FUTURERELEASE extension is not supported.\r\n",
            ),
            (
                "MAIL FROM:<a@example.com> MT-PRIORITY=1\r\n",
                "501 5.5.4 MT-PRIORITY extension is not supported.\r\n",
            ),
            // The null reverse path used by bounces
            (
                "MAIL FROM:<>\r\n",
                "550 5.7.1 Sender address is incorrect.\r\n",
            ),
        ] {
            let (mut session, out) = session_with_ehlo(test_config());
            session.handle_mail_from(parse_mail(line)).await.unwrap();
            assert_eq!(out.take(), expected, "line={line:?}");
        }
    }

    /// Malformed commands are rejected by the parser & never reach the handler,
    /// which is why it can assume a bare address without angle brackets
    #[test]
    fn test_mail_from_malformed_commands_do_not_parse() {
        for line in [
            // Angle brackets are mandatory
            "MAIL FROM:a@example.com\r\n",
            "MAIL FROM:<a@example.com\r\n",
            "MAIL FROM:a@example.com>\r\n",
            "MAIL FROM:\r\n",
            // Unknown & malformed parameters
            "MAIL FROM:<a@example.com> FOO=BAR\r\n",
            "MAIL FROM:<a@example.com> SIZE=notanumber\r\n",
            "MAIL FROM:<a@example.com> BODY=NONSENSE\r\n",
        ] {
            let mut iter = line.as_bytes().iter();
            assert!(
                Request::parse(&mut iter).is_err(),
                "{line:?} must not parse"
            );
        }
    }

    /// The order of the checks is observable, so pin it down: whatever comes
    /// first in the handler wins even when everything else is wrong too
    #[tokio::test]
    async fn test_mail_from_check_order() {
        let mut from = mail_from("not-an-address");
        from.flags = MAIL_BY_NOTIFY;
        from.by = 1;
        from.mt_priority = 1;
        from.size = 100_000;
        from.hold_for = 60;
        from.env_id = Some(Cow::Borrowed("x"));

        // EHLO first of all
        let (mut session, out) = new_session(test_config());
        session.handle_mail_from(from.clone()).await.unwrap();
        assert_eq!(out.take(), "503 5.5.1 Polite people say EHLO first.\r\n");

        // then TLS
        let mut cfg = test_config();
        cfg.tls_mode = SessionTlsMode::Required(tls_server_config());
        let (mut session, out) = session_with_ehlo(cfg);
        session.handle_mail_from(from.clone()).await.unwrap();
        assert_eq!(
            out.take(),
            "503 5.5.1 TLS is required to submit mail on this server.\r\n"
        );

        // then DELIVERBY, MT-PRIORITY, SIZE, FUTURERELEASE, DSN & the address last
        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from.clone()).await.unwrap();
        assert_eq!(
            out.take(),
            "501 5.5.4 DELIVERBY extension is not supported.\r\n"
        );

        from.flags = 0;
        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from.clone()).await.unwrap();
        assert_eq!(
            out.take(),
            "501 5.5.4 MT-PRIORITY extension is not supported.\r\n"
        );

        from.mt_priority = 0;
        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from.clone()).await.unwrap();
        assert_eq!(
            out.take(),
            "552 5.3.4 Message too big, we accept up to 512 bytes.\r\n"
        );

        from.size = 0;
        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from.clone()).await.unwrap();
        assert_eq!(
            out.take(),
            "501 5.5.4 FUTURERELEASE extension is not supported.\r\n"
        );

        from.hold_for = 0;
        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from.clone()).await.unwrap();
        assert_eq!(out.take(), "501 5.5.4 DSN extension is not supported.\r\n");

        from.env_id = None;
        let (mut session, out) = session_with_ehlo(test_config());
        session.handle_mail_from(from).await.unwrap();
        assert_eq!(out.take(), "550 5.7.1 Sender address is incorrect.\r\n");
    }

    // ---------------------------------------------------------------------
    // SPF
    // ---------------------------------------------------------------------

    /// `Pass`, `Neutral` & `None` are all treated as acceptable
    #[tokio::test]
    async fn test_mail_from_spf_pass_neutral_none_are_accepted() {
        for record in [
            // Pass - our IP is listed
            Some("v=spf1 ip4:1.2.3.4 -all"),
            // Neutral
            Some("v=spf1 ip4:9.9.9.9 ?all"),
            // None - no SPF record at all
            None,
        ] {
            let mut zone = dns::FakeDns::new();
            if let Some(v) = record {
                zone = zone.txt("example.com", v);
            }
            let dns = zone.spawn().await;

            let (mut session, out) = session_with_ehlo(spf_config(&dns));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(out.take(), "250 2.1.0 OK\r\n", "record={record:?}");
            assert!(session.data.mail_from.is_some());
            assert_eq!(session.counters.errors, 0);
        }
    }

    /// `Fail`, `SoftFail` & `PermError` share the same permanent rejection
    #[tokio::test]
    async fn test_mail_from_spf_fail_softfail_permerror_are_rejected() {
        for record in [
            // Fail
            "v=spf1 ip4:9.9.9.9 -all",
            // SoftFail - still rejected, we don't do "accept & mark"
            "v=spf1 ip4:9.9.9.9 ~all",
            // PermError - a syntactically broken record (duplicate redirect)
            "v=spf1 redirect=a.example.com redirect=b.example.com",
        ] {
            let dns = dns::FakeDns::new().txt("example.com", record).spawn().await;

            let (mut session, out) = session_with_ehlo(spf_config(&dns));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(
                out.take(),
                "550 5.7.23 SPF validation failed\r\n",
                "record={record:?}"
            );
            assert!(session.data.mail_from.is_none());
            assert_eq!(session.counters.errors, 1);
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::SpfValidationFailed(ref v))
                    if v == "SPF validation permanent error: None"
            ));
        }
    }

    /// A DNS failure while looking up the SPF record is retryable
    #[tokio::test]
    async fn test_mail_from_spf_temporary_error() {
        for answer in [dns::Answer::ServFail, dns::Answer::Drop] {
            let dns = dns::FakeDns::new()
                .answer("example.com", RecordType::TXT, answer)
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo(spf_config(&dns));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(out.take(), "451 4.7.24 Temporary SPF validation error.\r\n");
            assert!(session.data.mail_from.is_none());
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::SpfValidationFailed(ref v))
                    if v.starts_with("SPF validation temporary error")
            ));
        }
    }

    /// The `exp=` explanation is appended to the rejection, with its macros
    /// expanded from the session - which proves the client IP, the server
    /// hostname & the sender are all handed to the verifier
    #[tokio::test]
    async fn test_mail_from_spf_explanation_is_appended() {
        for (explanation, expected) in [
            ("you are not welcome here", "you are not welcome here"),
            ("rejected by %{r}", "rejected by test"),
            (
                "%{i} may not send as %{s}",
                "1.2.3.4 may not send as a@example.com",
            ),
        ] {
            let dns = dns::FakeDns::new()
                .txt("example.com", "v=spf1 ip4:9.9.9.9 -all exp=exp.example.com")
                .txt("exp.example.com", explanation)
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo(spf_config(&dns));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(
                out.take(),
                format!("550 5.7.23 SPF validation failed: {expected}\r\n"),
                "explanation={explanation:?}"
            );
        }
    }

    /// The explanation is attacker-controlled (it lives in the sender's own DNS),
    /// so it must not be able to break the reply out of its fixed-size buffer
    #[tokio::test]
    async fn test_mail_from_spf_explanation_cannot_overflow_the_reply() {
        // "550 5.7.23 SPF validation failed: " is 34 bytes, so 220 bytes of
        // explanation is the longest one that still fits with the trailing CRLF
        let dns = dns::FakeDns::new()
            .txt("example.com", "v=spf1 ip4:9.9.9.9 -all exp=exp.example.com")
            .txt("exp.example.com", &"y".repeat(220))
            .spawn()
            .await;

        let (mut session, out) = session_with_ehlo(spf_config(&dns));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        let reply = out.take();
        assert_eq!(
            reply,
            format!("550 5.7.23 SPF validation failed: {}\r\n", "y".repeat(220))
        );
        assert_eq!(reply.len(), MAX_REPLY_LEN);

        // One byte over & the explanation is dropped instead of being truncated,
        // but the reply stays a single well-formed line
        let dns = dns::FakeDns::new()
            .txt("example.com", "v=spf1 ip4:9.9.9.9 -all exp=exp.example.com")
            .txt("exp.example.com", &"y".repeat(250))
            .spawn()
            .await;

        let (mut session, out) = session_with_ehlo(spf_config(&dns));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        let reply = out.take();
        assert!(
            reply.len() <= MAX_REPLY_LEN + 2,
            "reply is {} bytes",
            reply.len()
        );
        assert_eq!(reply.matches("\r\n").count(), 1, "{reply:?}");
        assert!(!reply.contains('y'), "{reply:?}");
    }

    /// The `exp=` explanation comes from the sender's own DNS zone and reaches
    /// `reply_with()` unsanitised, so a CRLF in it splits the 550 into two SMTP
    /// response lines - the second one entirely attacker-chosen.
    ///
    /// NOTE: this pins the CURRENT (vulnerable) behaviour so the injection cannot
    /// regress silently. Once the explanation is filtered, this test must be
    /// updated to assert a single sanitised line.
    #[tokio::test]
    async fn test_mail_from_spf_explanation_can_inject_a_second_reply_line() {
        let dns = dns::FakeDns::new()
            .txt("example.com", "v=spf1 ip4:9.9.9.9 -all exp=exp.example.com")
            .txt("exp.example.com", "boom\r\n250 hacked")
            .spawn()
            .await;

        let (mut session, out) = session_with_ehlo(spf_config(&dns));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();

        let reply = out.take();
        assert_eq!(
            reply,
            "550 5.7.23 SPF validation failed: boom\r\n250 hacked\r\n"
        );
        // Two CRLF-terminated lines instead of the one the protocol allows
        assert_eq!(reply.matches("\r\n").count(), 2);
        assert!(session.data.mail_from.is_none());
    }

    /// SPF is evaluated for the *sender's* domain, and the EHLO hostname is passed
    /// along for the `%{h}` macro & the HELO identity
    #[tokio::test]
    async fn test_mail_from_spf_uses_the_sender_domain_and_the_ehlo_hostname() {
        // A `-all` record on the EHLO domain must not be consulted...
        let dns = dns::FakeDns::new()
            .txt("example.com", "v=spf1 ip4:1.2.3.4 -all")
            .txt("foo.bar", "v=spf1 -all")
            .spawn()
            .await;
        let (mut session, out) = session_with_ehlo(spf_config(&dns));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");

        // ...but the EHLO hostname is still handed over, so `%{h}` expands to it
        let dns = dns::FakeDns::new()
            .txt("example.com", "v=spf1 exists:%{h} -all")
            .a("foo.bar", &[Ipv4Addr::new(1, 2, 3, 4)])
            .spawn()
            .await;
        let (mut session, out) = session_with_ehlo(spf_config(&dns));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");

        // Same record, but now `foo.bar` doesn't exist -> the `exists:` mechanism
        // doesn't match & `-all` rejects
        let dns = dns::FakeDns::new()
            .txt("example.com", "v=spf1 exists:%{h} -all")
            .spawn()
            .await;
        let (mut session, out) = session_with_ehlo(spf_config(&dns));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "550 5.7.23 SPF validation failed\r\n");
    }

    /// Nothing is looked up at all while `verify_spf` is off
    #[tokio::test]
    async fn test_mail_from_spf_disabled_skips_the_check() {
        let dns = dns::FakeDns::new()
            .txt("example.com", "v=spf1 -all")
            .spawn()
            .await;

        let mut cfg = spf_config(&dns);
        cfg.verify_spf = false;
        let (mut session, out) = session_with_ehlo(cfg);
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
    }

    // ---------------------------------------------------------------------
    // Sender domain (MX)
    // ---------------------------------------------------------------------

    /// A single-label sender domain is refused before any DNS is touched
    #[tokio::test]
    async fn test_mail_from_sender_domain_must_be_fqdn() {
        let dns = dns::FakeDns::new().spawn().await;

        for address in ["a@localhost", "a@com"] {
            let (mut session, out) = session_with_ehlo(sender_domain_config(&dns));
            session.handle_mail_from(mail_from(address)).await.unwrap();

            assert_eq!(
                out.take(),
                "550 5.7.2 Sender must be an FQDN.\r\n",
                "address={address:?}"
            );
            assert!(session.data.mail_from.is_none());
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::SenderValidationFailed(ref v))
                    if v.starts_with("Sender domain is not FQDN")
            ));
        }
    }

    /// Both an NXDOMAIN & an empty answer count as "no MX"
    #[tokio::test]
    async fn test_mail_from_sender_domain_without_mx_is_rejected() {
        for answer in [dns::Answer::NxDomain, dns::Answer::Empty] {
            let dns = dns::FakeDns::new()
                .answer("example.com", RecordType::MX, answer)
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo(sender_domain_config(&dns));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(
                out.take(),
                "550 5.7.25 No MX record matching your sender domain found.\r\n"
            );
            assert!(session.data.mail_from.is_none());
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::SenderValidationFailed(ref v)) if v == "No MX records found"
            ));
        }
    }

    /// A broken resolver is a 4xx, not a 5xx
    #[tokio::test]
    async fn test_mail_from_sender_domain_temporary_dns_error() {
        for answer in [dns::Answer::ServFail, dns::Answer::Drop] {
            let dns = dns::FakeDns::new()
                .answer("example.com", RecordType::MX, answer)
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo(sender_domain_config(&dns));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(
                out.take(),
                "451 4.7.25 Temporary error validating sender domain.\r\n"
            );
            assert!(session.data.mail_from.is_none());
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::SenderValidationFailed(ref v))
                    if v.starts_with("Sender domain verification temporary error")
            ));
        }
    }

    /// The lookup is done for the sender's domain, not the EHLO one
    #[tokio::test]
    async fn test_mail_from_sender_domain_with_mx_is_accepted() {
        let dns = dns::FakeDns::new()
            .mx("example.com", "mail.example.com")
            .mx("foo.bar", "mail.foo.bar")
            .spawn()
            .await;

        let (mut session, out) = session_with_ehlo(sender_domain_config(&dns));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert!(session.data.mail_from.is_some());

        // A sender in a domain without MX is refused even though the EHLO domain has one
        let (mut session, out) = session_with_ehlo(sender_domain_config(&dns));
        session
            .handle_mail_from(mail_from("a@other.example"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            "550 5.7.25 No MX record matching your sender domain found.\r\n"
        );
    }

    // ---------------------------------------------------------------------
    // Reverse IP
    // ---------------------------------------------------------------------

    /// Without `verify_reverse_ip_strict` the mere existence of a PTR is enough -
    /// the forward lookup isn't even attempted
    #[tokio::test]
    async fn test_mail_from_reverse_ip_non_strict_only_needs_a_ptr() {
        let dns = dns::FakeDns::new()
            .ptr(TEST_IP, &["host.example.com"])
            // Deliberately pointing somewhere else
            .a("host.example.com", &[Ipv4Addr::new(9, 9, 9, 9)])
            .spawn()
            .await;

        let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, false));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();

        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert!(session.data.reverse_ip_verified);
        assert_eq!(session.counters.errors, 0);
    }

    /// In non-strict mode even a permanent failure is reported as temporary
    #[tokio::test]
    async fn test_mail_from_reverse_ip_non_strict_failures_are_temporary() {
        for answer in [
            dns::Answer::NxDomain,
            dns::Answer::Empty,
            dns::Answer::ServFail,
        ] {
            let dns = dns::FakeDns::new()
                .answer(&dns::reverse_name(TEST_IP), RecordType::PTR, answer)
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, false));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(
                out.take(),
                "451 4.7.25 Temporary error validating reverse DNS: unable to look up PTR record\r\n"
            );
            assert!(!session.data.reverse_ip_verified);
            assert!(session.data.mail_from.is_none());
            assert!(matches!(
                session.data.last_error,
                Some(ProtocolError::ReverseIpValidationFailed(ref v))
                    if v == "unable to look up PTR record"
            ));
        }
    }

    /// Strict mode is the only one that emits 5xx, and only for negative answers
    #[tokio::test]
    async fn test_mail_from_reverse_ip_strict_permanent_vs_temporary() {
        for (answer, expected) in [
            (
                dns::Answer::NxDomain,
                "550 5.7.25 Reverse DNS validation failed: unable to look up PTR record\r\n",
            ),
            (
                dns::Answer::ServFail,
                "451 4.7.25 Temporary error validating reverse DNS: unable to look up PTR record\r\n",
            ),
            (
                dns::Answer::Drop,
                "451 4.7.25 Temporary error validating reverse DNS: unable to look up PTR record\r\n",
            ),
        ] {
            let dns = dns::FakeDns::new()
                .answer(&dns::reverse_name(TEST_IP), RecordType::PTR, answer)
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, true));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(out.take(), expected);
            assert!(!session.data.reverse_ip_verified);
        }
    }

    /// Strict mode resolves the PTR back & wants the client's own address in there
    #[tokio::test]
    async fn test_mail_from_reverse_ip_strict_needs_a_matching_address() {
        // A match anywhere in the answer is enough
        let dns = dns::FakeDns::new()
            .ptr(TEST_IP, &["host.example.com"])
            .a(
                "host.example.com",
                &[Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 2, 3, 4)],
            )
            .spawn()
            .await;
        let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, true));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert!(session.data.reverse_ip_verified);

        // No match -> permanent rejection
        let dns = dns::FakeDns::new()
            .ptr(TEST_IP, &["host.example.com"])
            .a("host.example.com", &[Ipv4Addr::new(9, 9, 9, 9)])
            .spawn()
            .await;
        let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, true));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            concat!(
                "550 5.7.25 Reverse DNS validation failed: ",
                "no addresses matching client's IP found after resolving PTR\r\n"
            )
        );
        assert!(!session.data.reverse_ip_verified);
        assert!(session.data.mail_from.is_none());
    }

    /// A failing forward lookup is reported separately from a mismatch, and keeps
    /// the permanent/temporary distinction
    #[tokio::test]
    async fn test_mail_from_reverse_ip_strict_forward_lookup_errors() {
        for (answer, expected) in [
            (
                dns::Answer::NxDomain,
                concat!(
                    "550 5.7.25 Reverse DNS validation failed: ",
                    "unable to look up IP for the PTR record\r\n"
                ),
            ),
            (
                dns::Answer::ServFail,
                concat!(
                    "451 4.7.25 Temporary error validating reverse DNS: ",
                    "unable to look up IP for the PTR record\r\n"
                ),
            ),
        ] {
            let dns = dns::FakeDns::new()
                .ptr(TEST_IP, &["host.example.com"])
                .answer("host.example.com", RecordType::A, answer)
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, true));
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(out.take(), expected);
            assert!(!session.data.reverse_ip_verified);
        }
    }

    /// Only the first three PTRs are resolved, to bound the work an attacker can
    /// make us do
    #[tokio::test]
    async fn test_mail_from_reverse_ip_checks_at_most_three_ptrs() {
        let hosts = [
            "p1.example.com",
            "p2.example.com",
            "p3.example.com",
            "p4.example.com",
        ];

        // The match sits in the 4th PTR, which is never looked at
        let dns = dns::FakeDns::new()
            .ptr(TEST_IP, &hosts)
            .a("p1.example.com", &[Ipv4Addr::new(9, 9, 9, 1)])
            .a("p2.example.com", &[Ipv4Addr::new(9, 9, 9, 2)])
            .a("p3.example.com", &[Ipv4Addr::new(9, 9, 9, 3)])
            .a("p4.example.com", &[Ipv4Addr::new(1, 2, 3, 4)])
            .spawn()
            .await;
        let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, true));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            concat!(
                "550 5.7.25 Reverse DNS validation failed: ",
                "no addresses matching client's IP found after resolving PTR\r\n"
            )
        );

        // Moving it into the 3rd one makes the very same setup pass
        let dns = dns::FakeDns::new()
            .ptr(TEST_IP, &hosts)
            .a("p1.example.com", &[Ipv4Addr::new(9, 9, 9, 1)])
            .a("p2.example.com", &[Ipv4Addr::new(9, 9, 9, 2)])
            .a("p3.example.com", &[Ipv4Addr::new(1, 2, 3, 4)])
            .a("p4.example.com", &[Ipv4Addr::new(9, 9, 9, 4)])
            .spawn()
            .await;
        let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, true));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
    }

    /// The IPv6 branch compares AAAA records instead of A ones
    #[tokio::test]
    async fn test_mail_from_reverse_ip_strict_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        for (aaaa, expected) in [
            (
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                "250 2.1.0 OK\r\n",
            ),
            (
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9),
                concat!(
                    "550 5.7.25 Reverse DNS validation failed: ",
                    "no addresses matching client's IP found after resolving PTR\r\n"
                ),
            ),
        ] {
            let dns = dns::FakeDns::new()
                .ptr(ip, &["host.example.com"])
                .aaaa("host.example.com", &[aaaa])
                // An A record with the "right" last octet must not be consulted
                .a("host.example.com", &[Ipv4Addr::new(0, 0, 0, 1)])
                .spawn()
                .await;

            let (mut session, out) = session_with_ehlo_ip(reverse_ip_config(&dns, true), ip);
            session
                .handle_mail_from(mail_from("a@example.com"))
                .await
                .unwrap();

            assert_eq!(out.take(), expected, "aaaa={aaaa}");
        }
    }

    /// Once verified, the check is skipped for the rest of the session
    #[tokio::test]
    async fn test_mail_from_reverse_ip_is_verified_only_once() {
        // A zone where the verification can only fail
        let dns = dns::FakeDns::new().spawn().await;

        let (mut session, out) = session_with_ehlo(reverse_ip_config(&dns, true));
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(
            out.take(),
            "550 5.7.25 Reverse DNS validation failed: unable to look up PTR record\r\n"
        );

        // Pretending an earlier transaction already verified it lets the very
        // same command through without any lookup
        session.data.reverse_ip_verified = true;
        session
            .handle_mail_from(mail_from("a@example.com"))
            .await
            .unwrap();
        assert_eq!(out.take(), "250 2.1.0 OK\r\n");
        assert!(session.data.mail_from.is_some());
    }
}
