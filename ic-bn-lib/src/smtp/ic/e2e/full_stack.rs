//! The whole path a real MTA takes: SMTP client over a socket -> `Server` ->
//! session state machine -> `IcSmtpDeliveryAgent` -> chunked upload -> PocketIC
//! -> the PoC canister.
//!
//! The other tests in this module drive `deliver_mail` directly, which is the
//! right level for asserting protocol details. This one exists to prove the
//! pieces are actually connected, with a message large enough to chunk.

use std::{sync::Arc, time::Duration};

use mail_send::SmtpClientBuilder;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    network::{ListenerOpts, listener::listen_tcp},
    smtp::{Metrics as SmtpMetrics, inbound::SessionConfig, server::Server},
};

use super::{CANISTER_MAX_MESSAGE, DeliveryPath, SmtpTestEnv, delivery_agent, upload_cfg};

/// Large enough to need several chunks at the test's 64 KiB chunk size.
const BODY_LEN: usize = 300_000;

/// Drives the real SMTP server end to end.
///
/// **One message only.** Under `cfg(test)` the session assigns
/// `message_id = Uuid::nil()` (`inbound/mod.rs` and `session.rs`), so every
/// message this server produces shares one upload key. A second `send()` would
/// collide with the first upload - the canister answers 450 "chunk does not
/// match the upload in progress" because the envelope differs - or be deduped
/// to the first verdict. Install a second canister if you need a second message.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smtp_full_stack_e2e() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    let canister_id = env.install(&env.init_arg(CANISTER_MAX_MESSAGE)).await?;

    let agent = Arc::new(delivery_agent(env.agent().await?, upload_cfg()));

    // Build the message by hand rather than with `MessageBuilder`: it may
    // re-encode the body (quoted-printable, folding), which would break a
    // digest computed from what we passed in. CRLF endings as on the wire.
    let body: Vec<u8> = (0..BODY_LEN).map(|i| b'a' + (i % 26) as u8).collect();

    // The client terminates DATA with an unconditional "\r\n.\r\n", so the
    // message the server reassembles always carries one more CRLF than we
    // wrote - even if the body already ended with one. That is a property of
    // the transfer, not of the chunking, so bake it into the expectation
    // rather than trying to send a body that avoids it.
    let mut expected_body = body.clone();
    expected_body.extend_from_slice(b"\r\n");

    let rcpt = format!("jane@{canister_id}.icp0.io");

    let mut raw = format!(
        "From: John Doe <john@doe.com>\r\n\
         To: Jane Doe <{rcpt}>\r\n\
         Subject: full stack\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain\r\n\r\n"
    )
    .into_bytes();
    raw.extend_from_slice(&body);

    // The server must accept a message this large, and its recipient resolver
    // is the delivery agent itself.
    let mut cfg = SessionConfig::new("test", 4 * 1024 * 1024);
    cfg.delivery_agent = agent.clone();
    cfg.recipient_resolver = agent.clone();
    cfg.greeting_delay = None;

    let listener = listen_tcp("127.0.0.1:0".parse().unwrap(), ListenerOpts::default())?;
    let port = listener.local_addr()?.port();

    let token = CancellationToken::new();
    let server = Server::new_with_listener(listener, cfg, SmtpMetrics::new(&Default::default()))?;
    let server_task = {
        let token = token.child_token();
        tokio::spawn(async move { server.serve(token).await })
    };

    // `connect()` insists on STARTTLS and errors out if the server does not
    // advertise it; this server runs plaintext, which is what a gateway behind
    // a TLS terminator looks like.
    let mut client = SmtpClientBuilder::new("127.0.0.1", port)
        .map_err(|e| anyhow::anyhow!("unable to build the SMTP client: {e}"))?
        .implicit_tls(false)
        .helo_host("gateway.test")
        .connect_plain()
        .await?;

    client
        .send(mail_send::smtp::message::Message::new(
            "john@doe.com",
            [rcpt.as_str()],
            raw.clone(),
        ))
        .await?;

    client.quit().await.ok();
    token.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), server_task).await;

    // The session assigns the nil UUID under cfg(test) - see the doc comment.
    let delivered = env
        .delivered(canister_id, &uuid::Uuid::nil().to_string())
        .await?
        .expect("the canister recorded no delivery");

    assert_eq!(delivered.via, DeliveryPath::Chunked);
    assert_eq!(delivered.body_len, expected_body.len() as u64);
    assert_eq!(
        delivered.body_sha256,
        Sha256::digest(&expected_body).to_vec(),
        "body did not survive the round trip"
    );

    assert_eq!(
        delivered.envelope.to.len(),
        1,
        "{:?}",
        delivered.envelope.to
    );
    assert_eq!(delivered.envelope.to[0].user, "jane");

    let stats = env.stats(canister_id).await?;
    assert_eq!(stats.delivered, 1);
    assert_eq!(stats.open_uploads, 0);

    Ok(())
}
