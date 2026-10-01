//! End-to-end tests of the IC SMTP protocol against a real canister.
//!
//! Everything else that exercises the chunked upload does so against
//! `ChunkingExecutor`, an in-process mock living in the same file as the code
//! it checks. That proves the gateway is self-consistent and nothing more.
//! These tests run the gateway against `smtp/canister`, a separately-written
//! implementation, over a real `ic_agent::Agent` and a real PocketIC replica -
//! so a Candid mismatch, a wrong reply code or a bad digest actually shows up.
//!
//! All of them are `#[ignore]`d and only run from `./run_tests.sh`, which
//! downloads PocketIC and builds the canister wasm first.

use std::{net::IpAddr, str::FromStr, sync::Arc, time::Duration};

use candid::{Decode, Encode, Principal};
use prometheus::Registry;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    email,
    smtp::{
        DeliversMail, DeliveryError, EmailMessage, RecipientResolveError, ResolvesRecipient,
        SessionCounters, SessionMeta,
        address::EmailAddress,
        ic::{
            Metrics,
            candid::{
                SMTP_UPLOAD_PROTOCOL_VERSION, SmtpCapabilities, SmtpResponse, SmtpUploadCommit,
            },
            delivery_agent::IcSmtpDeliveryAgent,
            upload::IcSmtpUploadConfig,
        },
    },
};

use harness::{DeliveryPath, NoCustomDomains, SmtpTestEnv, Stub404Client};

mod harness;

/// Body size that chunks into exactly 5 pieces at the config below.
const CHUNKED_BODY: usize = 300_000;

/// What the canister advertises and enforces.
const CANISTER_MAX_MESSAGE: u64 = 10 * 1024 * 1024;

/// Small enough that a ~300 KB message must be chunked, large enough that the
/// per-chunk Candid overhead leaves room.
fn upload_cfg() -> IcSmtpUploadConfig {
    IcSmtpUploadConfig {
        max_ingress_size: 256 * 1024,
        chunk_size: 64 * 1024,
        max_inflight_bytes: 256 * 1024,
        global_concurrency: 4,
        ..Default::default()
    }
}

/// An upload config that never chunks, for comparing the two paths.
fn single_shot_cfg() -> IcSmtpUploadConfig {
    IcSmtpUploadConfig {
        max_ingress_size: 8 * 1024 * 1024,
        ..upload_cfg()
    }
}

fn delivery_agent(agent: ic_agent::Agent, cfg: IcSmtpUploadConfig) -> IcSmtpDeliveryAgent {
    IcSmtpDeliveryAgent::new_with_agent(
        agent,
        Arc::new(NoCustomDomains),
        Arc::new(Stub404Client),
        "icp0.io",
        Duration::from_secs(60),
        100,
        Metrics::new(&Registry::new()),
        None,
    )
    .with_upload_config(cfg)
}

fn test_meta() -> SessionMeta {
    SessionMeta {
        id: Uuid::nil(),
        message_id: Uuid::nil(),
        remote_ip: IpAddr::from_str("127.0.0.1").unwrap(),
        tls_info: None,
        ehlo_hostname: None,
        counters: SessionCounters::new(),
        last_error: None,
        mail_from: None,
        rcpt_to: vec![],
    }
}

/// A raw RFC 5322 message with a body of exactly `body_len` bytes.
///
/// Returns `(raw, body)` so the test can hash the body the canister will end up
/// with, independently of how the gateway parses it.
fn raw_message(body_len: usize) -> (Vec<u8>, Vec<u8>) {
    let headers = "From: John Doe <john@doe.com>\r\n\
                   To: Jane Doe <jane@example.com>\r\n\
                   Subject: chunked upload test\r\n\
                   MIME-Version: 1.0\r\n\
                   Content-Type: text/plain\r\n\r\n";

    let body: Vec<u8> = (0..body_len).map(|i| b'a' + (i % 26) as u8).collect();

    let mut raw = headers.as_bytes().to_vec();
    raw.extend_from_slice(&body);

    (raw, body)
}

fn message_to(canister_id: Principal, body_len: usize) -> (EmailMessage, Vec<u8>, Uuid) {
    let (raw, body) = raw_message(body_len);
    let id = Uuid::new_v4();

    let msg = EmailMessage {
        id,
        mail_from: email!("john@doe.com"),
        rcpt_to: vec![EmailAddress::from_str(&format!("jane@{canister_id}.icp0.io")).unwrap()],
        body: raw.into(),
    };

    (msg, body, id)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

// ---------------------------------------------------------------------------

/// The canister advertises chunking, and recipient probing maps reply codes the
/// way `resolve_recipient` expects - in particular 550 means "unknown mailbox".
#[ignore]
#[tokio::test]
async fn smtp_capabilities_and_validate() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    let canister_id = env.install(&env.init_arg(CANISTER_MAX_MESSAGE)).await?;
    let agent = delivery_agent(env.agent().await?, upload_cfg());

    // Capabilities must advertise a usable chunked protocol, or the gateway
    // treats the canister as legacy and refuses anything oversize.
    let caps: SmtpCapabilities = {
        let raw = env
            .pic
            .query_call(canister_id, env.sender, "smtp_capabilities", Encode!()?)
            .await
            .map_err(|e| anyhow::anyhow!("smtp_capabilities failed: {e}"))?;
        Decode!(&raw, SmtpCapabilities)?
    };
    assert_eq!(
        caps.upload_protocol_version,
        Some(SMTP_UPLOAD_PROTOCOL_VERSION)
    );
    assert!(caps.supports_chunked(), "{caps:?}");

    let from = email!("john@doe.com");
    let known = EmailAddress::from_str(&format!("jane@{canister_id}.icp0.io"))?;
    let unknown = EmailAddress::from_str(&format!("nobody@{canister_id}.icp0.io"))?;

    agent.resolve_recipient(&from, &known).await?;

    // 550 from the canister must surface as UnknownRecipient, not as a generic
    // permanent error - the SMTP layer answers 550 5.1.2 for this recipient only.
    let err = agent.resolve_recipient(&from, &unknown).await.unwrap_err();
    assert!(
        matches!(err, RecipientResolveError::UnknownRecipient),
        "{err:?}"
    );

    Ok(())
}

/// A message small enough for one ingress call takes the base protocol and
/// arrives intact.
#[ignore]
#[tokio::test]
async fn smtp_single_shot_delivery() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    let canister_id = env.install(&env.init_arg(CANISTER_MAX_MESSAGE)).await?;
    let agent = delivery_agent(env.agent().await?, single_shot_cfg());

    let (msg, body, id) = message_to(canister_id, 1024);
    agent.deliver_mail(test_meta(), Arc::new(msg)).await?;

    let delivered = env
        .delivered(canister_id, &id.to_string())
        .await?
        .expect("the canister recorded no delivery");

    assert_eq!(delivered.via, DeliveryPath::SingleShot);
    assert_eq!(delivered.body_len, body.len() as u64);
    assert_eq!(delivered.body_sha256, sha256(&body));
    assert!(
        delivered
            .headers
            .iter()
            .any(|h| h.name == "Subject" && h.value.contains("chunked upload test")),
        "{:?}",
        delivered.headers
    );

    Ok(())
}

/// The headline case: a message too large for one ingress call is uploaded in
/// chunks, committed, and reassembled by the canister byte for byte.
#[ignore]
#[tokio::test]
async fn smtp_chunked_delivery() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    let canister_id = env.install(&env.init_arg(CANISTER_MAX_MESSAGE)).await?;
    let agent = delivery_agent(env.agent().await?, upload_cfg());

    let (msg, body, id) = message_to(canister_id, CHUNKED_BODY);
    agent.deliver_mail(test_meta(), Arc::new(msg)).await?;

    let delivered = env
        .delivered(canister_id, &id.to_string())
        .await?
        .expect("the canister recorded no delivery");

    // Asserted from the CANISTER side: the gateway really chunked, and the
    // canister really reassembled. Inferring this from gateway metrics would
    // miss a bug where the canister assembled from a single call.
    assert_eq!(delivered.via, DeliveryPath::Chunked);
    assert_eq!(
        delivered.chunks_seen,
        CHUNKED_BODY.div_ceil(64 * 1024) as u32
    );

    assert_eq!(delivered.body_len, body.len() as u64);
    assert_eq!(
        delivered.body_sha256,
        sha256(&body),
        "prefix matches: {}, suffix matches: {}",
        delivered.body_prefix == body[..64],
        delivered.body_suffix == body[body.len() - 64..],
    );

    // The upload buffers must be released once the commit lands.
    let stats = env.stats(canister_id).await?;
    assert_eq!(stats.delivered, 1);
    assert_eq!(stats.open_uploads, 0);
    assert_eq!(stats.reserved_bytes, 0);

    Ok(())
}

/// The two transfer paths must be indistinguishable to the canister. Nothing in
/// the type system enforces that, and the chunked path is the less-exercised one.
#[ignore]
#[tokio::test]
async fn smtp_paths_agree() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    let canister_id = env.install(&env.init_arg(CANISTER_MAX_MESSAGE)).await?;

    let (raw, body) = raw_message(CHUNKED_BODY);
    let rcpt = EmailAddress::from_str(&format!("jane@{canister_id}.icp0.io"))?;

    let mut records = vec![];
    for cfg in [upload_cfg(), single_shot_cfg()] {
        let agent = delivery_agent(env.agent().await?, cfg);
        // Distinct ids: the canister keys uploads and dedup by (caller, id).
        let id = Uuid::new_v4();

        agent
            .deliver_mail(
                test_meta(),
                Arc::new(EmailMessage {
                    id,
                    mail_from: email!("john@doe.com"),
                    rcpt_to: vec![rcpt.clone()],
                    body: raw.clone().into(),
                }),
            )
            .await?;

        records.push(
            env.delivered(canister_id, &id.to_string())
                .await?
                .expect("no delivery recorded"),
        );
    }

    let (chunked, single) = (&records[0], &records[1]);
    assert_eq!(chunked.via, DeliveryPath::Chunked);
    assert_eq!(single.via, DeliveryPath::SingleShot);

    // Everything except how it got there must be identical.
    assert_eq!(chunked.body_sha256, single.body_sha256);
    assert_eq!(chunked.body_sha256, sha256(&body));
    assert_eq!(chunked.body_len, single.body_len);
    assert_eq!(chunked.headers, single.headers);
    assert_eq!(chunked.envelope, single.envelope);

    Ok(())
}

/// A commit whose reply is lost must not become a duplicate delivery: replaying
/// it returns the memoized verdict instead of failing with "unknown upload".
#[ignore]
#[tokio::test]
async fn smtp_commit_is_idempotent() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    let canister_id = env.install(&env.init_arg(CANISTER_MAX_MESSAGE)).await?;
    let agent = delivery_agent(env.agent().await?, upload_cfg());

    let (msg, body, id) = message_to(canister_id, CHUNKED_BODY);
    agent.deliver_mail(test_meta(), Arc::new(msg)).await?;

    let before = env.stats(canister_id).await?;
    assert_eq!(before.delivered, 1);

    // Replay the commit exactly as a retry after a lost reply would.
    let commit = SmtpUploadCommit {
        version: SMTP_UPLOAD_PROTOCOL_VERSION,
        message_id: id.to_string(),
        body_sha256: vec![0; 32], // deliberately wrong - the memo must win
        total_chunks: 1,
    };

    let raw = env
        .pic
        .update_call(
            canister_id,
            env.sender,
            "smtp_upload_commit",
            Encode!(&commit)?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("replayed commit failed: {e}"))?;

    let resp = Decode!(&raw, SmtpResponse)?;
    assert!(
        matches!(resp, SmtpResponse::Ok(_)),
        "a replayed commit must return the memoized verdict, got {resp:?}"
    );

    let after = env.stats(canister_id).await?;
    assert_eq!(after.delivered, 1, "the message was delivered twice");

    // ...and the body is still the original one.
    let delivered = env.delivered(canister_id, &id.to_string()).await?.unwrap();
    assert_eq!(delivered.body_sha256, sha256(&body));

    Ok(())
}

/// An unauthorized gateway must be bounced, not retried forever. This is why
/// the canister answers 530 instead of trapping: a trap would map to a
/// temporary failure.
#[ignore]
#[tokio::test]
async fn smtp_unauthorized_caller_is_rejected() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    let canister_id = env.install(&env.init_arg(CANISTER_MAX_MESSAGE)).await?;
    let agent = delivery_agent(env.agent_unauthorized().await?, single_shot_cfg());

    let (msg, _, id) = message_to(canister_id, 1024);
    let err = agent
        .deliver_mail(test_meta(), Arc::new(msg))
        .await
        .unwrap_err();

    assert!(matches!(err, DeliveryError::Permanent(_)), "{err:?}");
    assert!(env.delivered(canister_id, &id.to_string()).await?.is_none());

    Ok(())
}

/// A message larger than the canister advertises is refused without uploading
/// anything - the gateway checks the advertised ceiling before it starts.
#[ignore]
#[tokio::test]
async fn smtp_oversize_is_refused_before_uploading() -> anyhow::Result<()> {
    let env = SmtpTestEnv::new().await?;
    // Advertise less than the message we are about to send.
    let canister_id = env.install(&env.init_arg(100_000)).await?;
    let agent = delivery_agent(env.agent().await?, upload_cfg());

    let (msg, _, id) = message_to(canister_id, CHUNKED_BODY);
    let err = agent
        .deliver_mail(test_meta(), Arc::new(msg))
        .await
        .unwrap_err();

    assert!(matches!(err, DeliveryError::Permanent(_)), "{err:?}");
    assert!(env.delivered(canister_id, &id.to_string()).await?.is_none());

    let stats = env.stats(canister_id).await?;
    assert_eq!(stats.open_uploads, 0);
    assert_eq!(stats.reserved_bytes, 0, "no chunk should have been stored");

    Ok(())
}

mod full_stack;
