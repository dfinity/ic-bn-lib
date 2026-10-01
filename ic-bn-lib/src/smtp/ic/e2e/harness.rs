//! PocketIC harness for the SMTP E2E tests.
//!
//! `custom_domains::tests::TestEnv` cannot be reused: it is private to that
//! module and its installer hard-codes the custom-domains `InitArg`.
//!
//! The canister-side types below are **mirrors** of the ones in
//! `smtp/canister/src/types.rs`. The canister is `crate-type = ["cdylib"]`, so
//! there is no Rust API to import - Candid matches records by field-name hash,
//! not by declaration order, so a structurally equal mirror is enough. The
//! protocol types themselves are deliberately NOT mirrored: those come from
//! `crate::smtp::ic::candid`, which is the whole point of the exercise.

use std::{path::PathBuf, sync::Once};

use anyhow::{Context, anyhow};
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_agent::{Agent, Identity, identity::BasicIdentity};
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use tracing::info;
use url::Url;

use crate::{
    custom_domains::LooksUpCustomDomain,
    http::Client,
    smtp::ic::candid::{Envelope, Header},
};

/// Env var holding the path to the PoC canister wasm, exported by `run_tests.sh`.
const WASM_PATH_ENV: &str = "SMTP_CANISTER_WASM_PATH";

const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;

static INIT_LOGGING: Once = Once::new();

/// Unlike the custom-domains helper this must not `expect()` on the result:
/// with `--test-threads=1` those tests share a binary with these and whichever
/// runs second would panic on an already-installed global subscriber.
pub fn init_logging() {
    INIT_LOGGING.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();

        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();
    });
}

// ---------------------------------------------------------------------------
// Mirrors of the canister's non-protocol types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct InitArg {
    pub authorized: Principal,
    pub mailboxes: Vec<String>,
    pub max_message_size: u64,
    pub max_open_uploads: u32,
    pub max_buffered_bytes: u64,
    pub upload_ttl_secs: u64,
}

#[derive(Clone, Copy, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub enum DeliveryPath {
    SingleShot,
    Chunked,
}

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Delivered {
    pub envelope: Envelope,
    pub headers: Vec<Header>,
    pub gateway_flags: Option<Vec<String>>,
    pub body_len: u64,
    pub body_sha256: Vec<u8>,
    pub body_prefix: Vec<u8>,
    pub body_suffix: Vec<u8>,
    pub chunks_seen: u32,
    pub via: DeliveryPath,
}

#[derive(Clone, Copy, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct Stats {
    pub delivered: u64,
    pub open_uploads: u64,
    pub reserved_bytes: u64,
    pub rejected: u64,
}

// ---------------------------------------------------------------------------
// Gateway stubs
// ---------------------------------------------------------------------------

/// Answers the `.well-known/ic-smtp-canister-id` probe with a 404, so the
/// gateway falls back to addressing the app canister directly.
///
/// Returns `Ok(404)` rather than `Err`: an error would be a transport failure,
/// which is not what "this canister has no dedicated SMTP canister" looks like.
#[derive(Debug)]
pub struct Stub404Client;

#[async_trait::async_trait]
impl Client for Stub404Client {
    async fn execute(&self, _req: reqwest::Request) -> Result<reqwest::Response, reqwest::Error> {
        Ok(reqwest::Response::from(
            http::response::Builder::new().status(404).body("").unwrap(),
        ))
    }
}

/// Recipients are addressed `user@<principal>.icp0.io`, so the custom-domain
/// path is never taken.
#[derive(Debug)]
pub struct NoCustomDomains;

impl LooksUpCustomDomain for NoCustomDomains {
    fn lookup_custom_domain(&self, _hostname: &fqdn::Fqdn) -> Option<Principal> {
        None
    }
}

// ---------------------------------------------------------------------------
// The environment
// ---------------------------------------------------------------------------

pub struct SmtpTestEnv {
    pub pic: PocketIc,
    pub gateway_url: Url,
    /// Identity the canister is told to authorize.
    pub identity_key: [u8; 32],
    pub sender: Principal,
}

impl SmtpTestEnv {
    /// Boots PocketIC with an HTTP gateway so a real `ic_agent::Agent` can
    /// drive it.
    ///
    /// The NNS subnet is required: `pic.root_key()` returns `None` without one,
    /// and the agent cannot verify anything.
    pub async fn new() -> anyhow::Result<Self> {
        init_logging();

        let mut pic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

        // Also starts auto-progress, so `tick()` is no longer how time moves.
        let gateway_url = pic.make_live_with_params(None, None, None, None).await;
        info!("PocketIC HTTP gateway at {gateway_url}");

        let identity_key = [7u8; 32];
        let sender = BasicIdentity::from_raw_key(&identity_key)
            .sender()
            .map_err(|e| anyhow!("unable to derive sender: {e}"))?;

        Ok(Self {
            pic,
            gateway_url,
            identity_key,
            sender,
        })
    }

    /// An agent signing as the authorized gateway.
    pub async fn agent(&self) -> anyhow::Result<Agent> {
        self.agent_for(BasicIdentity::from_raw_key(&self.identity_key))
            .await
    }

    /// An agent signing as someone else, for the unauthorized case.
    pub async fn agent_unauthorized(&self) -> anyhow::Result<Agent> {
        self.agent_for(BasicIdentity::from_raw_key(&[9u8; 32]))
            .await
    }

    async fn agent_for(&self, identity: impl Identity + 'static) -> anyhow::Result<Agent> {
        let agent = Agent::builder()
            .with_url(self.gateway_url.clone())
            .with_identity(identity)
            .build()
            .context("unable to build the agent")?;

        agent.set_root_key(
            self.pic
                .root_key()
                .await
                .ok_or_else(|| anyhow!("no root key - is the NNS subnet missing?"))?,
        );

        Ok(agent)
    }

    /// Installs a fresh PoC canister. Callable repeatedly - each test that
    /// wants isolation gets its own.
    pub async fn install(&self, arg: &InitArg) -> anyhow::Result<Principal> {
        let wasm_path = std::env::var(WASM_PATH_ENV)
            .with_context(|| format!("{WASM_PATH_ENV} is not set - run via ./run_tests.sh"))?;

        let wasm = std::fs::read(PathBuf::from(&wasm_path))
            .with_context(|| format!("unable to read the canister wasm at {wasm_path}"))?;

        let canister_id = self.pic.create_canister().await;
        self.pic
            .add_cycles(canister_id, CANISTER_INITIAL_CYCLES)
            .await;
        self.pic
            .install_canister(canister_id, wasm, Encode!(arg)?, None)
            .await;

        info!("PoC SMTP canister installed as {canister_id}");
        Ok(canister_id)
    }

    /// Default config: authorizes this env's identity and accepts `jane`.
    pub fn init_arg(&self, max_message_size: u64) -> InitArg {
        InitArg {
            authorized: self.sender,
            mailboxes: vec!["jane".to_string()],
            max_message_size,
            max_open_uploads: 8,
            max_buffered_bytes: 64 * 1024 * 1024,
            upload_ttl_secs: 600,
        }
    }

    pub async fn delivered(
        &self,
        canister_id: Principal,
        message_id: &str,
    ) -> anyhow::Result<Option<Delivered>> {
        let res = self
            .pic
            .query_call(
                canister_id,
                self.sender,
                "poc_delivered",
                Encode!(&message_id.to_string())?,
            )
            .await
            .map_err(|e| anyhow!("poc_delivered failed: {e}"))?;

        Ok(Decode!(&res, Option<Delivered>)?)
    }

    pub async fn stats(&self, canister_id: Principal) -> anyhow::Result<Stats> {
        let res = self
            .pic
            .query_call(canister_id, self.sender, "poc_stats", Encode!()?)
            .await
            .map_err(|e| anyhow!("poc_stats failed: {e}"))?;

        Ok(Decode!(&res, Stats)?)
    }
}
