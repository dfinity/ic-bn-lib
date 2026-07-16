use std::{fs, path::PathBuf, sync::Once};

use anyhow::{Context, anyhow};
use candid::{Decode, Encode};
use hex::encode;
use ic_custom_domains_canister_api::{
    FetchTaskResult, GetDomainEntryResult, GetDomainStatusResult, HasNextTaskResult, InitArg,
    InputTask, SubmitTaskResult, TaskKind, TaskResult, TryAddTaskResult,
};
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use tracing::info;

use crate::ic_agent::export::Principal;

static INIT_LOGGING: Once = Once::new();

pub fn init_logging() {
    INIT_LOGGING.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();

        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init()
            .expect("failed to init logger")
    });
}

#[allow(dead_code)]
pub struct TestEnv {
    pub pic: PocketIc,
    pub canister_id: Principal,
    pub sender: Principal,
    pub authorized_principal: Option<Principal>,
    pub controller: Principal,
}

#[allow(dead_code)]
impl TestEnv {
    pub async fn new(
        authorized_principal: Option<Principal>,
        sender: Principal,
    ) -> anyhow::Result<Self> {
        Self::new_with_wasm_env("CANISTER_WASM_PATH", authorized_principal, sender).await
    }

    /// Like `new`, but loads the canister WASM from a caller-specified env var instead of the
    /// default `CANISTER_WASM_PATH`. Useful for tests that need a WASM built with non-default
    /// features (e.g. the `bench` feature), which is built separately from the main test WASM.
    pub async fn new_with_wasm_env(
        wasm_path_env_var: &str,
        authorized_principal: Option<Principal>,
        sender: Principal,
    ) -> anyhow::Result<Self> {
        info!("pocket-ic server starting ...");

        let pic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

        info!("pocket-ic server started");

        let wasm_path = std::env::var(wasm_path_env_var)
            .unwrap_or_else(|_| panic!("{wasm_path_env_var} env var not set"));

        let wasm = fs::read(PathBuf::from(wasm_path)).context("unable to load WASM")?;

        let controller = Principal::from_text("2vxsx-fae")?;

        let canister_id = install_canister(&pic, controller, authorized_principal, wasm)
            .await
            .context("unable to install canister")?;

        Ok(Self {
            pic,
            canister_id,
            sender,
            authorized_principal,
            controller,
        })
    }

    /// Progress the Pocket IC by n blocks
    pub async fn ticks(&self, n: u32) {
        for _ in 0..n {
            self.pic.tick().await;
        }
    }

    pub async fn try_add_task(
        &self,
        domain: String,
        kind: TaskKind,
    ) -> anyhow::Result<TryAddTaskResult> {
        let task = InputTask {
            domain,
            kind,
            wildcard: None,
        };
        let arg = Encode!(&task)?;

        let result = self
            .pic
            .update_call(self.canister_id, self.sender, "try_add_task", arg)
            .await
            .map_err(|e| anyhow!("update call failed: {e}"))?;

        Decode!(&result, TryAddTaskResult).map_err(|_| anyhow!("decoding failed"))
    }

    pub async fn get_domain_status(&self, domain: &str) -> anyhow::Result<GetDomainStatusResult> {
        let arg = Encode!(&domain)?;

        let result = self
            .pic
            .query_call(self.canister_id, self.sender, "get_domain_status", arg)
            .await
            .map_err(|e| anyhow!("query call failed: {e}"))?;

        Decode!(&result, GetDomainStatusResult).map_err(|_| anyhow!("decoding failed"))
    }

    pub async fn get_domain_entry(&self, domain: &str) -> anyhow::Result<GetDomainEntryResult> {
        let arg = Encode!(&domain)?;

        let result = self
            .pic
            .query_call(self.canister_id, self.sender, "get_domain_entry", arg)
            .await
            .map_err(|e| anyhow!("query call failed: {e}"))?;

        Decode!(&result, GetDomainEntryResult).map_err(|_| anyhow!("decoding failed"))
    }

    pub async fn has_next_task(&self) -> anyhow::Result<HasNextTaskResult> {
        let arg = Encode!(&())?;

        let result = self
            .pic
            .query_call(self.canister_id, self.sender, "has_next_task", arg)
            .await
            .map_err(|e| anyhow!("query call failed: {e}"))?;

        Decode!(&result, HasNextTaskResult).map_err(|_| anyhow!("decoding failed"))
    }

    pub async fn submit_task_result(&self, result: TaskResult) -> anyhow::Result<SubmitTaskResult> {
        let arg = Encode!(&result)?;

        let result = self
            .pic
            .update_call(self.canister_id, self.sender, "submit_task_result", arg)
            .await
            .map_err(|e| anyhow!("update call failed: {e}"))?;

        Decode!(&result, SubmitTaskResult).map_err(|_| anyhow!("decoding failed"))
    }

    pub async fn fetch_next_task(&self) -> anyhow::Result<FetchTaskResult> {
        let arg = Encode!(&())?;

        let result = self
            .pic
            .update_call(self.canister_id, self.sender, "fetch_next_task", arg)
            .await
            .map_err(|e| anyhow!("update call failed: {e}"))?;

        Decode!(&result, FetchTaskResult).map_err(|_| anyhow!("decoding failed"))
    }
}

pub async fn install_canister(
    pic: &PocketIc,
    controller: Principal,
    authorized_principal: Option<Principal>,
    canister_wasm_module: Vec<u8>,
) -> anyhow::Result<Principal> {
    const CANISTER_INITIAL_CYCLES: u128 = 100_000_000_000_000;

    info!("installing canister ...");

    let canister_id = pic
        .create_canister_with_settings(Some(controller), None)
        .await;

    pic.add_cycles(canister_id, CANISTER_INITIAL_CYCLES).await;

    pic.install_canister(
        canister_id,
        canister_wasm_module,
        Encode!(&InitArg {
            authorized_principal,
        })?,
        Some(controller),
    )
    .await;

    let module_hash = pic
        .canister_status(canister_id, None)
        .await
        .map_err(|_| anyhow!("status call failed"))?
        .module_hash
        .ok_or_else(|| anyhow!("No module hash"))?;

    let hash_str = encode(module_hash);

    info!("canister with id={canister_id} installed, hash={hash_str}");

    Ok(canister_id)
}
