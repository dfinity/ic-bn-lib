//! Measures how many WASM instructions `CanisterState`'s full-scan methods
//! (`has_next_task`, `fetch_next_task`, `compute_stats`, `domains_nearing_expiration`,
//! `cleanup_stale_domains`) consume as a function of the number of domains held, then
//! extrapolates the domain count at which each would hit the IC's 40B-instruction
//! per-message budget.
//!
//! Requires a canister WASM built with the `bench` feature (see `BENCH_CANISTER_WASM_PATH`
//! in `run_tests.sh`), which adds test-only endpoints to seed synthetic domains directly into
//! stable storage and to report `ic_cdk::api::instruction_counter()` deltas around a call.

use anyhow::anyhow;
use candid::{CandidType, Decode, Encode, Principal};
use serde::Deserialize;
use tracing::info;

use super::helpers::{TestEnv, init_logging};

/// Per-message instruction limit enforced by the IC for a single update/query call execution.
const INSTRUCTION_LIMIT: u64 = 40_000_000_000;

/// Domain counts to sample. Kept well below `MAX_STORED_DOMAINS` (1_000_000) so the run stays
/// fast; the linear scaling law measured over these points is then extrapolated further.
const SAMPLE_POINTS: [u64; 5] = [0, 5_000, 20_000, 50_000, 100_000];

/// Synthetic domains seeded per `bench_seed_domains` call, chosen to keep each seeding call
/// itself comfortably under the instruction limit.
const SEED_CHUNK: u64 = 20_000;

/// Mirrors `ic_custom_domains_canister::bench::BenchMethod`. Candid matches enum variants by
/// name, not declaration order, so this only needs matching variant names.
#[derive(CandidType, Deserialize, Clone, Copy, Debug)]
enum BenchMethod {
    HasNextTask,
    FetchNextTask,
    ComputeStats,
    DomainsNearingExpiration,
    CleanupStaleDomains,
}

const METHODS: [(&str, BenchMethod); 5] = [
    ("has_next_task", BenchMethod::HasNextTask),
    ("fetch_next_task", BenchMethod::FetchNextTask),
    ("compute_stats", BenchMethod::ComputeStats),
    (
        "domains_nearing_expiration",
        BenchMethod::DomainsNearingExpiration,
    ),
    ("cleanup_stale_domains", BenchMethod::CleanupStaleDomains),
];

async fn seed_up_to(env: &TestEnv, target: u64, mut current: u64) -> anyhow::Result<u64> {
    while current < target {
        let chunk = (target - current).min(SEED_CHUNK);
        let arg = Encode!(&chunk, &current)?;

        env.pic
            .update_call(env.canister_id, env.sender, "bench_seed_domains", arg)
            .await
            .map_err(|e| anyhow!("bench_seed_domains failed: {e}"))?;

        current += chunk;
    }

    Ok(current)
}

async fn measure(env: &TestEnv, method: BenchMethod) -> anyhow::Result<u64> {
    let arg = Encode!(&method)?;

    let result = env
        .pic
        .update_call(env.canister_id, env.sender, "bench_measure", arg)
        .await
        .map_err(|e| anyhow!("bench_measure failed: {e}"))?;

    Decode!(&result, u64).map_err(|e| anyhow!("failed to decode bench_measure result: {e}"))
}

/// Ordinary least-squares fit of `instructions ~= intercept + slope * domains`.
fn linear_fit(points: &[(f64, f64)]) -> (f64, f64) {
    let n = points.len() as f64;
    let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
    let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
    let sum_xx: f64 = points.iter().map(|(x, _)| x * x).sum();
    let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();

    let slope = n.mul_add(sum_xy, -(sum_x * sum_y)) / n.mul_add(sum_xx, -(sum_x * sum_x));
    let intercept = slope.mul_add(-sum_x, sum_y) / n;

    (slope, intercept)
}

#[ignore]
#[tokio::test]
async fn test_instruction_scaling_with_domain_count() -> anyhow::Result<()> {
    init_logging();

    let sender = Principal::from_text("oqjvn-fqaaa-aaaab-qab5q-cai")?;
    let env = TestEnv::new_with_wasm_env("BENCH_CANISTER_WASM_PATH", Some(sender), sender).await?;

    let mut current: u64 = 0;
    // instructions[method_index][sample_index]
    let mut instructions: Vec<Vec<u64>> = vec![Vec::new(); METHODS.len()];

    for &n in &SAMPLE_POINTS {
        current = seed_up_to(&env, n, current).await?;

        for (i, (name, method)) in METHODS.iter().enumerate() {
            let used = measure(&env, *method).await?;
            info!("domains={n:>8} {name:<28} instructions={used}");
            instructions[i].push(used);

            assert!(
                used < INSTRUCTION_LIMIT,
                "{name} used {used} instructions with {n} domains, exceeding the {INSTRUCTION_LIMIT} budget"
            );
        }
    }

    info!("--- extrapolation to the 40B instruction budget ---");
    for (i, (name, _)) in METHODS.iter().enumerate() {
        let points: Vec<(f64, f64)> = SAMPLE_POINTS
            .iter()
            .zip(&instructions[i])
            .map(|(&n, &used)| (n as f64, used as f64))
            .collect();

        let (per_domain, fixed) = linear_fit(&points);
        let max_domains = if per_domain > 0.0 {
            ((INSTRUCTION_LIMIT as f64 - fixed) / per_domain) as i64
        } else {
            i64::MAX
        };

        info!(
            "{name}: ~{per_domain:.2} instructions/domain + {fixed:.0} fixed overhead => \
             estimated max ~{max_domains} domains before hitting the {INSTRUCTION_LIMIT} instruction budget"
        );
    }

    Ok(())
}
