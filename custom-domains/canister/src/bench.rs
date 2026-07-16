//! Test-only endpoints for measuring how many WASM instructions `CanisterState`'s
//! full-scan methods consume as a function of the number of domains held.
//!
//! Gated behind the `bench` feature so none of this ships in a production build: it lets
//! the caller inject arbitrary synthetic domain entries directly into stable storage,
//! bypassing every validation `try_add_task` normally applies.

use candid::CandidType;
use ic_cdk::{api::instruction_counter, update};
use serde::Deserialize;

use crate::{
    get_time_secs,
    state::{DomainEntry, with_state, with_state_mut},
};

#[derive(CandidType, Deserialize, Clone, Copy, Debug)]
pub enum BenchMethod {
    HasNextTask,
    FetchNextTask,
    ComputeStats,
    DomainsNearingExpiration,
    CleanupStaleDomains,
}

/// Inserts `count` synthetic domain entries (keyed `bench-{start_index..start_index+count}.test`)
/// with a certificate validity window far from expiration/renewal, so the seeded entries are
/// inert: scanning them costs instructions, but doesn't trigger renewals or removals, keeping
/// repeated measurements against the same seeded set stable and comparable.
#[update]
fn bench_seed_domains(count: u64, start_index: u64) {
    let now = get_time_secs();

    with_state_mut(|state| {
        for i in 0..count {
            let mut entry = DomainEntry::new(None, now);
            entry.not_before = Some(now.saturating_sub(1_000_000));
            entry.not_after = Some(now + 1_000_000_000);
            state
                .domains
                .insert(format!("bench-{}.test", start_index + i), entry);
        }
    });
}

#[update]
fn bench_domain_count() -> u64 {
    with_state(|state| state.domains.len())
}

/// Runs `method` once against the current state and returns the number of WASM instructions
/// it consumed (via `ic_cdk::api::instruction_counter`), isolated from the seeding cost above.
#[update]
fn bench_measure(method: BenchMethod) -> u64 {
    let now = get_time_secs();
    let start = instruction_counter();

    with_state_mut(|state| match method {
        BenchMethod::HasNextTask => {
            let _ = state.has_next_task(now);
        }
        BenchMethod::FetchNextTask => {
            let _ = state.fetch_next_task(now);
        }
        BenchMethod::ComputeStats => {
            let _ = state.compute_stats(now);
        }
        BenchMethod::DomainsNearingExpiration => {
            let _ = state.domains_nearing_expiration(now);
        }
        BenchMethod::CleanupStaleDomains => state.cleanup_stale_domains(now),
    });

    instruction_counter() - start
}
