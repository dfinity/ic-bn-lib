use std::{borrow::BorrowMut, cell::RefCell};

use ic_cdk::{
    api::canister_cycle_balance,
    stable::{WASM_PAGE_SIZE_IN_BYTES, stable_size},
};
use ic_http_types::{HttpResponse, HttpResponseBuilder};
use prometheus::{
    CounterVec, Encoder, Gauge, GaugeVec, IntGauge, Registry, Result as PrometheusResult,
    TextEncoder, register_counter_vec_with_registry, register_gauge_vec_with_registry,
    register_gauge_with_registry, register_int_gauge_with_registry,
};

use crate::state::{UtcTimestamp, with_state};

pub const TRY_ADD_TASK_FUNC: &str = "try_add_task";
pub const FETCH_NEXT_TASK_FUNC: &str = "fetch_next_task";
pub const SUBMIT_TASK_RESULT_FUNC: &str = "submit_task_result";
pub const SUCCESS_STATUS: &str = "success";
pub const FAILURE_STATUS: &str = "failure";

thread_local! {
    pub static METRICS: RefCell<CanisterMetrics> = RefCell::new(CanisterMetrics::new().expect("failed to create Prometheus metrics"));
}

/// Represents all metrics collected in the canister
pub struct CanisterMetrics {
    pub registry: Registry, // Prometheus registry
    pub canister_api_calls: CounterVec,
    pub cycle_balance: Gauge,
    pub domains_nearing_expiration: IntGauge,
    pub domains_total: GaugeVec,
    pub last_upgrade_time: IntGauge,
    pub last_stale_domains_cleanup_time: IntGauge,
    pub task_failures: CounterVec,
    pub tasks_total: GaugeVec,
    pub stable_memory_size: Gauge,
}

impl CanisterMetrics {
    pub fn new() -> PrometheusResult<Self> {
        let registry = Registry::new();

        let cycle_balance = register_gauge_with_registry!(
            "cycle_balance",
            "Amount of funds available in the canister.",
            &registry
        )?;

        let canister_api_calls = register_counter_vec_with_registry!(
            "canister_api_calls",
            "Total number of API calls made to the canister by status, task_kind, and error (in case of failure).",
            &["method", "status", "task_kind", "error"],
            &registry,
        )?;

        let domains_total = register_gauge_vec_with_registry!(
            "domains_total",
            "Total number of domains by status.",
            &["registration_status"],
            &registry,
        )?;

        let domains_nearing_expiration = register_int_gauge_with_registry!(
            "domains_nearing_expiration",
            "Number of domains nearing the expiration threshold.",
            &registry,
        )?;

        let task_failures = register_counter_vec_with_registry!(
            "task_failures",
            "Total number of task failures by error types.",
            &["task_kind", "error"],
            &registry,
        )?;

        let tasks_total = register_gauge_vec_with_registry!(
            "tasks_total",
            "Total number of tasks by kind and status",
            &["task_kind", "status"],
            &registry,
        )?;

        let stable_memory_size = register_gauge_with_registry!(
            "stable_memory_bytes",
            "Size of the stable memory allocated by this canister in bytes.",
            &registry,
        )?;

        let last_upgrade_time = register_int_gauge_with_registry!(
            "last_upgrade_time",
            "The Unix timestamp (seconds) of the last successful canister upgrade",
            &registry,
        )?;

        let last_stale_domains_cleanup_time = register_int_gauge_with_registry!(
            "last_stale_domains_cleanup_time",
            "The Unix timestamp (seconds) of the last stale domains cleanup",
            &registry,
        )?;

        Ok(Self {
            registry,
            canister_api_calls,
            cycle_balance,
            domains_nearing_expiration,
            domains_total,
            last_upgrade_time,
            last_stale_domains_cleanup_time,
            task_failures,
            tasks_total,
            stable_memory_size,
        })
    }
}

pub fn export_metrics_as_http_response(now: UtcTimestamp) -> HttpResponse {
    // Certain metrics need to be recomputed
    recompute_metrics(now);

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let registry = METRICS.with(|cell| cell.borrow().registry.clone());
    let metrics_family = registry.gather();

    match encoder.encode(&metrics_family, &mut buffer) {
        Ok(()) => HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain")
            .with_body_and_content_length(buffer)
            .build(),
        Err(err) => {
            // Return an HTTP 500 error with detailed error information
            HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err:?}")).build()
        }
    }
}

pub fn recompute_metrics(now: UtcTimestamp) {
    METRICS.with(|cell| {
        let memory = (stable_size() * WASM_PAGE_SIZE_IN_BYTES) as f64;

        let mut cell = cell.borrow_mut();
        cell.stable_memory_size.borrow_mut().set(memory);
        cell.cycle_balance.set(canister_cycle_balance() as f64);

        let stats = with_state(|state| state.compute_stats(now));

        cell.domains_nearing_expiration
            .set(stats.domains_nearing_expiration as i64);

        for (status, count) in stats.registrations.iter() {
            let status: &'static str = status.into();
            cell.domains_total
                .with_label_values(&[status])
                .set(*count as f64);
        }

        for (task_status, count) in stats.tasks.iter() {
            let (status, task_kind) = task_status.as_str_pair();
            cell.tasks_total
                .with_label_values(&[task_kind, status])
                .set(*count as f64);
        }
    });
}
