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

#[cfg(test)]
mod test {
    use super::*;

    use ic_custom_domains_canister_api::TaskKind;
    use prometheus::core::Collector;
    use strum::IntoEnumIterator;

    use crate::state::{RegistrationStatusLabel, TaskStatus};

    /// Every metric family the canister is expected to expose, as
    /// `(exported name, help text, variable label names in declaration order)`.
    ///
    /// Scrapers, dashboards and alerts are all keyed off these strings, so they are part of
    /// the canister's observable interface: changing one has to be a deliberate act.
    const EXPECTED_METRICS: &[(&str, &str, &[&str])] = &[
        (
            "canister_api_calls",
            "Total number of API calls made to the canister by status, task_kind, and error (in case of failure).",
            &["method", "status", "task_kind", "error"],
        ),
        (
            "cycle_balance",
            "Amount of funds available in the canister.",
            &[],
        ),
        (
            "domains_nearing_expiration",
            "Number of domains nearing the expiration threshold.",
            &[],
        ),
        (
            "domains_total",
            "Total number of domains by status.",
            &["registration_status"],
        ),
        (
            "last_stale_domains_cleanup_time",
            "The Unix timestamp (seconds) of the last stale domains cleanup",
            &[],
        ),
        (
            "last_upgrade_time",
            "The Unix timestamp (seconds) of the last successful canister upgrade",
            &[],
        ),
        (
            "stable_memory_bytes",
            "Size of the stable memory allocated by this canister in bytes.",
            &[],
        ),
        (
            "task_failures",
            "Total number of task failures by error types.",
            &["task_kind", "error"],
        ),
        (
            "tasks_total",
            "Total number of tasks by kind and status",
            &["task_kind", "status"],
        ),
    ];

    /// The metrics that carry no labels and are therefore always exported, even before
    /// anything has been observed.
    const SCALAR_METRICS: &[&str] = &[
        "cycle_balance",
        "domains_nearing_expiration",
        "last_stale_domains_cleanup_time",
        "last_upgrade_time",
        "stable_memory_bytes",
    ];

    fn collectors(m: &CanisterMetrics) -> Vec<&dyn Collector> {
        vec![
            &m.canister_api_calls,
            &m.cycle_balance,
            &m.domains_nearing_expiration,
            &m.domains_total,
            &m.last_stale_domains_cleanup_time,
            &m.last_upgrade_time,
            &m.stable_memory_size,
            &m.task_failures,
            &m.tasks_total,
        ]
    }

    /// Touches every metric so that even the label-vector families end up in `gather()`.
    fn populate(m: &CanisterMetrics) {
        m.canister_api_calls
            .with_label_values(&[
                TRY_ADD_TASK_FUNC,
                FAILURE_STATUS,
                "issue",
                "domain_not_found",
            ])
            .inc();
        m.canister_api_calls
            .with_label_values(&[FETCH_NEXT_TASK_FUNC, SUCCESS_STATUS, "", ""])
            .inc_by(2.0);
        m.cycle_balance.set(1234.0);
        m.domains_nearing_expiration.set(3);
        m.domains_total.with_label_values(&["registered"]).set(7.0);
        m.last_stale_domains_cleanup_time.set(0);
        m.last_upgrade_time.set(1_700_000_000);
        m.stable_memory_size.set(65536.0);
        m.task_failures
            .with_label_values(&["renew", "rate_limited"])
            .inc();
        m.tasks_total
            .with_label_values(&["issue", "pending"])
            .set(2.0);
    }

    fn gathered_names(m: &CanisterMetrics) -> Vec<String> {
        m.registry
            .gather()
            .iter()
            .map(|f| f.name().to_string())
            .collect()
    }

    fn encode(m: &CanisterMetrics) -> String {
        TextEncoder::new()
            .encode_to_string(&m.registry.gather())
            .expect("encoding a populated registry must not fail")
    }

    #[test]
    fn test_metric_descriptors_are_stable() {
        let m = CanisterMetrics::new().unwrap();

        let mut actual = collectors(&m)
            .iter()
            .flat_map(|c| c.desc())
            .map(|d| (d.fq_name.clone(), d.help.clone(), d.variable_labels.clone()))
            .collect::<Vec<_>>();
        actual.sort();

        let expected = EXPECTED_METRICS
            .iter()
            .map(|(name, help, labels)| {
                (
                    (*name).to_string(),
                    (*help).to_string(),
                    labels.iter().map(|l| (*l).to_string()).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    /// The struct field is `stable_memory_size` but the metric it registers is deliberately
    /// named after its unit; scrapers see the latter.
    #[test]
    fn test_stable_memory_metric_is_exported_in_bytes() {
        let m = CanisterMetrics::new().unwrap();
        assert_eq!(
            m.stable_memory_size.desc()[0].fq_name,
            "stable_memory_bytes"
        );
        m.stable_memory_size
            .set(2.0 * WASM_PAGE_SIZE_IN_BYTES as f64);
        assert!(encode(&m).contains("stable_memory_bytes 131072\n"));
    }

    /// Prometheus prunes label-vector families that have no series yet, so a freshly created
    /// registry only exposes the scalar metrics until the first observation.
    #[test]
    fn test_fresh_registry_exports_only_scalar_metrics() {
        let m = CanisterMetrics::new().unwrap();
        assert_eq!(gathered_names(&m), SCALAR_METRICS);

        m.domains_total.with_label_values(&["expired"]).set(0.0);
        assert!(gathered_names(&m).contains(&"domains_total".to_string()));
    }

    #[test]
    fn test_all_families_are_exported_once_populated() {
        let m = CanisterMetrics::new().unwrap();
        populate(&m);

        let expected = EXPECTED_METRICS
            .iter()
            .map(|(name, _, _)| (*name).to_string())
            .collect::<Vec<_>>();
        // `gather()` is name-ordered, so this also pins that there are no duplicate families.
        assert_eq!(gathered_names(&m), expected);
    }

    #[test]
    fn test_encoded_output_matches_prometheus_text_format() {
        let m = CanisterMetrics::new().unwrap();
        populate(&m);

        let expected = "\
# HELP canister_api_calls Total number of API calls made to the canister by status, task_kind, and error (in case of failure).
# TYPE canister_api_calls counter
canister_api_calls{error=\"\",method=\"fetch_next_task\",status=\"success\",task_kind=\"\"} 2
canister_api_calls{error=\"domain_not_found\",method=\"try_add_task\",status=\"failure\",task_kind=\"issue\"} 1
# HELP cycle_balance Amount of funds available in the canister.
# TYPE cycle_balance gauge
cycle_balance 1234
# HELP domains_nearing_expiration Number of domains nearing the expiration threshold.
# TYPE domains_nearing_expiration gauge
domains_nearing_expiration 3
# HELP domains_total Total number of domains by status.
# TYPE domains_total gauge
domains_total{registration_status=\"registered\"} 7
# HELP last_stale_domains_cleanup_time The Unix timestamp (seconds) of the last stale domains cleanup
# TYPE last_stale_domains_cleanup_time gauge
last_stale_domains_cleanup_time 0
# HELP last_upgrade_time The Unix timestamp (seconds) of the last successful canister upgrade
# TYPE last_upgrade_time gauge
last_upgrade_time 1700000000
# HELP stable_memory_bytes Size of the stable memory allocated by this canister in bytes.
# TYPE stable_memory_bytes gauge
stable_memory_bytes 65536
# HELP task_failures Total number of task failures by error types.
# TYPE task_failures counter
task_failures{error=\"rate_limited\",task_kind=\"renew\"} 1
# HELP tasks_total Total number of tasks by kind and status
# TYPE tasks_total gauge
tasks_total{status=\"pending\",task_kind=\"issue\"} 2
";

        assert_eq!(encode(&m), expected);
    }

    #[test]
    fn test_api_call_series_are_keyed_by_the_full_label_tuple() {
        let m = CanisterMetrics::new().unwrap();

        let ok = [FETCH_NEXT_TASK_FUNC, SUCCESS_STATUS, "issue", ""];
        let failed = [FETCH_NEXT_TASK_FUNC, FAILURE_STATUS, "issue", "timeout"];

        m.canister_api_calls.with_label_values(&ok).inc();
        m.canister_api_calls.with_label_values(&ok).inc();
        m.canister_api_calls.with_label_values(&failed).inc();

        assert_eq!(m.canister_api_calls.with_label_values(&ok).get(), 2.0);
        assert_eq!(m.canister_api_calls.with_label_values(&failed).get(), 1.0);

        // Two distinct series, and the status label is what separates them.
        let text = encode(&m);
        assert!(
            text.contains(
                "canister_api_calls{error=\"\",method=\"fetch_next_task\",status=\"success\",task_kind=\"issue\"} 2\n"
            ),
            "unexpected output:\n{text}"
        );
        assert!(
            text.contains(
                "canister_api_calls{error=\"timeout\",method=\"fetch_next_task\",status=\"failure\",task_kind=\"issue\"} 1\n"
            ),
            "unexpected output:\n{text}"
        );
        assert_eq!(text.matches("\ncanister_api_calls{").count(), 2);
    }

    #[test]
    fn test_label_cardinality_is_enforced() {
        let m = CanisterMetrics::new().unwrap();

        // Right arity for every vector metric.
        assert!(
            m.canister_api_calls
                .get_metric_with_label_values(&[
                    SUBMIT_TASK_RESULT_FUNC,
                    SUCCESS_STATUS,
                    "renew",
                    ""
                ])
                .is_ok()
        );
        assert!(
            m.domains_total
                .get_metric_with_label_values(&["registering"])
                .is_ok()
        );
        assert!(
            m.task_failures
                .get_metric_with_label_values(&["renew", "rate_limited"])
                .is_ok()
        );
        assert!(
            m.tasks_total
                .get_metric_with_label_values(&["renew", "in_progress"])
                .is_ok()
        );

        // Too few and too many label values are both rejected rather than silently padded.
        for wrong in [
            vec![],
            vec!["a"],
            vec!["a", "b"],
            vec!["a", "b", "c", "d", "e"],
        ] {
            assert!(
                m.canister_api_calls
                    .get_metric_with_label_values(&wrong)
                    .is_err(),
                "canister_api_calls accepted {wrong:?}"
            );
        }
        assert!(
            m.domains_total
                .get_metric_with_label_values(&["a", "b"])
                .is_err()
        );
        assert!(
            m.task_failures
                .get_metric_with_label_values(&["a"])
                .is_err()
        );
        assert!(m.tasks_total.get_metric_with_label_values(&["a"]).is_err());
    }

    /// Every metric is registered into its own `Registry`, never the process-wide default one.
    /// If that changed, a second `CanisterMetrics::new()` would fail with `AlreadyReg` and the
    /// thread-local initializer would trap the canister on upgrade.
    #[test]
    fn test_new_uses_a_private_registry() {
        let first = CanisterMetrics::new().expect("first instance");
        let second = CanisterMetrics::new().expect("second instance");

        first.domains_nearing_expiration.set(11);
        second.domains_nearing_expiration.set(22);
        assert!(encode(&first).contains("domains_nearing_expiration 11\n"));
        assert!(encode(&second).contains("domains_nearing_expiration 22\n"));

        let default = prometheus::default_registry().gather();
        for (name, _, _) in EXPECTED_METRICS {
            assert!(
                !default.iter().any(|f| f.name() == *name),
                "{name} leaked into the global default registry"
            );
        }
    }

    /// `export_metrics_as_http_response` clones the registry out of the thread-local before
    /// gathering, which only works because `Registry` is a handle to shared state.
    #[test]
    fn test_registry_clone_observes_later_updates() {
        let m = CanisterMetrics::new().unwrap();
        let cloned = m.registry.clone();

        m.domains_nearing_expiration.set(5);
        m.tasks_total
            .with_label_values(&["issue", "pending"])
            .set(1.0);

        let text = TextEncoder::new()
            .encode_to_string(&cloned.gather())
            .unwrap();
        assert!(text.contains("domains_nearing_expiration 5\n"), "{text}");
        assert!(
            text.contains("tasks_total{status=\"pending\",task_kind=\"issue\"} 1\n"),
            "{text}"
        );
    }

    /// The thread-local initializer `expect()`s, so a duplicate registration would trap the
    /// canister on its very first metrics access.
    #[test]
    fn test_metrics_thread_local_is_usable() {
        METRICS.with(|cell| {
            let m = cell.borrow();
            let mut names = gathered_names(&m);
            names.sort();
            assert_eq!(names, SCALAR_METRICS);

            m.task_failures
                .with_label_values(&["delete", "generic_failure"])
                .inc();
            assert!(
                encode(&m)
                    .contains("task_failures{error=\"generic_failure\",task_kind=\"delete\"} 1\n")
            );
        });
    }

    /// `recompute_metrics` feeds `TaskStatus::as_str_pair()` into `tasks_total` as
    /// `[task_kind, status]`. That only lines up because `as_str_pair` returns the *status*
    /// first and the *kind* second, which is the opposite of the metric's label order — so both
    /// halves of that contract are pinned here.
    ///
    /// NOTE: this pins the two *ends* of the contract (what `as_str_pair` returns, and what
    /// `tasks_total` declares), not the call site that joins them. `recompute_metrics` itself
    /// cannot run natively — `stable_size()`/`canister_cycle_balance()` trap off-wasm — so the
    /// argument order at metrics.rs:159 is reproduced below rather than exercised, and a swap
    /// made *there* would not turn this test red. Closing that requires PocketIC.
    #[test]
    fn test_task_status_label_pairs_match_the_declared_label_order() {
        let m = CanisterMetrics::new().unwrap();
        assert_eq!(
            m.tasks_total.desc()[0].variable_labels,
            vec!["task_kind".to_string(), "status".to_string()],
        );

        let expected = [
            (TaskStatus::Pending(TaskKind::Issue), "pending", "issue"),
            (TaskStatus::Pending(TaskKind::Renew), "pending", "renew"),
            (TaskStatus::Pending(TaskKind::Update), "pending", "update"),
            (TaskStatus::Pending(TaskKind::Delete), "pending", "delete"),
            (
                TaskStatus::InProgress(TaskKind::Issue),
                "in_progress",
                "issue",
            ),
            (
                TaskStatus::InProgress(TaskKind::Renew),
                "in_progress",
                "renew",
            ),
            (
                TaskStatus::InProgress(TaskKind::Update),
                "in_progress",
                "update",
            ),
            (
                TaskStatus::InProgress(TaskKind::Delete),
                "in_progress",
                "delete",
            ),
        ];

        for (i, (task_status, want_status, want_kind)) in expected.into_iter().enumerate() {
            let (status, task_kind) = task_status.as_str_pair();
            assert_eq!(
                (status, task_kind),
                (want_status, want_kind),
                "as_str_pair() must be (status, kind) for {task_status:?}"
            );
            // Mirrors the call in `recompute_metrics` (see the NOTE above: mirrored, not
            // executed — keep the two in sync by hand).
            m.tasks_total
                .with_label_values(&[task_kind, status])
                .set(i as f64 + 1.0);
        }

        let text = encode(&m);
        for (i, (kind, status)) in [
            ("issue", "pending"),
            ("renew", "pending"),
            ("update", "pending"),
            ("delete", "pending"),
            ("issue", "in_progress"),
            ("renew", "in_progress"),
            ("update", "in_progress"),
            ("delete", "in_progress"),
        ]
        .into_iter()
        .enumerate()
        {
            let want = format!(
                "tasks_total{{status=\"{status}\",task_kind=\"{kind}\"}} {}\n",
                i + 1
            );
            assert!(text.contains(&want), "missing {want:?} in:\n{text}");
        }
        // Eight distinct series, i.e. no two task statuses collapsed onto the same labels.
        assert_eq!(text.matches("\ntasks_total{").count(), 8);
    }

    /// `compute_stats` seeds every `RegistrationStatusLabel` with zero so dashboards never see a
    /// gap when a status happens to be empty. That only helps if a zero-valued gauge is actually
    /// exported, which is what this pins — along with the label spellings themselves.
    #[test]
    fn test_every_registration_status_label_is_exported_even_when_zero() {
        let m = CanisterMetrics::new().unwrap();

        let labels = RegistrationStatusLabel::iter()
            .map(<&'static str>::from)
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec!["registering", "registered", "expired", "failed"]
        );

        for label in &labels {
            m.domains_total.with_label_values(&[label]).set(0.0);
        }

        let text = encode(&m);
        for label in &labels {
            assert!(
                text.contains(&format!(
                    "domains_total{{registration_status=\"{label}\"}} 0\n"
                )),
                "zero-valued {label} series was pruned:\n{text}"
            );
        }
        assert_eq!(text.matches("\ndomains_total{").count(), labels.len());
    }

    /// The `method` and `status` label values end up verbatim in dashboards and alert rules.
    #[test]
    fn test_method_and_status_label_constants_are_stable() {
        assert_eq!(TRY_ADD_TASK_FUNC, "try_add_task");
        assert_eq!(FETCH_NEXT_TASK_FUNC, "fetch_next_task");
        assert_eq!(SUBMIT_TASK_RESULT_FUNC, "submit_task_result");
        assert_eq!(SUCCESS_STATUS, "success");
        assert_eq!(FAILURE_STATUS, "failure");
    }
}
