use ic_cdk::{
    api::{accept_message, msg_caller, time},
    init, inspect_message, post_upgrade, query, trap, update,
};
use ic_cdk_timers::set_timer_interval;
use ic_custom_domains_canister_api::{
    FetchTaskError, FetchTaskResult, GetDomainEntryError, GetDomainEntryResult,
    GetDomainStatusError, GetDomainStatusResult, GetLastChangeTimeError, GetLastChangeTimeResult,
    HasNextTaskError, HasNextTaskResult, InitArg, InputTask, ListCertificatesPageError,
    ListCertificatesPageInput, ListCertificatesPageResult, ListDomainsPageError,
    ListDomainsPageInput, ListDomainsPageResult, STALE_DOMAINS_CLEANUP_INTERVAL, SubmitTaskError,
    SubmitTaskResult, TaskResult, TryAddTaskError, TryAddTaskResult,
};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};

use crate::{
    metrics::{METRICS, export_metrics_as_http_response},
    state::{UtcTimestamp, export_expiring_domains_as_http_response, with_state, with_state_mut},
    storage::AUTHORIZED_PRINCIPAL,
};

pub mod metrics;
pub mod state;
pub mod storage;

// Inspect ingress messages in the pre-consensus phase and reject early, if the caller is unauthorized
#[inspect_message]
fn inspect_message() {
    if let Some(authorized_principal) = AUTHORIZED_PRINCIPAL.with(|p| *p.borrow())
        && authorized_principal != msg_caller()
    {
        trap("message_inspection_failed: unauthorized call");
    }

    accept_message()
}

pub fn get_time_secs() -> UtcTimestamp {
    time() / 1_000_000_000
}

fn validate_caller<T>(unauthorized_error: T) -> Result<(), T> {
    if let Some(authorized_principal) = AUTHORIZED_PRINCIPAL.with(|p| *p.borrow())
        && authorized_principal != msg_caller()
    {
        return Err(unauthorized_error);
    }

    Ok(())
}

#[init]
fn init(init_arg: InitArg) {
    // Initialize the authorized principal
    AUTHORIZED_PRINCIPAL.with(|p| *p.borrow_mut() = init_arg.authorized_principal);

    set_timer_interval(STALE_DOMAINS_CLEANUP_INTERVAL, async move || {
        let now = get_time_secs();
        with_state_mut(|state| state.cleanup_stale_domains(now));
    });

    METRICS.with(|cell| {
        let metrics = cell.borrow();
        metrics.last_upgrade_time.set(get_time_secs() as i64);
    });
}

// Run every time a canister is upgraded
#[post_upgrade]
fn post_upgrade(init_arg: InitArg) {
    // Run the same initialization logic
    init(init_arg);
}

#[query]
async fn get_domain_status(domain: String) -> GetDomainStatusResult {
    validate_caller(GetDomainStatusError::Unauthorized)?;
    let now = get_time_secs();
    with_state(|state| state.get_domain_status(domain, now))
}

#[query]
async fn get_domain_entry(domain: String) -> GetDomainEntryResult {
    validate_caller(GetDomainEntryError::Unauthorized)?;
    with_state(|state| state.get_domain_entry(domain))
}

#[query]
async fn has_next_task() -> HasNextTaskResult {
    validate_caller(HasNextTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state(|state| state.has_next_task(now))
}

#[update]
async fn fetch_next_task() -> FetchTaskResult {
    validate_caller(FetchTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state_mut(|state| state.fetch_next_task_with_metrics(now))
}

#[update]
async fn submit_task_result(result: TaskResult) -> SubmitTaskResult {
    validate_caller(SubmitTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state_mut(|state| state.submit_task_result_with_metrics(result, now))
}

#[update]
async fn try_add_task(task: InputTask) -> TryAddTaskResult {
    validate_caller(TryAddTaskError::Unauthorized)?;
    let now = get_time_secs();
    with_state_mut(|state| state.try_add_task_with_metrics(task, now))
}

#[query]
async fn get_last_change_time() -> GetLastChangeTimeResult {
    validate_caller(GetLastChangeTimeError::Unauthorized)?;
    with_state(|state| state.get_last_change_time())
}

#[query]
async fn list_certificates_page(input: ListCertificatesPageInput) -> ListCertificatesPageResult {
    validate_caller(ListCertificatesPageError::Unauthorized)?;
    with_state(|state| state.list_certificates_page(input))
}

#[query]
async fn list_domains_page(input: ListDomainsPageInput) -> ListDomainsPageResult {
    validate_caller(ListDomainsPageError::Unauthorized)?;
    with_state(|state| state.list_domains_page(input))
}

#[query]
fn http_request(request: HttpRequest) -> HttpResponse {
    let now = get_time_secs();
    match request.path() {
        "/metrics" => export_metrics_as_http_response(now),
        "/expired_domains" => export_expiring_domains_as_http_response(now),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs::read_to_string, path::PathBuf};

    use candid_parser::utils::{CandidSource, service_equal};

    use super::*;

    fn source_to_str(source: &CandidSource) -> String {
        match source {
            CandidSource::File(f) => read_to_string(f).unwrap_or_else(|_| "".to_string()),
            CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_equal(new_name: &str, new: CandidSource, old_name: &str, old: CandidSource) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);

        match service_equal(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{new_name} is not compatible with {old_name}!\n\n\
                    {new_name}:\n{new_str}\n\n\
                    {old_name}:\n{old_str}\n"
                );
                panic!("Candid interface mismatch: {e:?}");
            }
        }
    }

    #[test]
    fn check_candid_interface_compatibility() {
        candid::export_service!();

        let new_interface = __export_service();

        // check the public interface against the actual one
        let canister_did = "canister_backend.did";
        let old_interface =
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(canister_did);

        check_service_equal(
            "actual candid interface",
            candid_parser::utils::CandidSource::Text(&new_interface),
            "declared candid interface in {canister_did} file",
            candid_parser::utils::CandidSource::File(old_interface.as_path()),
        );
    }
}
