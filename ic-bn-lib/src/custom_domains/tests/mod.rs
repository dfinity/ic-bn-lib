use anyhow::anyhow;
use candid::{Decode, Encode, Principal};
use pocket_ic::nonblocking::PocketIc;
use std::time::Duration;
use tracing::info;

use crate::custom_domains::canister::api::{
    CERTIFICATE_VALIDITY_FRACTION, DomainStatus, HasNextTaskError, HasNextTaskResult,
    IssueCertificateOutput, MAX_TASK_FAILURES, MIN_TASK_RETRY_DELAY, RegistrationStatus,
    STALE_DOMAINS_CLEANUP_INTERVAL, ScheduledTask as ScheduledTaskApi, ScheduledTask,
    SubmitTaskError, TASK_TIMEOUT, TaskFailReason, TaskKind, TaskOutcome, TaskOutput, TaskResult,
    UNREGISTERED_DOMAIN_EXPIRATION_TIME,
};
use helpers::{TestEnv, init_logging};

const TICKS_AFTER_TIME_ADVANCE: u32 = 5; // make pocket-ic progress by some blocks to ensure time advancement takes place
const CERTIFICATE_VALIDITY_DURATION_SECS: u64 = 100_000;
const RATE_LIMIT_MAX_ATTEMPTS: u32 = 25;

mod helpers;

#[tokio::test]
async fn test_canister_authorization() -> anyhow::Result<()> {
    init_logging();

    let sender = Principal::from_text("oqjvn-fqaaa-aaaab-qab5q-cai")?;
    let authorized_principal = Some(sender);
    let env = TestEnv::new(authorized_principal, sender).await?;

    info!("Step 1: Test successful call by authorized principal");
    verify_authorized_principal_access(&env).await?;

    info!("Step 2: Test call rejection by unauthorized principal");
    verify_unauthorized_principal_rejection(&env).await?;

    Ok(())
}

/// Test that domains with failed registrations are eventually removed after the expiration time
#[tokio::test]
async fn test_unregistered_domain_deletion() -> anyhow::Result<()> {
    init_logging();

    let sender = Principal::from_text("oqjvn-fqaaa-aaaab-qab5q-cai")?;
    let authorized_principal = Some(sender);
    let env = TestEnv::new(authorized_principal, sender).await?;

    let domain = "example.com";

    info!("Step 1: Submit certificate issuance task for domain {domain}");
    add_task(&env, domain, TaskKind::Issue).await?;
    let now = get_current_timestamp(&env.pic).await;
    let expected_expiration_time_secs =
        now.saturating_add(UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs());

    info!("Step 2: Retrieve the pending issuance task and verify no other tasks remain");
    assert_has_next_task(&env).await?;
    let task = fetch_next_task(&env).await?;
    assert_has_no_next_task(&env).await?;

    info!("Step 3: Simulate repeated registration failures until max retry limit is reached");
    let error_msg = "Some persistent failure".to_string();
    simulate_retries_after_generic_failures(&env, error_msg.clone(), task, MAX_TASK_FAILURES)
        .await?;

    info!("Step 4: Verify domain {domain} status is now marked as Failed");
    verify_domain_status(
        &env,
        domain,
        None,
        RegistrationStatus::Failed(format!("generic_failure: {error_msg}")),
    )
    .await?;
    assert_has_no_next_task(&env).await?;

    info!("Step 5: Advance time to just before expiration and verify domain {domain} still exists");
    let time_delta_sec = 1;
    let advance_time = expected_expiration_time_secs
        .saturating_sub(get_current_timestamp(&env.pic).await)
        .saturating_sub(time_delta_sec);
    advance_time_and_tick(
        &env,
        Duration::from_secs(advance_time),
        TICKS_AFTER_TIME_ADVANCE,
    )
    .await;
    verify_domain_status(
        &env,
        domain,
        None,
        RegistrationStatus::Failed(format!("generic_failure: {error_msg}")),
    )
    .await?;

    info!(
        "Step 6: Advance time past cleanup interval and verify domain '{domain}' has been deleted"
    );
    advance_time_and_tick(
        &env,
        STALE_DOMAINS_CLEANUP_INTERVAL.saturating_add(Duration::from_secs(time_delta_sec)),
        TICKS_AFTER_TIME_ADVANCE,
    )
    .await;
    let status = env
        .get_domain_status(domain)
        .await?
        .map_err(|err| anyhow!("Failed to get status for {domain}: {err:?}"))?;
    assert!(status.is_none(), "Domain {domain} should have been deleted");

    Ok(())
}

#[tokio::test]
async fn test_comprehensive_registration_scenario() -> anyhow::Result<()> {
    init_logging();

    let sender = Principal::from_text("oqjvn-fqaaa-aaaab-qab5q-cai")?;
    let authorized_principal = Some(sender);
    let env = TestEnv::new(authorized_principal, sender).await?;

    let domain_successful = "example1.com";
    let domain_with_failure = "example2.com";

    let canister_id1 = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai")?;
    let canister_id2 = Principal::from_text("363tq-3yaaa-aaaab-qacma-cai")?;

    info!("Step 1: Submit certificate issuance tasks for two domains");
    let task_kind = TaskKind::Issue;
    add_task(&env, domain_successful, task_kind).await?;
    add_task(&env, domain_with_failure, task_kind).await?;

    info!("Step 2: Verify both domains are in Registering status");
    verify_domain_status(
        &env,
        domain_successful,
        None,
        RegistrationStatus::Registering,
    )
    .await?;
    verify_domain_status(
        &env,
        domain_with_failure,
        None,
        RegistrationStatus::Registering,
    )
    .await?;

    info!("Step 3: Fetch two pending tasks and confirm no additional tasks remain");
    assert_has_next_task(&env).await?;
    let task1 = fetch_next_task(&env).await?;
    let task2 = fetch_next_task(&env).await?;
    assert_has_no_next_task(&env).await?;

    info!("Step 4: Complete first task successfully and submit result");
    submit_successful_task_result(&env, &task1, canister_id1).await?;

    info!("Step 5: Verify {domain_successful} is now in Registered status");
    verify_domain_status(
        &env,
        domain_successful,
        Some(canister_id1),
        RegistrationStatus::Registered,
    )
    .await?;
    verify_certificate_exists(&env, domain_successful).await?;

    info!("Step 6: Test task timeout and automatic rescheduling for {domain_with_failure}");
    let task2 = simulate_task_timeout_and_rescheduling(&env, &task2, canister_id2).await?;

    info!(
        "Step 7: Test rate-limited failure handling with unlimited retries for {domain_with_failure}"
    );
    let task2 =
        simulate_retries_after_rate_limited_errors(&env, task2, RATE_LIMIT_MAX_ATTEMPTS).await?;

    info!(
        "Step 8: Test generic failure handling with maximum retry limit for {domain_with_failure}"
    );
    let error_msg = "Some persistent failure".to_string();
    simulate_retries_after_generic_failures(&env, error_msg.clone(), task2, MAX_TASK_FAILURES)
        .await?;

    info!("Step 9: Verify {domain_with_failure} is marked as Failed with no pending tasks");
    verify_domain_status(
        &env,
        domain_with_failure,
        None,
        RegistrationStatus::Failed(format!("generic_failure: {error_msg}")),
    )
    .await?;
    // After MAX_TASK_FAILURES, the task should be dropped
    assert_has_no_next_task(&env).await?;

    info!("Step 10: Resubmit registration request for previously failed domain");
    add_task(&env, domain_with_failure, TaskKind::Issue).await?;
    assert_has_next_task(&env).await?;
    let task2 = fetch_next_task(&env).await?;

    info!("Step 11: Complete second domain registration successfully");
    submit_successful_task_result(&env, &task2, canister_id2).await?;
    verify_domain_status(
        &env,
        domain_with_failure,
        Some(canister_id2),
        RegistrationStatus::Registered,
    )
    .await?;

    info!("Step 12: Verify certificate renewal tasks are scheduled when time advances");
    verify_certificate_renewal_tasks_scheduled(&env).await?;

    info!("Step 13: Verify domains expire when renewal tasks are not executed");
    verify_domains_expire_after_renewal_tasks_not_executed(
        &env,
        domain_successful,
        canister_id1,
        domain_with_failure,
        canister_id2,
    )
    .await?;

    Ok(())
}

async fn verify_domains_expire_after_renewal_tasks_not_executed(
    env: &TestEnv,
    domain1: &str,
    canister_id1: Principal,
    domain2: &str,
    canister_id2: Principal,
) -> anyhow::Result<()> {
    advance_time_and_tick(
        env,
        Duration::from_secs(CERTIFICATE_VALIDITY_DURATION_SECS),
        TICKS_AFTER_TIME_ADVANCE,
    )
    .await;
    verify_domain_status(
        env,
        domain1,
        Some(canister_id1),
        RegistrationStatus::Expired,
    )
    .await?;
    verify_domain_status(
        env,
        domain2,
        Some(canister_id2),
        RegistrationStatus::Expired,
    )
    .await?;

    Ok(())
}

async fn verify_certificate_renewal_tasks_scheduled(env: &TestEnv) -> anyhow::Result<()> {
    assert_has_no_next_task(env).await?;
    // Advance time by the renewal interval to trigger renewal tasks scheduling
    let interval_sec =
        (CERTIFICATE_VALIDITY_FRACTION * CERTIFICATE_VALIDITY_DURATION_SECS as f64) as u64;
    advance_time_and_tick(
        env,
        Duration::from_secs(interval_sec),
        TICKS_AFTER_TIME_ADVANCE,
    )
    .await;
    // Now there should be renewal tasks available, we don't fetch the yet
    assert_has_next_task(env).await?;
    Ok(())
}

async fn add_task(env: &TestEnv, domain: &str, task_kind: TaskKind) -> anyhow::Result<()> {
    env.try_add_task(domain.to_string(), TaskKind::Issue)
        .await?
        .map_err(|err| anyhow!("Failed to add task {task_kind:?} for {domain}: {err:?}"))?;
    Ok(())
}

async fn verify_domain_status(
    env: &TestEnv,
    domain: &str,
    canister_id: Option<Principal>,
    registration_status: RegistrationStatus,
) -> anyhow::Result<()> {
    let status = env
        .get_domain_status(domain)
        .await?
        .map_err(|err| anyhow!("Failed to get status for {domain}: {err:?}"))?
        .ok_or_else(|| anyhow!("Domain {domain} not found"))?;

    assert_eq!(
        status,
        DomainStatus {
            domain: domain.to_string(),
            canister_id,
            status: registration_status
        },
        "Domain {domain} should be in status {status:?}",
    );

    Ok(())
}

async fn verify_certificate_exists(env: &TestEnv, domain: &str) -> anyhow::Result<()> {
    let entry = env
        .get_domain_entry(domain)
        .await?
        .map_err(|err| anyhow!("Failed to get domain entry for {domain}: {err:?}"))?
        .ok_or_else(|| anyhow!("Domain {domain} not found"))?;

    assert!(entry.enc_cert.is_some());
    assert!(entry.enc_priv_key.is_some());

    Ok(())
}

async fn verify_authorized_principal_access(env: &TestEnv) -> anyhow::Result<()> {
    let arg = Encode!(&()).map_err(|err| anyhow!("Failed to encode arguments: {err:?}"))?;

    let result = env
        .pic
        .query_call(env.canister_id, env.sender, "has_next_task", arg)
        .await
        .map_err(|err| anyhow!("Query call from authorized principal rejected: {err:?}"))?;

    let has_next_task = Decode!(&result, HasNextTaskResult)
        .map_err(|err| anyhow!("Failed to decode response: {err:?}"))?
        .map_err(|err| anyhow!("has_next_task call failed: {err:?}"))?;

    assert!(!has_next_task, "Expected no tasks initially in canister");

    Ok(())
}

async fn verify_unauthorized_principal_rejection(env: &TestEnv) -> anyhow::Result<()> {
    let arg = Encode!(&()).map_err(|err| anyhow!("Failed to encode arguments: {err:?}"))?;

    let result = env
        .pic
        .query_call(env.canister_id, env.controller, "has_next_task", arg)
        .await
        .map_err(|err| anyhow!("Query call from unauthorized principal rejected: {err:?}"))?;

    let unauthorized_result = Decode!(&result, HasNextTaskResult)
        .map_err(|err| anyhow!("Failed to decode unauthorized response: {err:?}"))?;

    assert_eq!(unauthorized_result, Err(HasNextTaskError::Unauthorized));

    Ok(())
}

async fn fetch_next_task(env: &TestEnv) -> anyhow::Result<ScheduledTask> {
    env.fetch_next_task()
        .await?
        .map_err(|err| anyhow!("Failed to fetch task: {err:?}"))?
        .ok_or_else(|| anyhow!("Expected a task"))
}

async fn assert_has_no_next_task(env: &TestEnv) -> anyhow::Result<()> {
    let has_task = env
        .has_next_task()
        .await?
        .map_err(|err| anyhow!("Failed to check for next task: {err:?}"))?;
    assert!(!has_task, "Expected no more tasks to be available");
    Ok(())
}

async fn assert_has_next_task(env: &TestEnv) -> anyhow::Result<()> {
    let has_task = env
        .has_next_task()
        .await?
        .map_err(|err| anyhow!("Failed to check for next task: {err:?}"))?;

    assert!(has_task, "Expected a task to be available");

    Ok(())
}

fn create_successful_task_result(
    task: &ScheduledTask,
    canister_id: Principal,
    now: u64,
) -> TaskResult {
    TaskResult {
        domain: task.domain.clone(),
        outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
            canister_id,
            enc_cert: b"certificate_data".to_vec(),
            enc_priv_key: b"private_key_data".to_vec(),
            not_before: now,
            not_after: now + CERTIFICATE_VALIDITY_DURATION_SECS,
        })),
        task_id: task.id,
        task_kind: task.kind,
        duration_secs: 60,
    }
}

async fn submit_successful_task_result(
    env: &TestEnv,
    task: &ScheduledTask,
    canister_id: Principal,
) -> anyhow::Result<()> {
    let now = get_current_timestamp(&env.pic).await;

    let task_result = create_successful_task_result(task, canister_id, now);

    env.submit_task_result(task_result)
        .await?
        .map_err(|err| anyhow!("Failed to submit successful task result: {err:?}"))?;

    Ok(())
}

async fn simulate_task_timeout_and_rescheduling(
    env: &TestEnv,
    task: &ScheduledTaskApi,
    canister_id: Principal,
) -> anyhow::Result<ScheduledTask> {
    assert_has_no_next_task(env).await?;

    // Advance time by TASK_TIMEOUT
    advance_time_and_tick(env, TASK_TIMEOUT, TICKS_AFTER_TIME_ADVANCE).await;

    let rescheduled_task = fetch_next_task(env).await?;

    let now = get_current_timestamp(&env.pic).await;

    let expired_task_result = TaskResult {
        domain: task.domain.clone(),
        outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
            canister_id,
            enc_cert: b"certificate_data".to_vec(),
            enc_priv_key: b"private_key_data".to_vec(),
            not_before: now,
            not_after: now + CERTIFICATE_VALIDITY_DURATION_SECS,
        })),
        task_id: task.id, // Submitting result for the old (expired) task ID
        task_kind: task.kind,
        duration_secs: 60,
    };

    let result = env.submit_task_result(expired_task_result).await?;
    assert_eq!(
        result,
        Err(SubmitTaskError::NonExistingTaskSubmitted(task.id)),
        "Should fail with NonExistingTaskSubmitted error"
    );

    Ok(rescheduled_task)
}

async fn simulate_retries_after_rate_limited_errors(
    env: &TestEnv,
    mut task: ScheduledTask,
    max_attempts: u32,
) -> anyhow::Result<ScheduledTask> {
    let domain = task.domain.clone();

    for _ in 1..=max_attempts {
        let failure_result = create_failure_task_result(&task, TaskFailReason::RateLimited);

        env.submit_task_result(failure_result)
            .await?
            .map_err(|err| anyhow!("Failed to submit rate-limited failure: {err:?}"))?;

        assert_has_no_next_task(env).await?;

        advance_time_and_tick(env, MIN_TASK_RETRY_DELAY, TICKS_AFTER_TIME_ADVANCE).await;

        task = fetch_next_task(env).await?;

        assert_eq!(task.kind, TaskKind::Issue);
        assert_eq!(task.domain, domain);
    }

    Ok(task)
}

async fn simulate_retries_after_generic_failures(
    env: &TestEnv,
    error_msg: String,
    mut task: ScheduledTask,
    max_attempts: u32,
) -> anyhow::Result<()> {
    let domain = task.domain.clone();

    for attempt in 1..=max_attempts {
        let failure_result =
            create_failure_task_result(&task, TaskFailReason::GenericFailure(error_msg.clone()));

        env.submit_task_result(failure_result)
            .await?
            .map_err(|err| anyhow!("Failed to submit generic failure: {err:?}"))?;

        assert_has_no_next_task(env).await?;

        advance_time_and_tick(env, MIN_TASK_RETRY_DELAY, TICKS_AFTER_TIME_ADVANCE).await;

        if attempt < max_attempts {
            task = fetch_next_task(env).await?;
            assert_eq!(task.kind, TaskKind::Issue);
            assert_eq!(task.domain, domain);
        }
    }

    Ok(())
}

fn create_failure_task_result(
    task: &ScheduledTaskApi,
    failure_reason: TaskFailReason,
) -> TaskResult {
    TaskResult {
        domain: task.domain.clone(),
        outcome: TaskOutcome::Failure(failure_reason),
        task_id: task.id,
        task_kind: task.kind,
        duration_secs: 45,
    }
}

async fn advance_time_and_tick(env: &TestEnv, duration: Duration, ticks: u32) {
    env.pic.advance_time(duration).await;
    env.ticks(ticks).await;
}

async fn get_current_timestamp(pic: &PocketIc) -> u64 {
    pic.get_time().await.as_nanos_since_unix_epoch() / 1_000_000_000
}
