//! # Custom Domains Canister API
//!
//! This module defines the public API types and interfaces for the custom domains management canister.
//! All types implement [`CandidType`] for integration with candid interface.

use std::time::Duration;

use candid::{CandidType, Principal};
use derive_new::new;
use serde::{Deserialize, Serialize};
use strum::{EnumIter, IntoStaticStr};
use thiserror::Error;

type TaskId = u64;
type UtcTimestamp = u64;

// Declare constants related to the canister here, enabling usage in other modules and tests.

// Certificate renewal should be attempted when this fraction of the validity period has elapsed
pub const CERTIFICATE_VALIDITY_FRACTION: f64 = 0.66;

// A domain is considered close to certificate expiration if less than this fraction of its validity period remains
pub const CERT_EXPIRATION_ALERT_THRESHOLD: f64 = 0.2;

// Task is considered timed out, if its result isn't submitted within this time window.
// This allows the task to be rescheduled if a worker fails.
// Submitting results for timed out tasks results in a NonExistingTaskSubmitted error.
pub const TASK_TIMEOUT: Duration = Duration::from_secs(10 * 60);

// If no certificate has been issued, the domain entry is removed after this duration.
pub const UNREGISTERED_DOMAIN_EXPIRATION_TIME: Duration = Duration::from_secs(24 * 60 * 60);

// If a domain has failed to renew and its certificate expired, it is removed after this duration.
pub const EXPIRED_DOMAIN_EXPIRATION_TIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

// If a task fails this many times with a recoverable error, it is no longer rescheduled.
// User is expected to resubmit the task.
pub const MAX_TASK_FAILURES: u32 = 20;

// If a task fails, it will not be rescheduled earlier than this interval.
pub const MIN_TASK_RETRY_DELAY: Duration = Duration::from_secs(30);

// Default number of domains returned per page when no limit is specified or limit is zero
pub const DEFAULT_PAGE_LIMIT: u32 = 100;

// Maximum number of domains that can be returned in a single page to safely stay lower than 2MB response
pub const MAX_PAGE_LIMIT: u32 = 400;

// Interval for purging stale, unregistered domains
pub const STALE_DOMAINS_CLEANUP_INTERVAL: Duration = Duration::from_hours(3);

pub type FetchTaskResult = Result<Option<ScheduledTask>, FetchTaskError>;
pub type SubmitTaskResult = Result<(), SubmitTaskError>;
pub type TryAddTaskResult = Result<(), TryAddTaskError>;
pub type GetDomainStatusResult = Result<Option<DomainStatus>, GetDomainStatusError>;
pub type GetDomainEntryResult = Result<Option<DomainEntry>, GetDomainEntryError>;
pub type GetLastChangeTimeResult = Result<UtcTimestamp, GetLastChangeTimeError>;
pub type ListCertificatesPageResult = Result<CertificatesPage, ListCertificatesPageError>;
pub type ListDomainsPageResult = Result<DomainsPage, ListDomainsPageError>;
pub type HasNextTaskResult = Result<bool, HasNextTaskError>;

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct InitArg {
    pub authorized_principal: Option<Principal>,
}

#[derive(
    CandidType, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash, IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum TaskKind {
    Issue,
    Renew,
    Update,
    Delete,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct InputTask {
    pub kind: TaskKind,
    pub domain: String,
    /// Whether to also include a `*.domain` wildcard SAN in the certificate
    pub wildcard: Option<bool>,
    /// The canister ID associated with the domain (if known at submission time)
    pub canister_id: Option<Principal>,
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, PartialEq, Eq, new)]
pub struct ScheduledTask {
    pub kind: TaskKind,
    pub domain: String,
    pub id: TaskId,
    pub enc_cert: Option<Vec<u8>>,
    // Whether to also include a `*.domain` wildcard SAN in the certificate
    pub wildcard: Option<bool>,
    /// The canister ID associated with the domain (if known at submission time)
    pub canister_id: Option<Principal>,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct TaskResult {
    pub domain: String,
    pub outcome: TaskOutcome,
    pub task_id: TaskId,
    pub task_kind: TaskKind,
    pub duration_secs: u64,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub enum TaskOutcome {
    Success(TaskOutput),
    Failure(TaskFailReason),
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub enum TaskOutput {
    Issue(IssueCertificateOutput),
    Update(Principal),
    Delete,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug)]
pub struct IssueCertificateOutput {
    pub canister_id: Principal,
    pub enc_cert: Vec<u8>,
    pub enc_priv_key: Vec<u8>,
    pub not_before: UtcTimestamp,
    pub not_after: UtcTimestamp,
}

#[derive(CandidType, Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Error, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TaskFailReason {
    #[error("validation_failed: {0}")]
    ValidationFailed(String),
    #[error("timeout after {duration_secs}s")]
    Timeout { duration_secs: UtcTimestamp },
    #[error("rate_limited")]
    RateLimited,
    #[error("generic_failure: {0}")]
    GenericFailure(String),
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct DomainStatus {
    pub domain: String,
    pub canister_id: Option<Principal>,
    pub status: RegistrationStatus,
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct DomainEntry {
    pub task: Option<TaskKind>,
    // Timestamp when the task failed last time, if any
    pub last_fail_time: Option<UtcTimestamp>,
    // Reason for the last failure, if any
    pub last_failure_reason: Option<TaskFailReason>,
    // Number of consecutive failures for the current task (excluding rate limit failures)
    pub failures_count: u32,
    // Number of rate limit failures for the current task
    pub rate_limit_failures_count: u32,
    // Canister ID associated with the domain
    pub canister_id: Option<Principal>,
    // Timestamp when the domain entry was created (set once and never updated)
    pub created_at: UtcTimestamp,
    // Timestamp when the current task was taken by a worker
    pub taken_at: Option<UtcTimestamp>,
    // Timestamp when the current task was created
    pub task_created_at: Option<UtcTimestamp>,
    // PEM-encoded certificate data (encrypted)
    pub enc_cert: Option<Vec<u8>>,
    // PEM-encoded private key data (encrypted)
    pub enc_priv_key: Option<Vec<u8>>,
    // Certificate validity period start (as UNIX timestamp)
    pub not_before: Option<UtcTimestamp>,
    // Certificate validity period end (as UNIX timestamp)
    pub not_after: Option<UtcTimestamp>,
    // Whether the certificate also includes a `*.domain` wildcard SAN
    pub wildcard: Option<bool>,
}

/// Domain entry as returned by list_domains_page: includes domain name and all entry fields except enc_cert and enc_priv_key.
#[derive(CandidType, Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct ListedDomainEntry {
    /// Fully qualified domain name (FQDN)
    pub domain: String,
    pub task: Option<TaskKind>,
    pub last_fail_time: Option<UtcTimestamp>,
    pub last_failure_reason: Option<TaskFailReason>,
    pub failures_count: u32,
    pub rate_limit_failures_count: u32,
    pub canister_id: Option<Principal>,
    pub created_at: UtcTimestamp,
    pub taken_at: Option<UtcTimestamp>,
    pub task_created_at: Option<UtcTimestamp>,
    pub not_before: Option<UtcTimestamp>,
    pub not_after: Option<UtcTimestamp>,
    pub wildcard: Option<bool>,
}

#[derive(
    CandidType, Clone, Deserialize, Serialize, Debug, EnumIter, IntoStaticStr, PartialEq, Eq,
)]
#[strum(serialize_all = "snake_case")]
pub enum RegistrationStatus {
    /// The registration is currently being processed
    Registering,
    /// The domain has been successfully registered and has a valid certificate
    Registered,
    /// The domain registration has expired
    Expired,
    /// The registration failed with an error message
    Failed(String),
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct CertificatesPage {
    pub items: Vec<RegisteredDomain>,
    pub next_key: Option<String>,
}

impl CertificatesPage {
    pub fn new(items: Vec<RegisteredDomain>, next_key: Option<String>) -> Self {
        Self { items, next_key }
    }
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct ListCertificatesPageInput {
    /// Optional starting point for pagination (domain name to start from)
    pub start_key: Option<String>,
    /// Maximum number of items to return per page
    pub limit: Option<u32>,
}

impl ListCertificatesPageInput {
    pub fn new() -> Self {
        Self {
            start_key: None,
            limit: None,
        }
    }
}

impl Default for ListCertificatesPageInput {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct RegisteredDomain {
    pub domain: String,
    pub canister_id: Principal,
    pub enc_cert: Vec<u8>,
    pub enc_priv_key: Vec<u8>,
}

/// A page of domain entries with pagination information (items exclude enc_cert and enc_priv_key).
#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct DomainsPage {
    pub items: Vec<ListedDomainEntry>,
    pub next_key: Option<String>,
}

impl DomainsPage {
    pub fn new(items: Vec<ListedDomainEntry>, next_key: Option<String>) -> Self {
        Self { items, next_key }
    }
}

/// Input for paginated domain listing
#[derive(CandidType, Clone, Deserialize, Serialize, Debug)]
pub struct ListDomainsPageInput {
    /// Optional starting point for pagination (domain name to start from)
    pub start_key: Option<String>,
    /// Maximum number of items to return per page
    pub limit: Option<u32>,
}

impl ListDomainsPageInput {
    pub fn new() -> Self {
        Self {
            start_key: None,
            limit: None,
        }
    }
}

impl Default for ListDomainsPageInput {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Error)]
pub enum ListDomainsPageError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Error)]
pub enum GetLastChangeTimeError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr, Error)]
#[strum(serialize_all = "snake_case")]
pub enum FetchTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Error)]
pub enum GetDomainStatusError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Error)]
pub enum GetDomainEntryError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, Error)]
pub enum ListCertificatesPageError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr, Error, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
pub enum SubmitTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Domain not found: {0}")]
    DomainNotFound(String),
    #[error("A non-existing task was submitted: {0}")]
    NonExistingTaskSubmitted(TaskId),
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Error)]
pub enum HasNextTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, IntoStaticStr, Error)]
#[strum(serialize_all = "snake_case")]
pub enum TryAddTaskError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Domain not found: {0}")]
    DomainNotFound(String),
    #[error("Another task is already in progress for domain: {0}")]
    AnotherTaskInProgress(String),
    #[error("Certificate already issued for domain: {0}")]
    CertificateAlreadyIssued(String),
    #[error("Update requires an existing certificate: {0}")]
    MissingCertificateForUpdate(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashSet;
    use std::fmt::Debug;

    use candid::{Decode, Encode};
    use strum::IntoEnumIterator;

    /// The candid (wire) type of `T` with all whitespace runs collapsed to single spaces, so
    /// the assertions below pin field names, field types and variant names without depending
    /// on candid's pretty-printer line breaking.
    fn candid_ty<T: CandidType>() -> String {
        <T as CandidType>::ty()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            // candid's pretty-printer only emits a trailing ";" before the closing brace when
            // it breaks a record/variant across lines, which depends on the line length only.
            .replace("; }", " }")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd-length hex literal");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Encodes `v` as candid, decodes it back and asserts nothing was lost or reordered.
    /// The comparison is on the `Debug` rendering because several wire types deliberately
    /// don't implement `PartialEq`.
    fn round_trip<T>(v: &T) -> T
    where
        T: CandidType + for<'de> Deserialize<'de> + Debug,
    {
        let bytes = Encode!(v).expect("candid encoding failed");
        let decoded = Decode!(&bytes, T).expect("candid decoding failed");
        assert_eq!(
            format!("{v:?}"),
            format!("{decoded:?}"),
            "candid round-trip did not preserve the value"
        );
        decoded
    }

    fn principal() -> Principal {
        Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()
    }

    fn issue_output() -> IssueCertificateOutput {
        IssueCertificateOutput {
            canister_id: principal(),
            enc_cert: vec![1, 2, 3],
            enc_priv_key: vec![4, 5],
            not_before: 1_000,
            not_after: 2_000,
        }
    }

    fn full_domain_entry() -> DomainEntry {
        DomainEntry {
            task: Some(TaskKind::Renew),
            last_fail_time: Some(11),
            last_failure_reason: Some(TaskFailReason::ValidationFailed("nope".into())),
            failures_count: 7,
            rate_limit_failures_count: 3,
            canister_id: Some(principal()),
            created_at: 5,
            taken_at: Some(6),
            task_created_at: Some(7),
            enc_cert: Some(vec![0xaa, 0xbb]),
            enc_priv_key: Some(vec![0xcc]),
            not_before: Some(100),
            not_after: Some(200),
            wildcard: Some(true),
        }
    }

    fn full_listed_entry() -> ListedDomainEntry {
        ListedDomainEntry {
            domain: "listed.example.com".into(),
            task: Some(TaskKind::Issue),
            last_fail_time: Some(1),
            last_failure_reason: Some(TaskFailReason::RateLimited),
            failures_count: 2,
            rate_limit_failures_count: 3,
            canister_id: Some(principal()),
            created_at: 4,
            taken_at: Some(5),
            task_created_at: Some(6),
            not_before: Some(7),
            not_after: Some(8),
            wildcard: Some(false),
        }
    }

    const ALL_TASK_KINDS: [TaskKind; 4] = [
        TaskKind::Issue,
        TaskKind::Renew,
        TaskKind::Update,
        TaskKind::Delete,
    ];

    // ---------------------------------------------------------------------------------------
    // Candid wire types. These are the published interface of the canister: a change to any
    // of these strings is a change every already-deployed client has to agree to.
    // ---------------------------------------------------------------------------------------

    const TASK_KIND_TY: &str = "variant { Issue; Renew; Delete; Update }";
    const TASK_FAIL_REASON_TY: &str = "variant { ValidationFailed : text; RateLimited; Timeout : record { duration_secs : nat64 }; GenericFailure : text }";
    const REGISTRATION_STATUS_TY: &str =
        "variant { Failed : text; Registered; Expired; Registering }";
    const AUTH_ERROR_TY: &str = "variant { Unauthorized; InternalError : text }";

    #[test]
    fn test_candid_type_of_task_types() {
        assert_eq!(
            candid_ty::<InitArg>(),
            "record { authorized_principal : opt principal }"
        );
        assert_eq!(candid_ty::<TaskKind>(), TASK_KIND_TY);
        assert_eq!(candid_ty::<TaskFailReason>(), TASK_FAIL_REASON_TY);
        assert_eq!(
            candid_ty::<IssueCertificateOutput>(),
            "record { not_before : nat64; canister_id : principal; not_after : nat64; enc_priv_key : blob; enc_cert : blob }"
        );
        assert_eq!(
            candid_ty::<InputTask>(),
            format!(
                "record {{ domain : text; kind : {TASK_KIND_TY}; canister_id : opt principal; wildcard : opt bool }}"
            )
        );
        assert_eq!(
            candid_ty::<ScheduledTask>(),
            format!(
                "record {{ id : nat64; domain : text; kind : {TASK_KIND_TY}; canister_id : opt principal; wildcard : opt bool; enc_cert : opt blob }}"
            )
        );
        assert_eq!(
            candid_ty::<TaskOutput>(),
            format!(
                "variant {{ Issue : {}; Delete; Update : principal }}",
                candid_ty::<IssueCertificateOutput>()
            )
        );
        assert_eq!(
            candid_ty::<TaskOutcome>(),
            format!(
                "variant {{ Success : {}; Failure : {TASK_FAIL_REASON_TY} }}",
                candid_ty::<TaskOutput>()
            )
        );
        assert_eq!(
            candid_ty::<TaskResult>(),
            format!(
                "record {{ task_id : nat64; domain : text; duration_secs : nat64; task_kind : {TASK_KIND_TY}; outcome : {} }}",
                candid_ty::<TaskOutcome>()
            )
        );
    }

    #[test]
    fn test_candid_type_of_domain_types() {
        assert_eq!(candid_ty::<RegistrationStatus>(), REGISTRATION_STATUS_TY);
        assert_eq!(
            candid_ty::<DomainStatus>(),
            format!(
                "record {{ status : {REGISTRATION_STATUS_TY}; domain : text; canister_id : opt principal }}"
            )
        );
        assert_eq!(
            candid_ty::<DomainEntry>(),
            format!(
                "record {{ not_before : opt nat64; task : opt {TASK_KIND_TY}; canister_id : opt principal; \
                 task_created_at : opt nat64; not_after : opt nat64; created_at : nat64; \
                 last_failure_reason : opt {TASK_FAIL_REASON_TY}; wildcard : opt bool; enc_priv_key : opt blob; \
                 failures_count : nat32; rate_limit_failures_count : nat32; last_fail_time : opt nat64; \
                 taken_at : opt nat64; enc_cert : opt blob }}"
            )
        );
        // Same as DomainEntry plus `domain`, minus the two certificate blobs.
        assert_eq!(
            candid_ty::<ListedDomainEntry>(),
            format!(
                "record {{ not_before : opt nat64; domain : text; task : opt {TASK_KIND_TY}; \
                 canister_id : opt principal; task_created_at : opt nat64; not_after : opt nat64; \
                 created_at : nat64; last_failure_reason : opt {TASK_FAIL_REASON_TY}; wildcard : opt bool; \
                 failures_count : nat32; rate_limit_failures_count : nat32; last_fail_time : opt nat64; \
                 taken_at : opt nat64 }}"
            )
        );
        assert!(
            !candid_ty::<ListedDomainEntry>().contains("enc_"),
            "ListedDomainEntry must never carry certificate material on the wire"
        );
    }

    #[test]
    fn test_candid_type_of_pagination_types() {
        assert_eq!(
            candid_ty::<RegisteredDomain>(),
            "record { domain : text; canister_id : principal; enc_priv_key : blob; enc_cert : blob }"
        );
        assert_eq!(
            candid_ty::<CertificatesPage>(),
            format!(
                "record {{ next_key : opt text; items : vec {} }}",
                candid_ty::<RegisteredDomain>()
            )
        );
        assert_eq!(
            candid_ty::<DomainsPage>(),
            format!(
                "record {{ next_key : opt text; items : vec {} }}",
                candid_ty::<ListedDomainEntry>()
            )
        );
        let page_input = "record { start_key : opt text; limit : opt nat32 }";
        assert_eq!(candid_ty::<ListCertificatesPageInput>(), page_input);
        assert_eq!(candid_ty::<ListDomainsPageInput>(), page_input);
    }

    #[test]
    fn test_candid_type_of_error_types() {
        // Every "plain" error is just Unauthorized/InternalError; if one of them ever grows a
        // variant, this test is the reminder to bump the interface deliberately.
        assert_eq!(candid_ty::<ListDomainsPageError>(), AUTH_ERROR_TY);
        assert_eq!(candid_ty::<GetLastChangeTimeError>(), AUTH_ERROR_TY);
        assert_eq!(candid_ty::<FetchTaskError>(), AUTH_ERROR_TY);
        assert_eq!(candid_ty::<GetDomainStatusError>(), AUTH_ERROR_TY);
        assert_eq!(candid_ty::<GetDomainEntryError>(), AUTH_ERROR_TY);
        assert_eq!(candid_ty::<ListCertificatesPageError>(), AUTH_ERROR_TY);
        assert_eq!(candid_ty::<HasNextTaskError>(), AUTH_ERROR_TY);

        assert_eq!(
            candid_ty::<SubmitTaskError>(),
            "variant { NonExistingTaskSubmitted : nat64; Unauthorized; DomainNotFound : text; InternalError : text }"
        );
        assert_eq!(
            candid_ty::<TryAddTaskError>(),
            "variant { Unauthorized; MissingCertificateForUpdate : text; DomainNotFound : text; \
             AnotherTaskInProgress : text; InternalError : text; CertificateAlreadyIssued : text }"
        );
    }

    #[test]
    fn test_candid_type_of_result_aliases() {
        assert_eq!(
            candid_ty::<FetchTaskResult>(),
            format!(
                "variant {{ Ok : opt {}; Err : {AUTH_ERROR_TY} }}",
                candid_ty::<ScheduledTask>()
            )
        );
        assert_eq!(
            candid_ty::<SubmitTaskResult>(),
            format!("variant {{ Ok; Err : {} }}", candid_ty::<SubmitTaskError>())
        );
        assert_eq!(
            candid_ty::<TryAddTaskResult>(),
            format!("variant {{ Ok; Err : {} }}", candid_ty::<TryAddTaskError>())
        );
        assert_eq!(
            candid_ty::<HasNextTaskResult>(),
            format!("variant {{ Ok : bool; Err : {AUTH_ERROR_TY} }}")
        );
        assert_eq!(
            candid_ty::<GetLastChangeTimeResult>(),
            format!("variant {{ Ok : nat64; Err : {AUTH_ERROR_TY} }}")
        );
        assert_eq!(
            candid_ty::<GetDomainStatusResult>(),
            format!(
                "variant {{ Ok : opt {}; Err : {AUTH_ERROR_TY} }}",
                candid_ty::<DomainStatus>()
            )
        );
        assert_eq!(
            candid_ty::<GetDomainEntryResult>(),
            format!(
                "variant {{ Ok : opt {}; Err : {AUTH_ERROR_TY} }}",
                candid_ty::<DomainEntry>()
            )
        );
        assert_eq!(
            candid_ty::<ListCertificatesPageResult>(),
            format!(
                "variant {{ Ok : {}; Err : {AUTH_ERROR_TY} }}",
                candid_ty::<CertificatesPage>()
            )
        );
        assert_eq!(
            candid_ty::<ListDomainsPageResult>(),
            format!(
                "variant {{ Ok : {}; Err : {AUTH_ERROR_TY} }}",
                candid_ty::<DomainsPage>()
            )
        );
    }

    // ---------------------------------------------------------------------------------------
    // Frozen wire bytes. Candid identifies variants by a hash of their *name*, so renaming a
    // variant silently changes the bytes on the wire; these goldens catch that.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn test_task_kind_wire_bytes_are_frozen() {
        let table = "4449444c016b04b997eea4057feddcc7cf077fcbe8b4fb097fa9f4e7dc0b7f0100";
        let expected = [
            (TaskKind::Issue, format!("{table}00")),
            (TaskKind::Renew, format!("{table}01")),
            (TaskKind::Delete, format!("{table}02")),
            (TaskKind::Update, format!("{table}03")),
        ];

        for (kind, golden) in expected {
            assert_eq!(hex(&Encode!(&kind).unwrap()), golden, "encoding {kind:?}");
            // ...and bytes produced by an already-deployed client still decode.
            assert_eq!(Decode!(&unhex(&golden), TaskKind).unwrap(), kind);
        }
    }

    #[test]
    fn test_registration_status_wire_bytes_are_frozen() {
        let table = "4449444c016b04ddf3cce40171a2c3c6da0e7f858fee950f7fbfbcfbe00f7f0100";
        let expected = [
            (
                RegistrationStatus::Failed("x".into()),
                format!("{table}000178"),
            ),
            (RegistrationStatus::Registered, format!("{table}01")),
            (RegistrationStatus::Expired, format!("{table}02")),
            (RegistrationStatus::Registering, format!("{table}03")),
        ];

        for (status, golden) in expected {
            assert_eq!(
                hex(&Encode!(&status).unwrap()),
                golden,
                "encoding {status:?}"
            );
            assert_eq!(
                Decode!(&unhex(&golden), RegistrationStatus).unwrap(),
                status
            );
        }
    }

    #[test]
    fn test_error_wire_bytes_are_frozen() {
        let golden = "4449444c026b04f6a5ce6071ba8a96b00a7f8185a1b20a0193f680a00c716c01cdffddc309780100022a00000000000000";
        let timeout = TaskFailReason::Timeout { duration_secs: 42 };
        assert_eq!(hex(&Encode!(&timeout).unwrap()), golden);
        assert_eq!(Decode!(&unhex(golden), TaskFailReason).unwrap(), timeout);

        let golden =
            "4449444c016b04fed9cbe90578d4b4c59a097fb3f39abf0b71ab8e83800e710100000900000000000000";
        let err = SubmitTaskError::NonExistingTaskSubmitted(9);
        assert_eq!(hex(&Encode!(&err).unwrap()), golden);
        assert_eq!(Decode!(&unhex(golden), SubmitTaskError).unwrap(), err);
    }

    // ---------------------------------------------------------------------------------------
    // Wire compatibility across versions.
    // ---------------------------------------------------------------------------------------

    /// `InputTask` as it looked before `wildcard`/`canister_id` were added.
    #[derive(CandidType, Serialize)]
    struct LegacyInputTask {
        kind: TaskKind,
        domain: String,
    }

    /// `ScheduledTask` as it looked before `wildcard`/`canister_id` were added.
    #[derive(CandidType, Serialize)]
    struct LegacyScheduledTask {
        kind: TaskKind,
        domain: String,
        id: TaskId,
        enc_cert: Option<Vec<u8>>,
    }

    #[test]
    fn test_task_inputs_decode_from_pre_wildcard_encodings() {
        let bytes = Encode!(&LegacyInputTask {
            kind: TaskKind::Issue,
            domain: "old.example.com".into(),
        })
        .unwrap();
        let task = Decode!(&bytes, InputTask).expect("old clients must keep working");
        assert_eq!(task.kind, TaskKind::Issue);
        assert_eq!(task.domain, "old.example.com");
        assert_eq!(task.wildcard, None);
        assert_eq!(task.canister_id, None);

        let bytes = Encode!(&LegacyScheduledTask {
            kind: TaskKind::Renew,
            domain: "old.example.com".into(),
            id: 17,
            enc_cert: Some(vec![9]),
        })
        .unwrap();
        let task = Decode!(&bytes, ScheduledTask).expect("old workers must keep working");
        assert_eq!(
            task,
            ScheduledTask::new(
                TaskKind::Renew,
                "old.example.com".into(),
                17,
                Some(vec![9]),
                None,
                None
            )
        );
    }

    /// A future version of the canister may add fields; current clients must ignore them.
    #[test]
    fn test_input_task_ignores_unknown_future_fields() {
        #[derive(CandidType, Serialize)]
        struct FutureInputTask {
            kind: TaskKind,
            domain: String,
            wildcard: Option<bool>,
            canister_id: Option<Principal>,
            some_field_from_the_future: u64,
        }

        let bytes = Encode!(&FutureInputTask {
            kind: TaskKind::Delete,
            domain: "future.example.com".into(),
            wildcard: Some(false),
            canister_id: Some(principal()),
            some_field_from_the_future: 5,
        })
        .unwrap();

        let task = Decode!(&bytes, InputTask).expect("unknown fields must be ignored");
        assert_eq!(task.kind, TaskKind::Delete);
        assert_eq!(task.wildcard, Some(false));
        assert_eq!(task.canister_id, Some(principal()));
    }

    /// `ListedDomainEntry` is `DomainEntry` plus the required `domain` field and minus the two
    /// optional certificate blobs, so decoding is possible in exactly one direction.
    #[test]
    fn test_listed_entry_and_domain_entry_subtyping() {
        let listed = full_listed_entry();
        let entry = Decode!(&Encode!(&listed).unwrap(), DomainEntry)
            .expect("ListedDomainEntry is a candid subtype of DomainEntry");
        assert_eq!(entry.task, listed.task);
        assert_eq!(entry.created_at, listed.created_at);
        assert_eq!(entry.wildcard, listed.wildcard);
        assert_eq!(entry.not_after, listed.not_after);
        assert_eq!(entry.last_failure_reason, listed.last_failure_reason);
        // The certificate blobs simply aren't there.
        assert_eq!(entry.enc_cert, None);
        assert_eq!(entry.enc_priv_key, None);

        // The other direction must fail: `domain` is required and DomainEntry has no such field.
        let bytes = Encode!(&full_domain_entry()).unwrap();
        assert!(
            Decode!(&bytes, ListedDomainEntry).is_err(),
            "DomainEntry must not silently decode as ListedDomainEntry with an empty domain"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Value round-trips.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn test_round_trip_task_types() {
        round_trip(&InitArg {
            authorized_principal: Some(principal()),
        });
        round_trip(&InitArg {
            authorized_principal: None,
        });

        for kind in ALL_TASK_KINDS {
            round_trip(&InputTask {
                kind,
                domain: "a.example.com".into(),
                wildcard: Some(true),
                canister_id: Some(principal()),
            });
            round_trip(&ScheduledTask::new(
                kind,
                "a.example.com".into(),
                1,
                Some(vec![1, 2, 3]),
                Some(false),
                None,
            ));
        }

        // All-optional-absent variants.
        round_trip(&InputTask {
            kind: TaskKind::Issue,
            domain: String::new(),
            wildcard: None,
            canister_id: None,
        });
        round_trip(&ScheduledTask::new(
            TaskKind::Delete,
            String::new(),
            0,
            None,
            None,
            None,
        ));

        for outcome in [
            TaskOutcome::Success(TaskOutput::Issue(issue_output())),
            TaskOutcome::Success(TaskOutput::Update(principal())),
            TaskOutcome::Success(TaskOutput::Delete),
            TaskOutcome::Failure(TaskFailReason::ValidationFailed("bad".into())),
            TaskOutcome::Failure(TaskFailReason::Timeout { duration_secs: 1 }),
            TaskOutcome::Failure(TaskFailReason::RateLimited),
            TaskOutcome::Failure(TaskFailReason::GenericFailure(String::new())),
        ] {
            round_trip(&TaskResult {
                domain: "a.example.com".into(),
                outcome,
                task_id: 42,
                task_kind: TaskKind::Issue,
                duration_secs: 9,
            });
        }
    }

    #[test]
    fn test_round_trip_domain_types() {
        for status in RegistrationStatus::iter() {
            let decoded = round_trip(&DomainStatus {
                domain: "a.example.com".into(),
                canister_id: Some(principal()),
                status: status.clone(),
            });
            assert_eq!(decoded.status, status);
        }

        assert_eq!(round_trip(&full_domain_entry()), full_domain_entry());
        assert_eq!(round_trip(&full_listed_entry()), full_listed_entry());

        // Everything optional absent.
        let empty = DomainEntry {
            task: None,
            last_fail_time: None,
            last_failure_reason: None,
            failures_count: 0,
            rate_limit_failures_count: 0,
            canister_id: None,
            created_at: 0,
            taken_at: None,
            task_created_at: None,
            enc_cert: None,
            enc_priv_key: None,
            not_before: None,
            not_after: None,
            wildcard: None,
        };
        assert_eq!(round_trip(&empty), empty);
    }

    #[test]
    fn test_round_trip_pages() {
        let cert_page = CertificatesPage::new(
            vec![RegisteredDomain {
                domain: "a.example.com".into(),
                canister_id: principal(),
                enc_cert: vec![1],
                enc_priv_key: vec![],
            }],
            Some("b.example.com".into()),
        );
        round_trip(&cert_page);
        round_trip(&CertificatesPage::new(vec![], None));

        round_trip(&DomainsPage::new(
            vec![full_listed_entry(), full_listed_entry()],
            None,
        ));
        round_trip(&DomainsPage::new(vec![], Some(String::new())));

        round_trip(&ListCertificatesPageInput {
            start_key: Some("k".into()),
            limit: Some(MAX_PAGE_LIMIT),
        });
        round_trip(&ListDomainsPageInput {
            start_key: None,
            limit: Some(0),
        });
    }

    #[test]
    fn test_round_trip_every_error_variant() {
        for e in [
            TaskFailReason::ValidationFailed("v".into()),
            TaskFailReason::Timeout {
                duration_secs: u64::MAX,
            },
            TaskFailReason::RateLimited,
            TaskFailReason::GenericFailure("g".into()),
        ] {
            assert_eq!(round_trip(&e), e);
        }

        for e in [
            SubmitTaskError::Unauthorized,
            SubmitTaskError::DomainNotFound("d".into()),
            SubmitTaskError::NonExistingTaskSubmitted(u64::MAX),
            SubmitTaskError::InternalError("i".into()),
        ] {
            assert_eq!(round_trip(&e), e);
        }

        for e in [
            TryAddTaskError::Unauthorized,
            TryAddTaskError::DomainNotFound("d".into()),
            TryAddTaskError::AnotherTaskInProgress("d".into()),
            TryAddTaskError::CertificateAlreadyIssued("d".into()),
            TryAddTaskError::MissingCertificateForUpdate("d".into()),
            TryAddTaskError::InternalError("i".into()),
        ] {
            round_trip(&e);
        }

        for e in [
            HasNextTaskError::Unauthorized,
            HasNextTaskError::InternalError("i".into()),
        ] {
            assert_eq!(round_trip(&e), e);
        }

        round_trip(&FetchTaskError::Unauthorized);
        round_trip(&FetchTaskError::InternalError("i".into()));
        round_trip(&GetDomainStatusError::Unauthorized);
        round_trip(&GetDomainStatusError::InternalError("i".into()));
        round_trip(&GetDomainEntryError::Unauthorized);
        round_trip(&GetDomainEntryError::InternalError("i".into()));
        round_trip(&GetLastChangeTimeError::Unauthorized);
        round_trip(&GetLastChangeTimeError::InternalError("i".into()));
        round_trip(&ListCertificatesPageError::Unauthorized);
        round_trip(&ListCertificatesPageError::InternalError("i".into()));
        round_trip(&ListDomainsPageError::Unauthorized);
        round_trip(&ListDomainsPageError::InternalError("i".into()));
    }

    #[test]
    fn test_round_trip_result_aliases() {
        let task = ScheduledTask::new(
            TaskKind::Issue,
            "a.example.com".into(),
            1,
            None,
            Some(true),
            Some(principal()),
        );
        let v: FetchTaskResult = Ok(Some(task.clone()));
        assert_eq!(round_trip(&v).unwrap(), Some(task));
        let v: FetchTaskResult = Ok(None);
        assert_eq!(round_trip(&v).unwrap(), None);
        let v: FetchTaskResult = Err(FetchTaskError::Unauthorized);
        assert!(matches!(round_trip(&v), Err(FetchTaskError::Unauthorized)));

        let v: SubmitTaskResult = Ok(());
        assert_eq!(round_trip(&v), Ok(()));
        let v: SubmitTaskResult = Err(SubmitTaskError::NonExistingTaskSubmitted(3));
        assert_eq!(
            round_trip(&v),
            Err(SubmitTaskError::NonExistingTaskSubmitted(3))
        );

        let v: TryAddTaskResult = Ok(());
        assert!(round_trip(&v).is_ok());
        let v: TryAddTaskResult = Err(TryAddTaskError::AnotherTaskInProgress("d".into()));
        assert!(matches!(
            round_trip(&v),
            Err(TryAddTaskError::AnotherTaskInProgress(d)) if d == "d"
        ));

        let v: HasNextTaskResult = Ok(true);
        assert_eq!(round_trip(&v), Ok(true));
        let v: HasNextTaskResult = Ok(false);
        assert_eq!(round_trip(&v), Ok(false));
        let v: HasNextTaskResult = Err(HasNextTaskError::InternalError("x".into()));
        assert_eq!(
            round_trip(&v),
            Err(HasNextTaskError::InternalError("x".into()))
        );

        let v: GetLastChangeTimeResult = Ok(u64::MAX);
        assert_eq!(round_trip(&v).unwrap(), u64::MAX);
        let v: GetLastChangeTimeResult = Ok(0);
        assert_eq!(round_trip(&v).unwrap(), 0);
        let v: GetLastChangeTimeResult = Err(GetLastChangeTimeError::Unauthorized);
        assert!(round_trip(&v).is_err());

        let v: GetDomainStatusResult = Ok(None);
        assert_eq!(round_trip(&v).unwrap(), None);
        let status = DomainStatus {
            domain: "a.example.com".into(),
            canister_id: None,
            status: RegistrationStatus::Failed("boom".into()),
        };
        let v: GetDomainStatusResult = Ok(Some(status.clone()));
        assert_eq!(round_trip(&v).unwrap(), Some(status));

        let v: GetDomainEntryResult = Ok(Some(full_domain_entry()));
        assert_eq!(round_trip(&v).unwrap(), Some(full_domain_entry()));
        let v: GetDomainEntryResult = Err(GetDomainEntryError::Unauthorized);
        assert!(round_trip(&v).is_err());

        let v: ListCertificatesPageResult = Ok(CertificatesPage::new(vec![], None));
        assert!(round_trip(&v).unwrap().items.is_empty());
        let v: ListDomainsPageResult = Ok(DomainsPage::new(vec![full_listed_entry()], None));
        assert_eq!(round_trip(&v).unwrap().items, vec![full_listed_entry()]);
        let v: ListDomainsPageResult = Err(ListDomainsPageError::Unauthorized);
        assert!(round_trip(&v).is_err());
    }

    #[test]
    fn test_round_trip_edge_case_values() {
        // Saturated numeric fields.
        let entry = DomainEntry {
            failures_count: u32::MAX,
            rate_limit_failures_count: u32::MAX,
            created_at: u64::MAX,
            not_before: Some(u64::MAX),
            not_after: Some(0),
            ..full_domain_entry()
        };
        assert_eq!(round_trip(&entry), entry);

        // Special principals: management (zero-length) and anonymous (single byte).
        for p in [
            Principal::management_canister(),
            Principal::anonymous(),
            principal(),
        ] {
            let decoded = round_trip(&DomainStatus {
                domain: "a.example.com".into(),
                canister_id: Some(p),
                status: RegistrationStatus::Registered,
            });
            assert_eq!(decoded.canister_id, Some(p));
        }

        // Non-ASCII and empty domains survive as bytes, plus an empty and a large blob.
        for domain in ["", "ünïcodé.example.com", "*.wildcard.example.com"] {
            let decoded = round_trip(&RegisteredDomain {
                domain: domain.to_string(),
                canister_id: principal(),
                enc_cert: vec![],
                enc_priv_key: vec![0xff; 4096],
            });
            assert_eq!(decoded.domain, domain);
            assert!(decoded.enc_cert.is_empty());
            assert_eq!(decoded.enc_priv_key.len(), 4096);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Display / strum labels. The static strings are used as Prometheus label values, so they
    // must stay snake_case and stable.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn test_task_kind_labels_are_snake_case() {
        assert_eq!(<&'static str>::from(TaskKind::Issue), "issue");
        assert_eq!(<&'static str>::from(TaskKind::Renew), "renew");
        assert_eq!(<&'static str>::from(TaskKind::Update), "update");
        assert_eq!(<&'static str>::from(TaskKind::Delete), "delete");
    }

    #[test]
    fn test_task_kind_is_a_usable_map_key() {
        // TaskKind is used as a HashMap key for per-kind stats, so all four must be distinct.
        let set: HashSet<TaskKind> = ALL_TASK_KINDS.into_iter().collect();
        assert_eq!(set.len(), 4);
        assert!(set.contains(&TaskKind::Renew));
    }

    #[test]
    fn test_registration_status_labels_and_iteration() {
        // EnumIter is what drives "report every status, even the zero ones" in the metrics.
        let statuses = RegistrationStatus::iter().collect::<Vec<_>>();
        assert_eq!(
            statuses,
            vec![
                RegistrationStatus::Registering,
                RegistrationStatus::Registered,
                RegistrationStatus::Expired,
                RegistrationStatus::Failed(String::new()),
            ]
        );
        assert_eq!(
            statuses
                .iter()
                .map(<&'static str>::from)
                .collect::<Vec<_>>(),
            vec!["registering", "registered", "expired", "failed"]
        );
        // The payload must not leak into the label.
        assert_eq!(
            <&'static str>::from(&RegistrationStatus::Failed("some long reason".into())),
            "failed"
        );
        assert_ne!(
            RegistrationStatus::Failed("a".into()),
            RegistrationStatus::Failed("b".into())
        );
    }

    #[test]
    fn test_task_fail_reason_labels_and_display() {
        let cases = [
            (
                TaskFailReason::ValidationFailed("dns lookup".into()),
                "validation_failed",
                "validation_failed: dns lookup",
            ),
            (
                TaskFailReason::Timeout { duration_secs: 42 },
                "timeout",
                "timeout after 42s",
            ),
            (TaskFailReason::RateLimited, "rate_limited", "rate_limited"),
            (
                TaskFailReason::GenericFailure(String::new()),
                "generic_failure",
                "generic_failure: ",
            ),
        ];

        for (reason, label, display) in cases {
            assert_eq!(<&'static str>::from(&reason), label);
            assert_eq!(reason.to_string(), display);
        }
    }

    #[test]
    fn test_error_labels_and_display() {
        assert_eq!(
            <&'static str>::from(&FetchTaskError::Unauthorized),
            "unauthorized"
        );
        assert_eq!(
            <&'static str>::from(&FetchTaskError::InternalError("x".into())),
            "internal_error"
        );
        assert_eq!(FetchTaskError::Unauthorized.to_string(), "Unauthorized");
        assert_eq!(
            FetchTaskError::InternalError("boom".into()).to_string(),
            "Internal error: boom"
        );

        let cases: [(SubmitTaskError, &str, &str); 4] = [
            (
                SubmitTaskError::Unauthorized,
                "unauthorized",
                "Unauthorized",
            ),
            (
                SubmitTaskError::DomainNotFound("a.com".into()),
                "domain_not_found",
                "Domain not found: a.com",
            ),
            (
                SubmitTaskError::NonExistingTaskSubmitted(7),
                "non_existing_task_submitted",
                "A non-existing task was submitted: 7",
            ),
            (
                SubmitTaskError::InternalError("boom".into()),
                "internal_error",
                "Internal error: boom",
            ),
        ];
        for (err, label, display) in cases {
            assert_eq!(<&'static str>::from(&err), label);
            assert_eq!(err.to_string(), display);
        }

        let cases: [(TryAddTaskError, &str, &str); 6] = [
            (
                TryAddTaskError::Unauthorized,
                "unauthorized",
                "Unauthorized",
            ),
            (
                TryAddTaskError::DomainNotFound("a.com".into()),
                "domain_not_found",
                "Domain not found: a.com",
            ),
            (
                TryAddTaskError::AnotherTaskInProgress("a.com".into()),
                "another_task_in_progress",
                "Another task is already in progress for domain: a.com",
            ),
            (
                TryAddTaskError::CertificateAlreadyIssued("a.com".into()),
                "certificate_already_issued",
                "Certificate already issued for domain: a.com",
            ),
            (
                TryAddTaskError::MissingCertificateForUpdate("a.com".into()),
                "missing_certificate_for_update",
                "Update requires an existing certificate: a.com",
            ),
            (
                TryAddTaskError::InternalError("boom".into()),
                "internal_error",
                "Internal error: boom",
            ),
        ];
        for (err, label, display) in cases {
            assert_eq!(<&'static str>::from(&err), label);
            assert_eq!(err.to_string(), display);
        }

        assert_eq!(
            GetDomainStatusError::InternalError("x".into()).to_string(),
            "Internal error: x"
        );
        assert_eq!(
            GetDomainEntryError::Unauthorized.to_string(),
            "Unauthorized"
        );
        assert_eq!(
            GetLastChangeTimeError::InternalError("x".into()).to_string(),
            "Internal error: x"
        );
        assert_eq!(
            ListCertificatesPageError::Unauthorized.to_string(),
            "Unauthorized"
        );
        assert_eq!(
            ListDomainsPageError::InternalError("x".into()).to_string(),
            "Internal error: x"
        );
        assert_eq!(HasNextTaskError::Unauthorized.to_string(), "Unauthorized");
    }

    // ---------------------------------------------------------------------------------------
    // Constructors, defaults and constants.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn test_page_inputs_default_to_unbounded() {
        let d = ListCertificatesPageInput::default();
        assert!(d.start_key.is_none());
        assert!(d.limit.is_none());
        assert_eq!(
            format!("{d:?}"),
            format!("{:?}", ListCertificatesPageInput::new())
        );

        let d = ListDomainsPageInput::default();
        assert!(d.start_key.is_none());
        assert!(d.limit.is_none());
        assert_eq!(
            format!("{d:?}"),
            format!("{:?}", ListDomainsPageInput::new())
        );
    }

    #[test]
    fn test_page_constructors_preserve_arguments() {
        let items = vec![RegisteredDomain {
            domain: "a.example.com".into(),
            canister_id: principal(),
            enc_cert: vec![1],
            enc_priv_key: vec![2],
        }];
        let page = CertificatesPage::new(items.clone(), Some("next".into()));
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].domain, items[0].domain);
        assert_eq!(page.next_key.as_deref(), Some("next"));

        let page = DomainsPage::new(vec![full_listed_entry()], None);
        assert_eq!(page.items, vec![full_listed_entry()]);
        assert!(page.next_key.is_none());
    }

    #[test]
    fn test_scheduled_task_new_maps_arguments_in_order() {
        let task = ScheduledTask::new(
            TaskKind::Update,
            "new.example.com".into(),
            99,
            Some(vec![7, 8]),
            Some(true),
            Some(principal()),
        );
        assert_eq!(task.kind, TaskKind::Update);
        assert_eq!(task.domain, "new.example.com");
        assert_eq!(task.id, 99);
        assert_eq!(task.enc_cert, Some(vec![7, 8]));
        assert_eq!(task.wildcard, Some(true));
        assert_eq!(task.canister_id, Some(principal()));
    }

    #[test]
    // The whole point of this test is to assert relationships between constants.
    #[allow(clippy::assertions_on_constants)]
    fn test_constant_invariants() {
        // Both thresholds are fractions of the certificate validity period.
        assert!(CERTIFICATE_VALIDITY_FRACTION > 0.0 && CERTIFICATE_VALIDITY_FRACTION < 1.0);
        assert!(
            CERT_EXPIRATION_ALERT_THRESHOLD > 0.0 && CERT_EXPIRATION_ALERT_THRESHOLD < 1.0,
            "the alert threshold is a fraction of remaining validity"
        );
        // Renewal (measured in elapsed validity) has to kick in before the alert threshold
        // (measured in remaining validity), otherwise every renewal would page someone.
        assert!(
            CERTIFICATE_VALIDITY_FRACTION < 1.0 - CERT_EXPIRATION_ALERT_THRESHOLD,
            "renewal must start before a domain is considered nearing expiration"
        );

        assert!(DEFAULT_PAGE_LIMIT > 0);
        assert!(
            DEFAULT_PAGE_LIMIT <= MAX_PAGE_LIMIT,
            "the default page size must be servable"
        );

        // A worker that dies must have its task rescheduled long before the domain is purged.
        assert!(MIN_TASK_RETRY_DELAY < TASK_TIMEOUT);
        assert!(TASK_TIMEOUT < UNREGISTERED_DOMAIN_EXPIRATION_TIME);
        assert!(UNREGISTERED_DOMAIN_EXPIRATION_TIME < EXPIRED_DOMAIN_EXPIRATION_TIME);
        assert!(MAX_TASK_FAILURES > 0);

        // Spelled with `from_hours`, so pin the actual number of seconds.
        assert_eq!(STALE_DOMAINS_CLEANUP_INTERVAL.as_secs(), 3 * 60 * 60);
        assert_eq!(TASK_TIMEOUT.as_secs(), 600);
        assert_eq!(UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs(), 86_400);
        assert_eq!(EXPIRED_DOMAIN_EXPIRATION_TIME.as_secs(), 604_800);
        assert!(
            STALE_DOMAINS_CLEANUP_INTERVAL < UNREGISTERED_DOMAIN_EXPIRATION_TIME,
            "cleanup has to run more often than domains expire"
        );
    }

    /// The `submit_task_result` argument is the most complex value on the wire: a record
    /// containing a variant containing a variant containing a record. The shared prefix below is
    /// the candid type table (i.e. every field-name and variant-name hash), so a rename anywhere
    /// in that tree moves these bytes even when the Rust code still compiles.
    const TASK_RESULT_PREFIX: &str = "4449444c086c05d597bbf30178c4e282ec0271cdffddc30978ce87bf8f0b0192f1bede0d026b04b997eea4057feddcc7cf077fcbe8b4fb097fa9f4e7dc0b7f6b02a39bfdac0803aab0aea20e066b03b997eea40504cbe8b4fb097fa9f4e7dc0b686c05ebcac45178b3c4b1f20468b0adf88e0678d4b9e6d70a05a9918cca0f056d7b6b04f6a5ce6071ba8a96b00a7f8185a1b20a0793f680a00c716c01cdffddc30978010007000000000000000d672e6578616d706c652e636f6d";

    #[test]
    fn test_task_result_wire_bytes_are_frozen() {
        let cases = [
            (
                TaskResult {
                    domain: "g.example.com".into(),
                    outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
                        canister_id: principal(),
                        enc_cert: vec![0x01, 0x02],
                        enc_priv_key: vec![0x03],
                        not_before: 1_700_000_000,
                        not_after: 1_700_086_400,
                    })),
                    task_id: 7,
                    task_kind: TaskKind::Issue,
                    duration_secs: 12,
                },
                "0c0000000000000000000000f1536500000000010a0000000000000007010180425565000000000103020102",
            ),
            (
                TaskResult {
                    domain: "g.example.com".into(),
                    outcome: TaskOutcome::Success(TaskOutput::Delete),
                    task_id: 7,
                    task_kind: TaskKind::Delete,
                    duration_secs: 0,
                },
                "0000000000000000020001",
            ),
            (
                TaskResult {
                    domain: "g.example.com".into(),
                    outcome: TaskOutcome::Success(TaskOutput::Update(principal())),
                    task_id: 7,
                    task_kind: TaskKind::Update,
                    duration_secs: 1,
                },
                "0100000000000000030002010a00000000000000070101",
            ),
            (
                TaskResult {
                    domain: "g.example.com".into(),
                    outcome: TaskOutcome::Failure(TaskFailReason::RateLimited),
                    task_id: 7,
                    task_kind: TaskKind::Renew,
                    duration_secs: 3,
                },
                "0300000000000000010101",
            ),
        ];

        for (result, suffix) in cases {
            let golden = format!("{TASK_RESULT_PREFIX}{suffix}");
            assert_eq!(
                hex(&Encode!(&result).unwrap()),
                golden,
                "encoding {result:?}"
            );
            // Bytes from an already-deployed worker still decode into the same value.
            let decoded = Decode!(&unhex(&golden), TaskResult).unwrap();
            assert_eq!(format!("{decoded:?}"), format!("{result:?}"));
        }
    }

    /// Candid resolves variants by name hash, so a *new* variant added to a type the canister
    /// returns is not backwards compatible: already-deployed clients reject it outright rather
    /// than falling back to some default. This pins that rule, because it is the reason
    /// [`RegistrationStatus`] and [`TaskFailReason`] cannot be extended silently.
    #[test]
    fn test_unknown_variants_are_rejected_not_defaulted() {
        #[derive(CandidType, Serialize)]
        enum FutureRegistrationStatus {
            Registering,
            #[allow(dead_code)]
            Suspended(String),
        }

        // A value using a variant the current type also knows still decodes.
        let bytes = Encode!(&FutureRegistrationStatus::Registering).unwrap();
        assert_eq!(
            Decode!(&bytes, RegistrationStatus).unwrap(),
            RegistrationStatus::Registering
        );

        // ...but the new one does not.
        let bytes = Encode!(&FutureRegistrationStatus::Suspended("why".into())).unwrap();
        assert!(
            Decode!(&bytes, RegistrationStatus).is_err(),
            "an unknown status must not decode as an existing variant"
        );

        #[derive(CandidType, Serialize)]
        enum FutureTaskFailReason {
            #[allow(dead_code)]
            RateLimited,
            QuotaExceeded(u64),
        }
        let bytes = Encode!(&FutureTaskFailReason::QuotaExceeded(1)).unwrap();
        assert!(Decode!(&bytes, TaskFailReason).is_err());
    }
}
