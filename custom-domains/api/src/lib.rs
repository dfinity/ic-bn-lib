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
pub const STALE_DOMAINS_CLEANUP_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);

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
    // Whether to also include a `*.domain` wildcard SAN in the certificate
    pub wildcard: Option<bool>,
}

#[derive(CandidType, Deserialize, Serialize, Debug, Clone, PartialEq, Eq, new)]
pub struct ScheduledTask {
    pub kind: TaskKind,
    pub domain: String,
    pub id: TaskId,
    pub enc_cert: Option<Vec<u8>>,
    // Whether to also include a `*.domain` wildcard SAN in the certificate
    pub wildcard: Option<bool>,
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
