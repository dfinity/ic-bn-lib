use std::time::Duration;

use candid::Principal;
use derive_new::new;
use fqdn::FQDN;
use ic_custom_domains_canister_api::{
    InputTask as ApiInputTask, IssueCertificateOutput as ApiIssueCertificateOutput,
    TaskFailReason as ApiTaskFailReason, TaskKind as ApiTaskKind, TaskOutcome as ApiTaskOutcome,
    TaskOutput as ApiTaskOutput, TaskResult as ApiTaskResult,
};
use strum::{AsRefStr, Display, IntoStaticStr};

use crate::custom_domains::base::traits::time::UtcTimestamp;

/// Represents different types of domain certificate tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum TaskKind {
    /// Initial certificate issuance for a new domain
    Issue,
    /// Certificate renewal for an existing domain
    Renew,
    /// Update domain configuration if canister ID changes
    Update,
    /// Delete domain and revoke its certificate
    Delete,
}

/// A task submitted by user for further scheduling and execution.
#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct InputTask {
    /// The type of task to perform
    pub kind: TaskKind,
    /// The domain to process
    pub domain: FQDN,
    /// Whether to also include a `*.domain` wildcard SAN in the certificate
    pub wildcard: bool,
    /// The canister ID associated with the domain (if known at submission time)
    pub canister_id: Option<Principal>,
}

/// Scheduled task that is ready for execution by a worker.
#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct ScheduledTask {
    /// The type of task to perform
    pub kind: TaskKind,
    /// The domain to process
    pub domain: FQDN,
    /// Unique task identifier (timestamp)
    pub task_id: UtcTimestamp,
    /// Existing certificate data (for renewal/deletion tasks)
    pub cert: Option<Vec<u8>>,
    /// Whether to also include a `*.domain` wildcard SAN in the certificate
    pub wildcard: bool,
    /// The canister ID associated with the domain (if known at submission time)
    pub canister_id: Option<Principal>,
}

/// Represents the result of a task execution submitted by a worker to the repository.
///
/// Contains all relevant information about task completion:
/// - If `output` is `Some`, the task succeeded.
/// - If `failure` is `Some`, the task failed.
///   Only one of these can be `Some`.
#[derive(Debug, Clone)]
pub struct TaskResult {
    /// The domain that was processed
    pub domain: FQDN,
    /// Task outcome
    pub outcome: TaskOutcome,
    /// Unique task identifier
    pub task_id: UtcTimestamp,
    /// The type of task that was executed
    pub task_kind: TaskKind,
    /// Time taken to execute the task
    pub duration: Duration,
}

impl TaskResult {
    /// Creates a successful task result.
    pub const fn success(
        domain: FQDN,
        output: TaskOutput,
        task_id: UtcTimestamp,
        task_kind: TaskKind,
    ) -> Self {
        Self {
            domain,
            outcome: TaskOutcome::Success(output),
            task_id,
            task_kind,
            duration: Duration::ZERO,
        }
    }

    /// Creates a failed task result.
    pub const fn failure(
        domain: FQDN,
        failure: TaskFailReason,
        task_id: UtcTimestamp,
        task_kind: TaskKind,
    ) -> Self {
        Self {
            domain,
            outcome: TaskOutcome::Failure(failure),
            task_id,
            task_kind,
            duration: Duration::ZERO,
        }
    }
}

impl TaskResult {
    /// Sets the duration for this task result.
    pub const fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// Checks if the task execution was successful
    pub const fn is_success(&self) -> bool {
        matches!(self.outcome, TaskOutcome::Success(_))
    }
}

/// Outcome of a task execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOutcome {
    Success(TaskOutput),
    Failure(TaskFailReason),
}

impl From<TaskOutcome> for ApiTaskOutcome {
    fn from(value: TaskOutcome) -> Self {
        match value {
            TaskOutcome::Success(v) => Self::Success(v.into()),
            TaskOutcome::Failure(v) => Self::Failure(v.into()),
        }
    }
}

/// Output data from successful task execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOutput {
    /// Certificate issuance output containing cert, key, and validity info
    Issue(IssueCertificateOutput),
    /// Domain update output containing the new canister ID
    Update(Principal),
    /// Domain deletion output (no additional data)
    Delete,
}

// TODO: add request_id to the body? (should be already in the header once intergrated into ic-gateway)
#[derive(Debug, Clone, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TaskFailReason {
    /// Domain validation failed with a specific error message
    ValidationFailed(String),
    /// Task execution exceeded the allowed time limit
    Timeout { duration_secs: u64 },
    /// Let's Encrypt rate limit exceeded (https://letsencrypt.org/docs/rate-limits/)
    RateLimited,
    /// Generic failure with error details
    GenericFailure(String),
}

/// Output from successful certificate issuance containing all certificate data.
#[derive(Debug, Clone, PartialEq, Eq, new)]
pub struct IssueCertificateOutput {
    /// The canister ID this certificate is issued for
    pub canister_id: Principal,
    /// The PEM-encoded certificate chain
    pub cert: Vec<u8>,
    /// The PEM-encoded private key
    pub priv_key: Vec<u8>,
    /// Certificate validity start time (Unix timestamp)
    pub not_before: UtcTimestamp,
    /// Certificate validity end time (Unix timestamp)
    pub not_after: UtcTimestamp,
}

impl From<ApiTaskKind> for TaskKind {
    fn from(task_kind: ApiTaskKind) -> Self {
        match task_kind {
            ApiTaskKind::Issue => Self::Issue,
            ApiTaskKind::Renew => Self::Renew,
            ApiTaskKind::Update => Self::Update,
            ApiTaskKind::Delete => Self::Delete,
        }
    }
}

impl From<InputTask> for ApiInputTask {
    fn from(task: InputTask) -> Self {
        Self {
            kind: task.kind.into(),
            domain: task.domain.to_string(),
            wildcard: Some(task.wildcard),
            canister_id: task.canister_id,
        }
    }
}

impl From<TaskKind> for ApiTaskKind {
    fn from(task_kind: TaskKind) -> Self {
        match task_kind {
            TaskKind::Issue => Self::Issue,
            TaskKind::Renew => Self::Renew,
            TaskKind::Update => Self::Update,
            TaskKind::Delete => Self::Delete,
        }
    }
}

impl From<TaskOutput> for ApiTaskOutput {
    fn from(output: TaskOutput) -> Self {
        match output {
            TaskOutput::Issue(issue_output) => Self::Issue(issue_output.into()),
            TaskOutput::Update(principal) => Self::Update(principal),
            TaskOutput::Delete => Self::Delete,
        }
    }
}

impl From<IssueCertificateOutput> for ApiIssueCertificateOutput {
    fn from(output: IssueCertificateOutput) -> Self {
        Self {
            canister_id: output.canister_id,
            enc_cert: output.cert,
            enc_priv_key: output.priv_key,
            not_before: output.not_before,
            not_after: output.not_after,
        }
    }
}

impl From<TaskResult> for ApiTaskResult {
    fn from(task_result: TaskResult) -> Self {
        Self {
            domain: task_result.domain.to_string(),
            outcome: task_result.outcome.into(),
            task_id: task_result.task_id,
            task_kind: ApiTaskKind::from(task_result.task_kind),
            duration_secs: task_result.duration.as_secs(),
        }
    }
}

impl From<TaskFailReason> for ApiTaskFailReason {
    fn from(failure: TaskFailReason) -> Self {
        match failure {
            TaskFailReason::ValidationFailed(reason) => Self::ValidationFailed(reason),
            TaskFailReason::Timeout { duration_secs } => Self::Timeout { duration_secs },
            TaskFailReason::RateLimited => Self::RateLimited,
            TaskFailReason::GenericFailure(reason) => Self::GenericFailure(reason),
        }
    }
}
