use std::{borrow::Cow, collections::HashMap, hash::Hash, ops::Bound as RangeBound};

use candid::Principal;
use ic_custom_domains_canister_api::{
    CERT_EXPIRATION_ALERT_THRESHOLD, CERTIFICATE_VALIDITY_FRACTION, CertificatesPage,
    DEFAULT_PAGE_LIMIT, DomainEntry as DomainEntryApi, DomainStatus, DomainsPage,
    EXPIRED_DOMAIN_EXPIRATION_TIME, FetchTaskResult, GetDomainEntryResult, GetDomainStatusResult,
    GetLastChangeTimeResult, HasNextTaskResult, InputTask, ListCertificatesPageInput,
    ListCertificatesPageResult, ListDomainsPageInput, ListDomainsPageResult, ListedDomainEntry,
    MAX_PAGE_LIMIT, MAX_TASK_FAILURES, MIN_TASK_RETRY_DELAY, RegisteredDomain, RegistrationStatus,
    ScheduledTask, SubmitTaskError, SubmitTaskResult, TASK_TIMEOUT, TaskFailReason, TaskKind,
    TaskOutcome, TaskOutput, TaskResult, TryAddTaskError, TryAddTaskResult,
    UNREGISTERED_DOMAIN_EXPIRATION_TIME,
};
use ic_http_types::{HttpResponse, HttpResponseBuilder};
use ic_stable_structures::{
    DefaultMemoryImpl, StableBTreeMap, StableCell, Storable, memory_manager::VirtualMemory,
    storable::Bound,
};
use serde::{Deserialize, Serialize};
use serde_cbor::{from_slice, to_vec};
use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};

use crate::{
    metrics::{
        FAILURE_STATUS, FETCH_NEXT_TASK_FUNC, METRICS, SUBMIT_TASK_RESULT_FUNC, SUCCESS_STATUS,
        TRY_ADD_TASK_FUNC,
    },
    storage::STATE,
};

/// Timestamp representing seconds in UTC since the UNIX epoch (January 1, 1970).
pub type UtcTimestamp = u64;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEntry {
    /// Current task being processed for the domain, if any
    pub task: Option<TaskKind>,
    /// Timestamp when the task failed last time, if any
    pub last_fail_time: Option<UtcTimestamp>,
    /// Reason for the last failure, if any
    pub last_failure_reason: Option<TaskFailReason>,
    /// Number of consecutive failures for the current task (excluding rate limit failures)
    pub failures_count: u32,
    /// Number of rate limit failures for the current task
    pub rate_limit_failures_count: u32,
    /// Canister ID associated with the domain
    pub canister_id: Option<Principal>,
    /// Timestamp when the domain entry was created (set once and never updated)
    pub created_at: UtcTimestamp,
    /// Timestamp when the current task was taken by a worker
    pub taken_at: Option<UtcTimestamp>,
    /// Timestamp when the current task was created
    pub task_created_at: Option<UtcTimestamp>,
    /// Certificate validity period start (as UNIX timestamp)
    pub not_before: Option<UtcTimestamp>,
    /// Certificate validity period end (as UNIX timestamp)
    pub not_after: Option<UtcTimestamp>,
    /// Whether to also issue a `*.domain` wildcard SAN in the certificate.
    /// `#[serde(default)]` keeps existing stable-storage entries deserializable
    /// after upgrade (they predate this field and default to `false`).
    #[serde(default)]
    pub wildcard: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateEntry {
    /// PEM-encoded certificate data (encrypted)
    pub enc_cert: Vec<u8>,
    /// PEM-encoded private key data (encrypted)
    pub enc_priv_key: Vec<u8>,
}

impl Storable for CertificateEntry {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("CertificateEntry serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        to_vec(&self).expect("CertificateEntry serialization failed")
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("CertificateEntry deserialization failed")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum TaskStatus {
    /// Task is pending and has not been taken by any worker yet
    Pending(TaskKind),
    /// Task is currently being processed by a worker
    InProgress(TaskKind),
}

impl TaskStatus {
    pub fn as_str_pair(&self) -> (&'static str, &'static str) {
        match self {
            TaskStatus::Pending(kind) => (self.into(), kind.into()),
            TaskStatus::InProgress(kind) => (self.into(), kind.into()),
        }
    }
}

/// Simplified registration status labels for metrics and stats
#[derive(Debug, Clone, Eq, PartialEq, Hash, EnumIter, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RegistrationStatusLabel {
    Registering,
    Registered,
    Expired,
    Failed,
}

impl From<RegistrationStatus> for RegistrationStatusLabel {
    fn from(value: RegistrationStatus) -> Self {
        match value {
            RegistrationStatus::Registering => RegistrationStatusLabel::Registering,
            RegistrationStatus::Registered => RegistrationStatusLabel::Registered,
            RegistrationStatus::Expired => RegistrationStatusLabel::Expired,
            RegistrationStatus::Failed(_) => RegistrationStatusLabel::Failed,
        }
    }
}

/// Statistics about the domains and tasks
pub struct Stats {
    /// Registration statuses and their counts
    pub registrations: HashMap<RegistrationStatusLabel, u32>,
    /// Task statuses and their counts
    pub tasks: HashMap<TaskStatus, u32>,
    /// Number of domains with certificates nearing expiration
    pub domains_nearing_expiration: u32,
}

impl DomainEntry {
    pub fn new(task: Option<TaskKind>, created_at: UtcTimestamp) -> Self {
        Self {
            task,
            created_at,
            ..Default::default()
        }
    }

    pub fn registration_status(&self, now: UtcTimestamp) -> RegistrationStatus {
        // `not_after` is only ever set together with the certificate (see
        // `submit_task_result`), so its presence is a reliable, cheap proxy for "certificate
        // issued" that avoids a `certificates` map lookup on this hot, per-entry path.
        if let Some(not_after) = self.not_after {
            if now < not_after {
                return RegistrationStatus::Registered;
            }

            RegistrationStatus::Expired
        } else if self.task == Some(TaskKind::Issue) {
            RegistrationStatus::Registering
        } else {
            RegistrationStatus::Failed(
                self.last_failure_reason
                    .clone()
                    .map_or("".to_string(), |err| err.to_string()),
            )
        }
    }

    pub fn task_status(&self) -> Option<TaskStatus> {
        if let Some(task) = &self.task {
            if self.taken_at.is_some() {
                return Some(TaskStatus::InProgress(*task));
            } else {
                return Some(TaskStatus::Pending(*task));
            }
        }

        None
    }

    /// Returns true if this entry's certificate is close to expire at time `now`,
    /// i.e. remaining validity < CERT_EXPIRATION_ALERT_THRESHOLD of total validity.
    /// Returns false if not_before or not_after is missing.
    pub fn is_nearing_expiration(&self, now: UtcTimestamp) -> bool {
        let Some((start, end)) = self.not_before.zip(self.not_after) else {
            return false;
        };

        let total = end.saturating_sub(start);
        let remaining = end.saturating_sub(now);

        // Multiply the threshold to avoid division and zero-checks
        (remaining as f64) < (total as f64 * CERT_EXPIRATION_ALERT_THRESHOLD)
    }
}

impl Storable for DomainEntry {
    const BOUND: Bound = Bound::Unbounded;

    fn to_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        Cow::Owned(to_vec(&self).expect("DomainEntry serialization failed"))
    }

    fn into_bytes(self) -> Vec<u8> {
        to_vec(&self).expect("DomainEntry serialization failed")
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        from_slice(&bytes).expect("DomainEntry deserialization failed")
    }
}

pub struct CanisterState {
    pub domains: StableBTreeMap<String, DomainEntry, VirtualMemory<DefaultMemoryImpl>>,
    pub last_change: StableCell<UtcTimestamp, VirtualMemory<DefaultMemoryImpl>>,
    pub certificates: StableBTreeMap<String, CertificateEntry, VirtualMemory<DefaultMemoryImpl>>,
    pub max_domains: u64,
}

impl CanisterState {
    /// Processes all domains and returns true if next task exists.
    pub fn has_next_task(&self, now: UtcTimestamp) -> HasNextTaskResult {
        let has_task = self
            .domains
            .values()
            .any(|entry| next_pending_task(&entry, now).is_some());

        Ok(has_task)
    }

    pub fn fetch_next_task_with_metrics(&mut self, now: UtcTimestamp) -> FetchTaskResult {
        let result = self.fetch_next_task(now);

        // Update metrics based on result
        let (status, error, task_kind) = match &result {
            Ok(Some(task)) => (SUCCESS_STATUS, "", task.kind.into()),
            Ok(None) => (SUCCESS_STATUS, "", ""),
            Err(err) => (FAILURE_STATUS, err.into(), ""),
        };

        METRICS.with(|cell| {
            let metrics = cell.borrow();
            metrics
                .canister_api_calls
                .with_label_values(&[FETCH_NEXT_TASK_FUNC, status, task_kind, error])
                .inc();
        });

        result
    }

    pub fn fetch_next_task(&mut self, now: UtcTimestamp) -> FetchTaskResult {
        let mut domains_to_update = Vec::new();
        let mut oldest_candidate_task = None;
        let mut oldest_task_created_at = u64::MAX;

        // Pass through all domains:
        // - create all needed renewal tasks and track domain entries that need updates
        // - find the oldest pending task
        for entry in self.domains.iter() {
            let domain = entry.key();
            let mut domain_entry = entry.value();

            if let Some(task_kind) = next_pending_task(&domain_entry, now) {
                // Create Renew task
                if task_kind == TaskKind::Renew && domain_entry.task.is_none() {
                    domain_entry.task = Some(task_kind);
                    domain_entry.task_created_at = Some(now);
                    domains_to_update.push((domain.clone(), domain_entry.clone()));
                }

                // Keep track of the oldest task
                if let Some(task_created_at) = domain_entry.task_created_at
                    && task_created_at < oldest_task_created_at
                {
                    oldest_task_created_at = task_created_at;
                    oldest_candidate_task = Some((domain.clone(), domain_entry.clone()));
                }
            }
        }

        // Update all domains with renewal tasks created
        for (domain, domain_entry) in domains_to_update {
            self.domains.insert(domain, domain_entry);
        }

        // Schedule the oldest task if exists
        match oldest_candidate_task {
            Some((domain, mut domain_entry)) => {
                // Mark task as taken and update the value
                domain_entry.taken_at = Some(now);
                self.domains.insert(domain.clone(), domain_entry.clone());

                let enc_cert = self.certificates.get(&domain).map(|cert| cert.enc_cert);

                Ok(Some(ScheduledTask::new(
                    domain_entry.task.unwrap(),
                    domain,
                    now,
                    enc_cert,
                    Some(domain_entry.wildcard),
                )))
            }
            None => Ok(None),
        }
    }

    /// Compute statistics about the domains and tasks
    pub fn compute_stats(&self, now: UtcTimestamp) -> Stats {
        let mut domains_nearing_expiration = 0;
        let mut registration_statuses: HashMap<_, _> = HashMap::new();
        let mut task_statuses: HashMap<_, _> = HashMap::new();

        // Initialize registration statuses to display all possible states
        for key in RegistrationStatusLabel::iter() {
            registration_statuses.insert(key, 0);
        }

        for entry in self.domains.iter() {
            let entry = entry.value();

            let reg_status: RegistrationStatusLabel = entry.registration_status(now).into();
            registration_statuses
                .entry(reg_status)
                .and_modify(|v| *v += 1)
                .or_insert(1);

            if let Some(task_status) = entry.task_status() {
                task_statuses
                    .entry(task_status)
                    .and_modify(|v| *v += 1)
                    .or_insert(1);
            }

            // Check how many domains are getting close to their certificate expiration
            if entry.is_nearing_expiration(now) {
                domains_nearing_expiration += 1;
            }
        }

        Stats {
            registrations: registration_statuses,
            tasks: task_statuses,
            domains_nearing_expiration,
        }
    }

    /// Returns the names of all domains whose certificate is close to expire
    /// (remaining validity < CERT_EXPIRATION_ALERT_THRESHOLD of total validity).
    pub fn domains_nearing_expiration(&self, now: UtcTimestamp) -> Vec<String> {
        let mut result: Vec<String> = self
            .domains
            .iter()
            .filter(|entry| entry.value().is_nearing_expiration(now))
            .map(|entry| entry.key().clone())
            .collect();

        result.sort();
        result
    }

    pub fn get_domain_status(&self, domain: String, now: UtcTimestamp) -> GetDomainStatusResult {
        let entry = match self.domains.get(&domain) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let status = entry.registration_status(now);

        let domain_status = DomainStatus {
            domain: domain.clone(),
            canister_id: entry.canister_id,
            status,
        };

        Ok(Some(domain_status))
    }

    pub fn get_domain_entry(&self, domain: String) -> GetDomainEntryResult {
        let entry = match self.domains.get(&domain) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let cert = self.certificates.get(&domain);
        Ok(Some(domain_entry_to_api(entry, cert)))
    }

    /// Removes unregistered domains that have been in the system for too long
    pub fn cleanup_stale_domains(&mut self, now: UtcTimestamp) {
        let mut domains_to_remove = Vec::new();

        for entry in self.domains.iter() {
            let domain = entry.key().clone();
            let domain_entry = entry.value();

            // Remove domain if it stayed unregistered for more than UNREGISTERED_DOMAIN_EXPIRATION_TIME
            // This covers new registrations that fail to be completed
            // (`not_after` is only ever set alongside the certificate, so its absence
            // reliably means no certificate has been issued yet)
            let unregistered_too_long = domain_entry.not_after.is_none()
                && domain_entry.task.is_none()
                && now
                    >= domain_entry
                        .created_at
                        .saturating_add(UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs());

            // Remove domain if certificate expired more than EXPIRED_DOMAIN_EXPIRATION_TIME ago
            // This covers renewal failures of the certificate
            let cert_expired_too_long_ago = domain_entry.not_after.is_some_and(|not_after| {
                not_after.saturating_add(EXPIRED_DOMAIN_EXPIRATION_TIME.as_secs()) <= now
            });

            if unregistered_too_long || cert_expired_too_long_ago {
                domains_to_remove.push(domain);
            }
        }

        // Remove expired/unregistered domains, along with any associated certificate
        // data so it doesn't linger orphaned in the certificates map.
        for domain in domains_to_remove {
            self.domains.remove(&domain);
            self.certificates.remove(&domain);
        }

        METRICS.with(|cell| {
            let metrics = cell.borrow();
            metrics.last_stale_domains_cleanup_time.set(now as i64);
        });
    }

    pub fn try_add_task_with_metrics(
        &mut self,
        task: InputTask,
        now: UtcTimestamp,
    ) -> TryAddTaskResult {
        let task_kind: &'static str = task.kind.into();
        let result = self.try_add_task(task, now);

        // Update metrics based on result
        let (status, error) = match &result {
            Ok(()) => (SUCCESS_STATUS, ""),
            Err(err) => (FAILURE_STATUS, err.into()),
        };

        METRICS.with(|cell| {
            let metrics = cell.borrow();
            metrics
                .canister_api_calls
                .with_label_values(&[TRY_ADD_TASK_FUNC, status, task_kind, error])
                .inc();
        });

        result
    }

    fn try_add_task(&mut self, task: InputTask, now: UtcTimestamp) -> TryAddTaskResult {
        if self.domains.len() >= self.max_domains {
            return Err(TryAddTaskError::InternalError(
                "Maximum domains count reached".to_string(),
            ));
        }

        let domain = task.domain;
        let domain_entry = match self.domains.get(&domain) {
            Some(mut entry) => {
                // The wildcard intent is only (re)set when issuing a certificate.
                // Update/Delete/Renew must preserve the stored value, otherwise a later
                // canister-generated Renew would drop the wildcard SAN.
                if task.kind == TaskKind::Issue {
                    entry.wildcard = task.wildcard.unwrap_or(false);
                }

                // Prevent scheduling concurrent tasks for domain if:
                // - there is already a task for the domain that is not a renewal task
                // - there is a renewal task for the domain that is not yet near expiration or already taken
                if (entry.task.is_some() && entry.task != Some(TaskKind::Renew))
                    || (entry.task == Some(TaskKind::Renew)
                        && (!entry.is_nearing_expiration(now) || entry.taken_at.is_some()))
                {
                    return Err(TryAddTaskError::AnotherTaskInProgress(domain));
                }

                // Prevent explicit certificate re-issuance (if the domain is not near expiration)
                // Note: to reissue certificate, submit `Renew` task instead
                // (`not_after` is only ever set alongside the certificate, so it's a
                // reliable, cheap proxy for "certificate issued" here)
                if task.kind == TaskKind::Issue
                    && entry.not_after.is_some()
                    && !entry.is_nearing_expiration(now)
                {
                    return Err(TryAddTaskError::CertificateAlreadyIssued(domain));
                }

                // Require an existing certificate for `Update` task
                if task.kind == TaskKind::Update && entry.not_after.is_none() {
                    return Err(TryAddTaskError::MissingCertificateForUpdate(domain));
                }

                // Set the task field
                entry.task = Some(task.kind);
                // Reset failure counts on task to make sure it gets retried if it was failing before
                entry.last_fail_time = None;
                entry.failures_count = 0;
                entry.last_failure_reason = None;
                entry.rate_limit_failures_count = 0;
                entry.task_created_at = Some(now);

                entry
            }
            None => {
                // Only `Issue` task can create new domain entry
                if task.kind != TaskKind::Issue {
                    return Err(TryAddTaskError::DomainNotFound(domain));
                }

                let mut entry = DomainEntry::new(Some(task.kind), now);
                entry.task_created_at = Some(now);
                entry.wildcard = task.wildcard.unwrap_or(false);
                entry
            }
        };

        // Upsert the domain entry
        self.domains.insert(domain, domain_entry);

        Ok(())
    }

    pub fn submit_task_result_with_metrics(
        &mut self,
        task_result: TaskResult,
        now: UtcTimestamp,
    ) -> SubmitTaskResult {
        let task_kind: &'static str = task_result.task_kind.into();
        let result = self.submit_task_result(task_result.clone(), now);

        // Update metrics based on result
        let (status, error, task_kind) = match &result {
            Ok(()) => (SUCCESS_STATUS, "", task_kind),
            Err(err) => (FAILURE_STATUS, err.into(), task_kind),
        };

        METRICS.with(|cell| {
            let metrics = cell.borrow();

            metrics
                .canister_api_calls
                .with_label_values(&[SUBMIT_TASK_RESULT_FUNC, status, task_kind, error])
                .inc();

            if result.is_ok()
                && let TaskOutcome::Failure(error) = task_result.outcome
            {
                metrics
                    .task_failures
                    .with_label_values(&[task_kind, error.into()])
                    .inc();
            }
        });

        result
    }

    pub fn submit_task_result(
        &mut self,
        task_result: TaskResult,
        now: UtcTimestamp,
    ) -> SubmitTaskResult {
        let domain = task_result.domain.clone();
        let task_id = task_result.task_id;

        let mut entry = self
            .domains
            .get(&domain)
            .ok_or_else(|| SubmitTaskError::DomainNotFound(domain.clone()))?;

        // Validate task ID matches `taken_at` (checking `task_kind` is optional)
        if entry.taken_at != Some(task_id) {
            return Err(SubmitTaskError::NonExistingTaskSubmitted(task_id));
        }

        // Handle task result based on the outcome
        match task_result.outcome {
            TaskOutcome::Success(output) => {
                // Unset fields in case of task success
                entry.task = None;
                entry.taken_at = None;
                entry.last_failure_reason = None;
                entry.failures_count = 0;
                entry.last_fail_time = None;
                entry.rate_limit_failures_count = 0;
                self.last_change.set(now);
                entry.task_created_at = None;

                match output {
                    TaskOutput::Issue(output) => {
                        entry.canister_id = Some(output.canister_id);
                        entry.not_before = Some(output.not_before);
                        entry.not_after = Some(output.not_after);
                        self.certificates.insert(
                            domain.clone(),
                            CertificateEntry {
                                enc_cert: output.enc_cert,
                                enc_priv_key: output.enc_priv_key,
                            },
                        );
                    }
                    TaskOutput::Delete => {
                        self.domains.remove(&domain);
                        self.certificates.remove(&domain);
                        return Ok(());
                    }
                    TaskOutput::Update(canister_id) => {
                        entry.canister_id = Some(canister_id);
                    }
                }
            }

            TaskOutcome::Failure(failure) => {
                // Note: rate-limited failures do not impact the retry limit, they are just counted
                if failure == TaskFailReason::RateLimited {
                    entry.rate_limit_failures_count += 1;
                } else {
                    entry.failures_count += 1;
                }

                entry.last_failure_reason = Some(failure);
                entry.taken_at = None;
                entry.last_fail_time = Some(now);
                // To keep scheduling fair, update the task creation time on failure
                entry.task_created_at = Some(now);

                // Delete the task if the retry limit is reached
                if entry.failures_count >= MAX_TASK_FAILURES {
                    entry.task = None;
                }
            }
        }

        // Update the domain entry
        self.domains.insert(domain, entry);

        Ok(())
    }

    pub fn get_last_change_time(&self) -> GetLastChangeTimeResult {
        Ok(*self.last_change.get())
    }

    pub fn list_certificates_page(
        &self,
        input: ListCertificatesPageInput,
    ) -> ListCertificatesPageResult {
        let limit = input
            .limit
            .filter(|&lim| lim > 0)
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .min(MAX_PAGE_LIMIT) as usize;

        let mut registered_domains = Vec::with_capacity(limit);
        let mut next_key = None;

        let domains_iter = match &input.start_key {
            Some(start_key) => self
                .domains
                .range((RangeBound::Included(start_key), RangeBound::Unbounded)),
            None => self.domains.range(..),
        };

        let mut count = 0;

        for entry in domains_iter {
            let domain = entry.key();
            let domain_entry = entry.value();

            // Only include domains with an issued certificate and existing canister_id.
            // `not_after` is only ever set alongside the certificate, so it's a reliable,
            // cheap proxy for "certificate issued" that avoids a `certificates` map lookup
            // for every entry scanned (as opposed to only the ones actually returned below).
            if domain_entry.not_after.is_some()
                && let Some(canister_id) = &domain_entry.canister_id
            {
                if count >= limit {
                    next_key = Some(domain.clone());
                    break;
                }

                let Some(cert_entry) = self.certificates.get(domain) else {
                    continue;
                };

                registered_domains.push(RegisteredDomain {
                    domain: domain.clone(),
                    canister_id: *canister_id,
                    enc_cert: cert_entry.enc_cert,
                    enc_priv_key: cert_entry.enc_priv_key,
                });

                count += 1;
            }
        }

        let page = CertificatesPage::new(registered_domains, next_key);
        Ok(page)
    }

    pub fn list_domains_page(&self, input: ListDomainsPageInput) -> ListDomainsPageResult {
        let limit = input
            .limit
            .filter(|&lim| lim > 0)
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .min(MAX_PAGE_LIMIT) as usize;

        let range = match &input.start_key {
            Some(k) => self.domains.range(k..),
            None => self.domains.range(..),
        };

        // get the limit entries and one more to peek at the next key for pagination
        let mut entries = range.take(limit + 1);

        // collect the first limit items (without enc_cert/enc_priv_key)
        let items: Vec<ListedDomainEntry> = entries
            .by_ref()
            .take(limit)
            .map(|range_entry| {
                let domain = range_entry.key().clone();
                let e = range_entry.value();
                ListedDomainEntry {
                    domain,
                    task: e.task,
                    last_fail_time: e.last_fail_time,
                    last_failure_reason: e.last_failure_reason.clone(),
                    failures_count: e.failures_count,
                    rate_limit_failures_count: e.rate_limit_failures_count,
                    canister_id: e.canister_id,
                    created_at: e.created_at,
                    taken_at: e.taken_at,
                    task_created_at: e.task_created_at,
                    not_before: e.not_before,
                    not_after: e.not_after,
                    wildcard: Some(e.wildcard),
                }
            })
            .collect();

        // if there is an extra item, it is the next_key
        let next_key = entries.next().map(|entry| entry.key().clone());

        Ok(DomainsPage::new(items, next_key))
    }
}

/// Determines the next pending task for a domain entry based on current state and time.
fn next_pending_task(entry: &DomainEntry, now: UtcTimestamp) -> Option<TaskKind> {
    // Normal existing tasks are always prioritized over scheduling renewals
    let normal_task = entry
        .task
        .and_then(|task| handle_existing_task(entry, task, now));

    if let Some(task) = normal_task {
        return Some(task);
    }

    // Check if a renewal task should be scheduled. This must respect the same
    // failure back-off/cap as an existing task's retry (see `retry_allowed`):
    // `submit_task_result` clears `entry.task` back to `None` once
    // `failures_count` hits `MAX_TASK_FAILURES`, and without this check we'd
    // recreate a fresh `Renew` task here on the very next call, ignoring both
    // `MIN_TASK_RETRY_DELAY` and the failure cap that was just enforced.
    if let (None, Some(not_before), Some(not_after)) =
        (entry.task, entry.not_before, entry.not_after)
        && renewal_needed(not_before, not_after, now)
        && retry_allowed(entry, now)
    {
        return Some(TaskKind::Renew);
    }

    None
}

/// Whether a domain entry's failure history currently permits starting/retrying a task.
fn retry_allowed(entry: &DomainEntry, now: UtcTimestamp) -> bool {
    if entry.failures_count >= MAX_TASK_FAILURES {
        return false;
    }

    match entry.last_fail_time {
        Some(last_fail_time) => {
            now >= last_fail_time.saturating_add(MIN_TASK_RETRY_DELAY.as_secs())
        }
        None => true,
    }
}

fn handle_existing_task(
    entry: &DomainEntry,
    task: TaskKind,
    now: UtcTimestamp,
) -> Option<TaskKind> {
    // Case 1: Task is currently being executed by a worker
    if let Some(taken_at) = entry.taken_at {
        // Reclaim task if it has been running longer than timeout
        let expiry_time = taken_at.saturating_add(TASK_TIMEOUT.as_secs());
        if now >= expiry_time {
            return Some(task);
        }
        // Task is still being processed and hasn't timed out
        return None;
    }

    // Case 2: Task has previously failed and probably needs to be retried
    if entry.last_fail_time.is_some() {
        return retry_allowed(entry, now).then_some(task);
    }

    // Case 3: Task is new and has never been taken or failed
    Some(task)
}

fn renewal_needed(not_before: UtcTimestamp, not_after: UtcTimestamp, now: UtcTimestamp) -> bool {
    // Always renew if certificate has expired
    if now >= not_after {
        return true;
    }

    let total_validity = not_after.saturating_sub(not_before);

    // If validity period is zero or negative, renew immediately (shouldn't normally happen)
    if total_validity == 0 {
        return true;
    }

    let elapsed_time = now.saturating_sub(not_before);
    let elapsed_validity_fraction = elapsed_time as f64 / total_validity as f64;

    // Schedule renewal if renewal threshold passed
    elapsed_validity_fraction >= CERTIFICATE_VALIDITY_FRACTION
}

pub fn with_state<R>(f: impl FnOnce(&CanisterState) -> R) -> R {
    STATE.with(|s| f(&s.borrow()))
}

pub fn with_state_mut<R>(f: impl FnOnce(&mut CanisterState) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

/// Returns an HTTP response listing all domain names whose certificate is close to expire,
/// one domain per line (text/plain).
pub fn export_expiring_domains_as_http_response(now: UtcTimestamp) -> HttpResponse {
    let body = with_state(|state| state.domains_nearing_expiration(now).join("\n")); // This returns a String

    HttpResponseBuilder::ok()
        .header("Content-Type", "text/plain; charset=utf-8")
        .with_body_and_content_length(body.into_bytes()) // Consumes String, no new allocation
        .build()
}

/// Builds the public (candid) `DomainEntry` from the internal, cert-less entry plus its
/// certificate data (looked up separately, since `enc_cert`/`enc_priv_key` no longer live
/// on the internal `DomainEntry`).
fn domain_entry_to_api(entry: DomainEntry, cert: Option<CertificateEntry>) -> DomainEntryApi {
    DomainEntryApi {
        task: entry.task,
        last_fail_time: entry.last_fail_time,
        last_failure_reason: entry.last_failure_reason.clone(),
        failures_count: entry.failures_count,
        rate_limit_failures_count: entry.rate_limit_failures_count,
        canister_id: entry.canister_id,
        created_at: entry.created_at,
        taken_at: entry.taken_at,
        task_created_at: entry.task_created_at,
        enc_cert: cert.as_ref().map(|c| c.enc_cert.clone()),
        enc_priv_key: cert.map(|c| c.enc_priv_key),
        not_before: entry.not_before,
        not_after: entry.not_after,
        wildcard: Some(entry.wildcard),
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::MAX_STORED_DOMAINS;

    use super::*;
    use candid::Principal;
    use ic_custom_domains_canister_api::{IssueCertificateOutput, TaskKind as TaskKindApi};
    use ic_stable_structures::memory_manager::{MemoryId, MemoryManager};

    /// Mirrors the `DomainEntry` layout *before* the `wildcard` field was added, so we can
    /// produce stable-storage bytes exactly as a pre-upgrade canister would have written them.
    #[derive(Serialize)]
    struct LegacyDomainEntry {
        task: Option<TaskKind>,
        last_fail_time: Option<UtcTimestamp>,
        last_failure_reason: Option<TaskFailReason>,
        failures_count: u32,
        rate_limit_failures_count: u32,
        canister_id: Option<Principal>,
        created_at: UtcTimestamp,
        taken_at: Option<UtcTimestamp>,
        task_created_at: Option<UtcTimestamp>,
        enc_cert: Option<Vec<u8>>,
        enc_priv_key: Option<Vec<u8>>,
        not_before: Option<UtcTimestamp>,
        not_after: Option<UtcTimestamp>,
    }

    /// A `DomainEntry` persisted before the `wildcard` field existed must still deserialize
    /// after upgrade, defaulting `wildcard` to `false` (guards the `#[serde(default)]`).
    /// It also carries `enc_cert`/`enc_priv_key`, which `DomainEntry` no longer declares
    /// since the certificate split: those extra CBOR map keys must be silently ignored
    /// rather than causing a deserialization error, since that's exactly the property
    /// `migrate_certificates_out_of_domains` relies on being safe.
    #[test]
    fn test_domain_entry_deserializes_legacy_bytes_without_wildcard() {
        let legacy = LegacyDomainEntry {
            task: Some(TaskKind::Issue),
            last_fail_time: None,
            last_failure_reason: None,
            failures_count: 3,
            rate_limit_failures_count: 1,
            canister_id: Some(Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()),
            created_at: 1000,
            taken_at: Some(2000),
            task_created_at: Some(1500),
            enc_cert: Some(b"cert".to_vec()),
            enc_priv_key: Some(b"key".to_vec()),
            not_before: Some(0),
            not_after: Some(9999),
        };

        // Serialize using the same CBOR codec the `Storable` impl uses.
        let legacy_bytes = to_vec(&legacy).expect("legacy serialization failed");

        // Deserialize through the production `Storable` path.
        let entry = DomainEntry::from_bytes(Cow::Owned(legacy_bytes));

        assert!(
            !entry.wildcard,
            "legacy entries must default wildcard to false"
        );
        // Sanity check that the rest of the fields round-tripped correctly.
        assert_eq!(entry.task, Some(TaskKind::Issue));
        assert_eq!(entry.failures_count, 3);
        assert_eq!(entry.created_at, 1000);
    }

    fn create_test_empty_state() -> CanisterState {
        let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
        let domains_memory = memory_manager.get(MemoryId::new(0));
        let last_change_memory = memory_manager.get(MemoryId::new(1));
        let certs_memory = memory_manager.get(MemoryId::new(2));

        let domains = StableBTreeMap::init(domains_memory);
        let last_change = StableCell::init(last_change_memory, 0);
        let certificates = StableBTreeMap::init(certs_memory);

        CanisterState {
            domains,
            last_change,
            certificates,
            max_domains: MAX_STORED_DOMAINS,
        }
    }

    /// Create a test CanisterState with sample data
    fn create_test_populated_state() -> CanisterState {
        let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
        let domains_memory = memory_manager.get(MemoryId::new(0));
        let last_change_memory = memory_manager.get(MemoryId::new(1));
        let certs_memory = memory_manager.get(MemoryId::new(2));

        let domains = StableBTreeMap::init(domains_memory);
        let last_change = StableCell::init(last_change_memory, 0);
        let certificates = StableBTreeMap::init(certs_memory);

        let mut state = CanisterState {
            domains,
            last_change,
            certificates,
            max_domains: MAX_STORED_DOMAINS,
        };

        let canister_id_1 = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let canister_id_2 = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
        let canister_id_3 = Principal::from_text("rno2w-sqaaa-aaaaa-aaacq-cai").unwrap();

        // Domain with certificate
        let mut domain1 = DomainEntry::new(None, 1000);
        domain1.canister_id = Some(canister_id_1);
        domain1.not_before = Some(1500);
        domain1.not_after = Some(2500);
        state.domains.insert("example.com".to_string(), domain1);
        state.certificates.insert(
            "example.com".to_string(),
            CertificateEntry {
                enc_cert: b"cert1_data".to_vec(),
                enc_priv_key: b"key1_data".to_vec(),
            },
        );

        // Another domain with certificate
        let mut domain2 = DomainEntry::new(None, 1100);
        domain2.canister_id = Some(canister_id_2);
        domain2.not_before = Some(1600);
        domain2.not_after = Some(2600);
        state.domains.insert("test.org".to_string(), domain2);
        state.certificates.insert(
            "test.org".to_string(),
            CertificateEntry {
                enc_cert: b"cert2_data".to_vec(),
                enc_priv_key: b"key2_data".to_vec(),
            },
        );

        // Domain without certificate (should be excluded)
        let domain3 = DomainEntry::new(Some(TaskKind::Issue), 1200);
        state.domains.insert("pending.net".to_string(), domain3);

        // Another domain with certificate
        let mut domain4 = DomainEntry::new(None, 1300);
        domain4.canister_id = Some(canister_id_3);
        domain4.not_before = Some(1700);
        domain4.not_after = Some(2700);
        state.domains.insert("website.io".to_string(), domain4);
        state.certificates.insert(
            "website.io".to_string(),
            CertificateEntry {
                enc_cert: b"cert3_data".to_vec(),
                enc_priv_key: b"key3_data".to_vec(),
            },
        );

        // Domain without certificate (should be excluded)
        let mut domain5 = DomainEntry::new(None, 1400);
        domain5.canister_id = Some(canister_id_1);
        state.domains.insert("incomplete.dev".to_string(), domain5);

        // Another domain with certificate
        let mut domain6 = DomainEntry::new(None, 1300);
        domain6.canister_id = Some(canister_id_2);
        domain6.not_before = Some(1700);
        domain6.not_after = Some(2700);
        state.domains.insert("dfinity.org".to_string(), domain6);
        state.certificates.insert(
            "dfinity.org".to_string(),
            CertificateEntry {
                enc_cert: b"cert6_data".to_vec(),
                enc_priv_key: b"key6_data".to_vec(),
            },
        );

        state
    }

    #[test]
    fn test_is_nearing_expiration_cases() {
        // threshold = 0.2
        let cases = [
            // (not_before, not_after, now, expected, "description")
            (None, Some(2500), 2000, false, "missing before"),
            (Some(1500), None, 2000, false, "missing after"),
            (None, None, 2000, false, "missing both"),
            (Some(1500), Some(2500), 2000, false, "far from expiry (50%)"),
            (
                Some(1500),
                Some(2500),
                2300,
                false,
                "exactly at threshold (20%)",
            ),
            (Some(1500), Some(2500), 2301, true, "just under threshold"),
            (Some(1500), Some(2500), 2400, true, "well past threshold"),
            (Some(1500), Some(2500), 2500, true, "at expiration"),
            (Some(1500), Some(2500), 2600, true, "past expiration"),
            (
                Some(2000),
                Some(2000),
                2000,
                false,
                "zero validity interval",
            ),
        ];

        for (nb, na, now, expected, desc) in cases {
            let mut entry = DomainEntry::new(None, 1000);
            entry.not_before = nb;
            entry.not_after = na;

            assert_eq!(
                entry.is_nearing_expiration(now),
                expected,
                "Failed test case: {desc}"
            );
        }
    }

    #[test]
    fn test_domains_nearing_expiration_scenarios() {
        let state = create_test_populated_state();

        let cases = [
            (2000, vec![], "none nearing - plenty of time"),
            (2400, vec!["example.com"], "single domain nearing"),
            (
                2500,
                vec!["example.com", "test.org"],
                "multiple nearing and sorted",
            ),
            (
                3000,
                vec!["dfinity.org", "example.com", "test.org", "website.io"],
                "all certs expired, missing certs excluded",
            ),
        ];

        // Test populated state
        for (now, expected, desc) in cases {
            let result = state.domains_nearing_expiration(now);
            assert_eq!(result, expected, "Failed populated state: {desc}");
        }

        // Test empty state edge case
        let empty_state = create_test_empty_state();
        assert!(
            empty_state.domains_nearing_expiration(2000).is_empty(),
            "Empty state should return empty vec"
        );
    }

    #[test]
    fn test_list_certificates_page_basic_functionality() {
        let state = create_test_populated_state();

        let input = ListCertificatesPageInput {
            start_key: None,
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return only domains with certificates
        assert_eq!(result.items.len(), 4);

        // Verify the domains are sorted alphabetically
        let domains: Vec<&str> = result.items.iter().map(|d| d.domain.as_str()).collect();
        assert_eq!(
            domains,
            vec!["dfinity.org", "example.com", "test.org", "website.io"]
        );

        let first_domain = &result.items[1];
        assert_eq!(first_domain.domain, "example.com");
        assert_eq!(first_domain.enc_cert, b"cert1_data");
        assert_eq!(first_domain.enc_priv_key, b"key1_data");
        assert_eq!(
            first_domain.canister_id,
            Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap()
        );
    }

    #[test]
    fn test_list_certificates_page_with_limit() {
        let state = create_test_populated_state();

        let input = ListCertificatesPageInput {
            start_key: None,
            limit: Some(2),
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return only 2 domains due to limit
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].domain, "dfinity.org");
        assert_eq!(result.items[1].domain, "example.com");

        // Should have next_key for pagination
        assert_eq!(result.next_key, Some("test.org".to_string()));
    }

    #[test]
    fn test_list_certificates_page_pagination_with_start_key() {
        let state = create_test_populated_state();

        let input = ListCertificatesPageInput {
            start_key: Some("test.org".to_string()),
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].domain, "test.org");
        assert_eq!(result.items[1].domain, "website.io");

        // No next key since we've reached the end
        assert_eq!(result.next_key, None);
    }

    #[test]
    fn test_list_certificates_page_pagination_continuation() {
        let state = create_test_populated_state();

        // First page with limit 1
        let input1 = ListCertificatesPageInput {
            start_key: None,
            limit: Some(1),
        };
        let result1 = state.list_certificates_page(input1).unwrap();

        assert_eq!(result1.items.len(), 1);
        assert_eq!(result1.items[0].domain, "dfinity.org");
        assert_eq!(result1.next_key, Some("example.com".to_string()));

        // Second page using next_key and limit 2
        let input2 = ListCertificatesPageInput {
            start_key: result1.next_key,
            limit: Some(2),
        };
        let result2 = state.list_certificates_page(input2).unwrap();

        assert_eq!(result2.items.len(), 2);
        assert_eq!(result2.items[0].domain, "example.com");
        assert_eq!(result2.items[1].domain, "test.org");
        assert_eq!(result2.next_key, Some("website.io".to_string()));

        // Third page using next_key and limit 3
        let input3 = ListCertificatesPageInput {
            start_key: result2.next_key,
            limit: Some(3),
        };
        let result3 = state.list_certificates_page(input3).unwrap();

        assert_eq!(result3.items.len(), 1);
        assert_eq!(result3.items[0].domain, "website.io");
        assert_eq!(result3.next_key, None);
    }

    #[test]
    fn test_list_certificates_page_nonexistent_start_key() {
        let state = create_test_populated_state();

        // Use a start_key that doesn't exist but is lexicographically between domains
        let input = ListCertificatesPageInput {
            start_key: Some("middle.com".to_string()), // Between "example.com" and "test.org"
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return domains that come after "middle.com" lexicographically
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].domain, "test.org");
        assert_eq!(result.items[1].domain, "website.io");
    }

    #[test]
    fn test_list_certificates_page_empty_state() {
        let memory_manager = MemoryManager::init(DefaultMemoryImpl::default());
        let domains_memory = memory_manager.get(MemoryId::new(0));
        let last_change_memory = memory_manager.get(MemoryId::new(1));
        let certs_memory = memory_manager.get(MemoryId::new(2));

        let domains = StableBTreeMap::init(domains_memory);
        let last_change = StableCell::init(last_change_memory, 0);
        let certificates = StableBTreeMap::init(certs_memory);

        let state = CanisterState {
            domains,
            last_change,
            certificates,
            max_domains: MAX_STORED_DOMAINS,
        };

        let input = ListCertificatesPageInput {
            start_key: None,
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        assert_eq!(result.items.len(), 0);
        assert_eq!(result.next_key, None);
    }

    #[test]
    fn test_list_certificates_page_start_key_at_end() {
        let state = create_test_populated_state();

        // Use the last domain as start_key
        let input = ListCertificatesPageInput {
            start_key: Some("website.io".to_string()),
            limit: None,
        };
        let result = state.list_certificates_page(input).unwrap();

        // Should return this domain only
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.next_key, None);
        assert_eq!(result.items[0].domain, "website.io");
    }

    #[test]
    fn test_list_domains_page_basic_functionality() {
        let state = create_test_populated_state();

        let input = ListDomainsPageInput {
            start_key: None,
            limit: None,
        };
        let result = state.list_domains_page(input).unwrap();

        // Should return all 6 domains (no filtering by certificate), in lexicographic order
        assert_eq!(result.items.len(), 6);
        assert_eq!(result.next_key, None);

        // Spot-check first entry (dfinity.org - first lexicographically)
        let first = &result.items[0];
        assert_eq!(first.domain, "dfinity.org");
        assert_eq!(
            first.canister_id,
            Some(Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap())
        );
        assert_eq!(first.created_at, 1300);
        assert_eq!(first.task, None);

        // Spot-check entry for domain without cert (incomplete.dev is 3rd lexicographically)
        let without_cert = &result.items[2];
        assert_eq!(without_cert.domain, "incomplete.dev");
        assert_eq!(without_cert.created_at, 1400);
    }

    #[test]
    fn test_list_domains_page_with_limit() {
        let state = create_test_populated_state();

        let input = ListDomainsPageInput {
            start_key: None,
            limit: Some(2),
        };
        let result = state.list_domains_page(input).unwrap();

        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].created_at, 1300); // dfinity.org
        assert_eq!(result.items[1].created_at, 1000); // example.com
        assert_eq!(result.next_key, Some("incomplete.dev".to_string()));
    }

    #[test]
    fn test_list_domains_page_pagination_with_start_key() {
        let state = create_test_populated_state();

        let input = ListDomainsPageInput {
            start_key: Some("pending.net".to_string()),
            limit: None,
        };
        let result = state.list_domains_page(input).unwrap();

        assert_eq!(result.items.len(), 3); // pending.net, test.org, website.io
        assert_eq!(result.items[0].created_at, 1200); // pending.net
        assert_eq!(result.items[1].created_at, 1100); // test.org
        assert_eq!(result.items[2].created_at, 1300); // website.io
        assert_eq!(result.next_key, None);
    }

    #[test]
    fn test_list_domains_page_pagination_continuation() {
        let state = create_test_populated_state();

        let input1 = ListDomainsPageInput {
            start_key: None,
            limit: Some(2),
        };
        let result1 = state.list_domains_page(input1).unwrap();
        assert_eq!(result1.items.len(), 2);
        assert_eq!(result1.next_key, Some("incomplete.dev".to_string()));

        let input2 = ListDomainsPageInput {
            start_key: result1.next_key,
            limit: Some(2),
        };
        let result2 = state.list_domains_page(input2).unwrap();
        assert_eq!(result2.items.len(), 2);
        assert_eq!(result2.items[0].created_at, 1400); // incomplete.dev
        assert_eq!(result2.items[1].created_at, 1200); // pending.net
        assert_eq!(result2.next_key, Some("test.org".to_string()));

        let input3 = ListDomainsPageInput {
            start_key: result2.next_key,
            limit: Some(10),
        };
        let result3 = state.list_domains_page(input3).unwrap();
        assert_eq!(result3.items.len(), 2); // test.org, website.io
        assert_eq!(result3.next_key, None);
    }

    #[test]
    fn test_list_domains_page_nonexistent_start_key() {
        let state = create_test_populated_state();

        let input = ListDomainsPageInput {
            start_key: Some("middle.com".to_string()),
            limit: None,
        };
        let result = state.list_domains_page(input).unwrap();

        // Lexicographically after "middle.com": pending.net, test.org, website.io
        assert_eq!(result.items.len(), 3);
        assert_eq!(result.items[0].created_at, 1200);
        assert_eq!(result.items[1].created_at, 1100);
        assert_eq!(result.items[2].created_at, 1300);
    }

    #[test]
    fn test_list_domains_page_empty_state() {
        let state = create_test_empty_state();

        let input = ListDomainsPageInput {
            start_key: None,
            limit: None,
        };
        let result = state.list_domains_page(input).unwrap();

        assert_eq!(result.items.len(), 0);
        assert_eq!(result.next_key, None);
    }

    #[test]
    fn test_list_domains_page_start_key_at_end() {
        let state = create_test_populated_state();

        let input = ListDomainsPageInput {
            start_key: Some("website.io".to_string()),
            limit: None,
        };
        let result = state.list_domains_page(input).unwrap();

        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].created_at, 1300);
        assert_eq!(result.next_key, None);
    }

    #[test]
    fn text_next_pending_task() {
        let created_at = 1000;
        let domain = DomainEntry::new(None, created_at);

        assert!(next_pending_task(&domain, created_at).is_none());

        // Test all task kinds (Renew is handled separately)
        let task_kinds = [TaskKind::Issue, TaskKind::Update, TaskKind::Delete];

        for task_kind in task_kinds {
            // New task which has not been taken or failed yet
            {
                let domain = DomainEntry::new(Some(task_kind), created_at);
                let now = created_at;
                assert_eq!(next_pending_task(&domain, now), Some(task_kind));
            }

            // Task was taken but execution has not timed out yet (on the edge of timeout)
            {
                let mut domain = DomainEntry::new(Some(task_kind), created_at);
                let now = created_at.saturating_add(TASK_TIMEOUT.as_secs() - 1); // 1 sec before timeout
                domain.taken_at = Some(created_at);
                assert!(next_pending_task(&domain, now).is_none());
            }

            // Task was taken and execution has timed out
            {
                let mut domain = DomainEntry::new(Some(task_kind), created_at);
                domain.failures_count = MAX_TASK_FAILURES + 1; // Should not affect timeout logic
                domain.taken_at = Some(created_at);
                let now = created_at.saturating_add(TASK_TIMEOUT.as_secs());
                assert_eq!(next_pending_task(&domain, now), Some(task_kind));
            }

            // Task previously failed, but retry delay has not elapsed yet (on the edge of delay)
            {
                let mut domain = DomainEntry::new(Some(task_kind), created_at);
                let fail_time = created_at + 200;
                domain.last_fail_time = Some(fail_time);
                let now = fail_time.saturating_add(MIN_TASK_RETRY_DELAY.as_secs() - 1);
                assert!(next_pending_task(&domain, now).is_none());
            }

            // Task previously failed, and retry delay has elapsed
            {
                let mut domain = DomainEntry::new(Some(task_kind), created_at);
                let fail_time = created_at + 200;
                domain.last_fail_time = Some(fail_time);
                domain.failures_count = MAX_TASK_FAILURES - 1; // One attempt is still allowed
                let now = fail_time.saturating_add(MIN_TASK_RETRY_DELAY.as_secs());
                assert_eq!(next_pending_task(&domain, now), Some(task_kind));
            }

            // Task previously failed, retry delay has elapsed, but number of max retries reached
            {
                let mut domain = DomainEntry::new(Some(task_kind), created_at);
                let fail_time = created_at + 200;
                domain.last_fail_time = Some(fail_time);
                domain.failures_count = MAX_TASK_FAILURES;
                let now = fail_time.saturating_add(MIN_TASK_RETRY_DELAY.as_secs());
                assert!(next_pending_task(&domain, now).is_none());
            }
        }

        // Certificate renewal check. 65% of the validity period has elapsed => no renewal task yet
        {
            let mut domain = DomainEntry::new(None, created_at);
            let not_before = 500;
            let not_after = 2500;
            domain.not_before = Some(not_before);
            domain.not_after = Some(not_after);
            let now = not_before + 1300; // 1300 = 0.65*(2500 - 500)
            assert!(next_pending_task(&domain, now).is_none());
        }

        // Certificate renewal check. 67% of the validity period has elapsed => renewal task
        {
            let mut domain = DomainEntry::new(None, created_at);
            let not_before = 500;
            let not_after = 2500;
            domain.not_before = Some(not_before);
            domain.not_after = Some(not_after);
            let now = not_before + 1340; // 1340 = 0.67*(2500 - 500)
            assert_eq!(next_pending_task(&domain, now), Some(TaskKind::Renew));
        }
    }

    #[test]
    fn test_try_add_task_new_domain() {
        let mut state = create_test_empty_state();
        let now = 1000;

        // Test Issue task can create new domain
        let domain_name = "test.example.com".to_string();
        {
            let task = InputTask {
                domain: domain_name.clone(),
                kind: TaskKind::Issue,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(result.is_ok());

            let entry = state.domains.get(&domain_name).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Issue));
            assert_eq!(entry.created_at, now);
            assert_eq!(entry.failures_count, 0);
            assert_eq!(entry.rate_limit_failures_count, 0);
            assert!(entry.last_fail_time.is_none());
            assert!(entry.last_failure_reason.is_none());
        }

        // Test e.g. Update task cannot create new domain entry
        {
            let task = InputTask {
                domain: "new.example.com".to_string(),
                kind: TaskKind::Update,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(matches!(result, Err(TryAddTaskError::DomainNotFound(_))));
        }
    }

    #[test]
    fn test_try_add_task_wildcard_intent() {
        let mut state = create_test_empty_state();
        let now = 1000;

        // Issuing with wildcard = true stores the intent on a new entry.
        let domain = "wildcard.example.com".to_string();
        state
            .try_add_task(
                InputTask {
                    domain: domain.clone(),
                    kind: TaskKind::Issue,
                    wildcard: Some(true),
                },
                now,
            )
            .expect("issue task should be accepted");
        assert!(state.domains.get(&domain).unwrap().wildcard);

        // A later Update (which the backend submits with wildcard = Some(false)) must
        // NOT clobber the stored wildcard intent, otherwise a subsequent canister-
        // generated Renew would re-issue without the wildcard SAN.
        let mut entry = state.domains.get(&domain).unwrap();
        entry.task = None; // simulate the issue task having completed
        entry.not_after = Some(9999); // Update requires an existing certificate
        state.domains.insert(domain.clone(), entry);

        state
            .try_add_task(
                InputTask {
                    domain: domain.clone(),
                    kind: TaskKind::Update,
                    wildcard: Some(false),
                },
                now,
            )
            .expect("update task should be accepted");
        assert!(
            state.domains.get(&domain).unwrap().wildcard,
            "Update must preserve the stored wildcard intent"
        );
    }

    #[test]
    fn test_try_add_task_concurrent_tasks_prevention() {
        let mut state = create_test_empty_state();
        let now = 1000;

        // Add a domain with an existing pending task
        let domain_with_task = DomainEntry::new(Some(TaskKind::Issue), now);
        let domain = "pending-domain.com".to_string();
        state.domains.insert(domain.clone(), domain_with_task);

        // Test that adding another task fails
        {
            let task = InputTask {
                domain: domain.clone(),
                kind: TaskKind::Update,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(matches!(
                result,
                Err(TryAddTaskError::AnotherTaskInProgress(domain)) if domain == "pending-domain.com"
            ));
        }

        // Test different task types all fail
        for task_kind in [
            TaskKind::Issue,
            TaskKind::Update,
            TaskKind::Delete,
            TaskKind::Renew,
        ] {
            let task = InputTask {
                domain: domain.clone(),
                kind: task_kind,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(matches!(
                result,
                Err(TryAddTaskError::AnotherTaskInProgress(domain))  if domain == "pending-domain.com"
            ));
        }
    }

    #[test]
    fn test_try_add_task_failure_state_reset() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Add a domain with previous failures
        let domain = "example.com".to_string();
        let mut domain_with_failures = DomainEntry::new(None, now);
        domain_with_failures.not_after = Some(now + 9999);
        domain_with_failures.canister_id = Some(canister_id);
        domain_with_failures.failures_count = 5;
        domain_with_failures.rate_limit_failures_count = 3;
        domain_with_failures.last_fail_time = Some(now - 100);
        domain_with_failures.last_failure_reason =
            Some(TaskFailReason::GenericFailure("Internal error".to_string()));
        state.domains.insert(domain.clone(), domain_with_failures);

        // Add a task and verify all failure state is reset
        {
            let task = InputTask {
                domain: domain.clone(),
                kind: TaskKind::Update,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(result.is_ok());

            let entry = state.domains.get(&domain).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Update));
            assert_eq!(entry.failures_count, 0);
            assert_eq!(entry.rate_limit_failures_count, 0);
            assert!(entry.last_fail_time.is_none());
            assert!(entry.last_failure_reason.is_none());
        }
    }

    #[test]
    fn test_try_add_task_all_task_types() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Test Issue task on new domain
        {
            let task = InputTask {
                domain: "issue.com".to_string(),
                kind: TaskKind::Issue,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(result.is_ok());

            let entry = state.domains.get(&"issue.com".to_string()).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Issue));
        }

        // Test Update task on domain with certificate
        {
            let mut domain_for_update = DomainEntry::new(None, now);
            domain_for_update.not_after = Some(now + 9999);
            domain_for_update.canister_id = Some(canister_id);
            state
                .domains
                .insert("update.com".to_string(), domain_for_update);

            let task = InputTask {
                domain: "update.com".to_string(),
                kind: TaskKind::Update,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(result.is_ok());

            let entry = state.domains.get(&"update.com".to_string()).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Update));
        }

        // Test Delete task on domain with certificate
        {
            let mut domain_for_delete = DomainEntry::new(None, now);
            domain_for_delete.not_after = Some(now + 9999);
            domain_for_delete.canister_id = Some(canister_id);
            state
                .domains
                .insert("delete.com".to_string(), domain_for_delete);

            let task = InputTask {
                domain: "delete.com".to_string(),
                kind: TaskKind::Delete,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(result.is_ok());

            let entry = state.domains.get(&"delete.com".to_string()).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Delete));
        }

        // Test Renew task on domain with certificate
        {
            let mut domain_for_renew = DomainEntry::new(None, now);
            domain_for_renew.not_after = Some(now + 9999);
            domain_for_renew.canister_id = Some(canister_id);
            state
                .domains
                .insert("renew.com".to_string(), domain_for_renew);

            let task = InputTask {
                domain: "renew.com".to_string(),
                kind: TaskKind::Renew,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            assert!(result.is_ok());

            let entry = state.domains.get(&"renew.com".to_string()).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Renew));
        }
    }

    #[test]
    fn test_try_add_task_edge_cases() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Test Update task on domain with only canister_id (no certificate)
        {
            let mut domain_with_canister_only = DomainEntry::new(None, now);
            domain_with_canister_only.canister_id = Some(canister_id);
            state
                .domains
                .insert("update.com".to_string(), domain_with_canister_only);

            let task = InputTask {
                domain: "update.com".to_string(),
                kind: TaskKind::Update,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            // Should fail because certificate is required for Update
            assert!(matches!(
                result,
                Err(TryAddTaskError::MissingCertificateForUpdate(domain)) if domain == "update.com"
            ));
        }

        // Test Delete task on domain with only canister_id (no certificate)
        {
            let mut domain_with_canister_only = DomainEntry::new(None, now);
            domain_with_canister_only.canister_id = Some(canister_id);
            state
                .domains
                .insert("delete.com".to_string(), domain_with_canister_only);

            let task = InputTask {
                domain: "delete.com".to_string(),
                kind: TaskKind::Delete,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            // Should succeed as Delete can work with just canister_id
            assert!(result.is_ok());

            let entry = state.domains.get(&"delete.com".to_string()).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Delete));
        }

        // Test Issue task on domain with existing certificate is not allowed
        {
            let mut domain_with_cert = DomainEntry::new(None, now);
            domain_with_cert.not_after = Some(now + 9999);
            domain_with_cert.canister_id = Some(canister_id);
            state
                .domains
                .insert("issue.com".to_string(), domain_with_cert);

            let task = InputTask {
                domain: "issue.com".to_string(),
                kind: TaskKind::Issue,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            // Should fail because Issue on already registered domain is not allowed
            assert!(matches!(
                result,
                Err(TryAddTaskError::CertificateAlreadyIssued(domain)) if domain == "issue.com"
            ));
        }

        // Test Renew task on domain with certificate should succeed
        {
            let mut domain_with_cert = DomainEntry::new(None, now);
            domain_with_cert.not_after = Some(now + 9999);
            domain_with_cert.canister_id = Some(canister_id);
            state
                .domains
                .insert("renew.com".to_string(), domain_with_cert);

            let task = InputTask {
                domain: "renew.com".to_string(),
                kind: TaskKind::Renew,
                wildcard: None,
            };
            let result = state.try_add_task(task, now);
            // Should succeed because Renew on registered domain is allowed
            assert!(result.is_ok());

            let entry = state.domains.get(&"renew.com".to_string()).unwrap();
            assert_eq!(entry.task, Some(TaskKind::Renew));
        }
    }

    #[test]
    fn test_fetch_next_task_no_tasks() {
        // Arrange
        let mut state = create_test_empty_state();
        let now = 1000;

        // Act + Assert
        // No domains at all
        let result = state.fetch_next_task(now).unwrap();
        assert!(result.is_none());
        // Add a domain without any task
        let domain = DomainEntry::new(None, now);
        state.domains.insert("no-task.com".to_string(), domain);
        let result = state.fetch_next_task(now).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_fetch_next_task_returns_tasks() {
        // Arrange
        let mut state = create_test_empty_state();
        let now = 1000;

        // Add two domain with two tasks
        let task_1 = InputTask {
            domain: "task1.com".to_string(),
            kind: TaskKind::Issue,
            wildcard: None,
        };
        let task_2 = InputTask {
            domain: "task2.com".to_string(),
            kind: TaskKind::Issue,
            wildcard: None,
        };
        state
            .try_add_task(task_1, now)
            .expect("failed to add a task");
        state
            .try_add_task(task_2, now + 10)
            .expect("failed to add a task");

        // Act + Assert: fetch tasks one by one, the older comes first
        let task = state.fetch_next_task(now).unwrap();
        let expected_task = Some(ScheduledTask::new(
            TaskKindApi::Issue,
            "task1.com".to_string(),
            now,
            None,
            Some(false),
        ));
        assert_eq!(task, expected_task);
        let task = state.fetch_next_task(now).unwrap();
        let expected_task = Some(ScheduledTask::new(
            TaskKindApi::Issue,
            "task2.com".to_string(),
            now,
            None,
            Some(false),
        ));
        assert_eq!(task, expected_task);
        let task = state.fetch_next_task(now).unwrap();
        assert!(task.is_none())
    }

    #[test]
    fn test_fetch_next_task_renewal_task() {
        // Arrange
        let mut state = create_test_empty_state();
        let now = 10000;
        state.domains.insert("renewal.com".to_string(), {
            let mut domain = DomainEntry::new(None, now - 5000);
            domain.not_before = Some(0);
            domain.not_after = Some(now);
            domain
        });
        state.certificates.insert(
            "renewal.com".to_string(),
            CertificateEntry {
                enc_cert: b"cert_data".to_vec(),
                enc_priv_key: b"key_data".to_vec(),
            },
        );

        // Act
        let result = state.fetch_next_task(now - 4000).unwrap();
        assert!(result.is_none(), "No renewal needed yet");
        let result = state.fetch_next_task(now - 3000).unwrap();
        let expected_task = Some(ScheduledTask::new(
            TaskKindApi::Renew,
            "renewal.com".to_string(),
            now - 3000,
            Some(b"cert_data".to_vec()),
            Some(false),
        ));
        assert_eq!(result, expected_task);
    }

    #[test]
    fn test_renewal_respects_failure_backoff_after_task_reset() {
        // A domain whose cert is expiring right now (so renewal is always
        // needed) and whose `Renew` task has already failed
        // `MAX_TASK_FAILURES - 1` times.
        let mut state = create_test_empty_state();
        let now = 100_000u64;
        let task_id = 7u64;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        let mut domain = DomainEntry::new(Some(TaskKind::Renew), now - 5000);
        domain.taken_at = Some(task_id);
        domain.canister_id = Some(canister_id);
        domain.not_before = Some(0);
        domain.not_after = Some(now);
        domain.failures_count = MAX_TASK_FAILURES - 1;
        state.domains.insert("flaky.com".to_string(), domain);

        // One more failure pushes `failures_count` to `MAX_TASK_FAILURES`,
        // which resets `task` back to `None` (see `submit_task_result`).
        let task_result = TaskResult {
            domain: "flaky.com".to_string(),
            task_id,
            task_kind: TaskKind::Renew,
            outcome: TaskOutcome::Failure(TaskFailReason::GenericFailure("boom".to_string())),
            duration_secs: 1,
        };
        state.submit_task_result(task_result, now).unwrap();

        let domain_entry = state.domains.get(&"flaky.com".to_string()).unwrap();
        assert_eq!(domain_entry.task, None);
        assert_eq!(domain_entry.failures_count, MAX_TASK_FAILURES);
        assert_eq!(domain_entry.last_fail_time, Some(now));

        // A worker fetching again immediately (no sleep in between, as
        // `base/types/worker.rs` does after submitting a result) must not get
        // a freshly-recreated `Renew` task for this domain.
        let result = state.fetch_next_task(now).unwrap();
        assert!(
            result.is_none(),
            "must not immediately recreate a Renew task after hitting MAX_TASK_FAILURES"
        );

        // Even well past `MIN_TASK_RETRY_DELAY`, a domain that has exhausted
        // its failure cap must stay untouched (only an explicit reset of
        // `failures_count`, not elapsed time, should ever unblock it again).
        let later = now + MIN_TASK_RETRY_DELAY.as_secs() + 10_000;
        let result = state.fetch_next_task(later).unwrap();
        assert!(
            result.is_none(),
            "must not retry a domain that has exhausted MAX_TASK_FAILURES, regardless of elapsed time"
        );
    }

    #[test]
    fn test_cleanup_stale_domains() {
        let mut state = create_test_empty_state();
        let now = 1_000_000;
        let expiration_time = UNREGISTERED_DOMAIN_EXPIRATION_TIME.as_secs();
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Scenario 1: Domain with valid certificate should NOT be removed
        {
            let mut domain_with_cert = DomainEntry::new(None, now - expiration_time - 3600);
            domain_with_cert.canister_id = Some(canister_id);
            domain_with_cert.not_after = Some(now + 3600); // Expires in 1 hour
            state
                .domains
                .insert("has-cert.com".to_string(), domain_with_cert);
        }

        // Scenario 2: Domain with pending task should NOT be removed (even if old)
        {
            let domain_with_task =
                DomainEntry::new(Some(TaskKind::Issue), now - expiration_time - 3600);
            state
                .domains
                .insert("has-task.com".to_string(), domain_with_task);
        }

        // Scenario 3: Fresh unregistered domain should NOT be removed
        {
            let fresh_domain = DomainEntry::new(None, now - 3600); // Created 1 hour ago
            state.domains.insert("fresh.com".to_string(), fresh_domain);
        }

        // Scenario 4: Old unregistered domain should be removed
        {
            let mut old_domain = DomainEntry::new(None, now - expiration_time - 3600); // Expired expiration time + 1 hour ago
            old_domain.failures_count = 2; // Some failures, but no cert or task
            old_domain.last_fail_time = Some(now - 2000);
            old_domain.last_failure_reason =
                Some(TaskFailReason::GenericFailure("Some error".to_string()));
            state.domains.insert("old.com".to_string(), old_domain);
        }

        // Scenario 5: Unregistered domain exactly at expiration threshold should be removed
        {
            let expired_domain = DomainEntry::new(None, now - expiration_time);
            state
                .domains
                .insert("just-expired.com".to_string(), expired_domain);
        }

        // Scenario 6: Domain with certificate that expired more than 7 days ago should be removed
        {
            let expired_grace = EXPIRED_DOMAIN_EXPIRATION_TIME.as_secs();
            let mut expired_cert_domain = DomainEntry::new(Some(TaskKind::Renew), now - 10000);
            expired_cert_domain.canister_id = Some(canister_id);
            expired_cert_domain.not_before = Some(now - 900_000);
            expired_cert_domain.not_after = Some(now - expired_grace - 3600); // Expired >7 days ago
            state
                .domains
                .insert("expired-cert.com".to_string(), expired_cert_domain);
            state.certificates.insert(
                "expired-cert.com".to_string(),
                CertificateEntry {
                    enc_cert: b"cert_data".to_vec(),
                    enc_priv_key: b"key_data".to_vec(),
                },
            );
        }

        // Scenario 7: Domain with certificate that expired less than 7 days ago should NOT be removed
        {
            let mut recent_expired = DomainEntry::new(None, now - 10000);
            recent_expired.canister_id = Some(canister_id);
            recent_expired.not_before = Some(now - 10000);
            recent_expired.not_after = Some(now - 3600); // Expired 1 hour ago (< 7 days)
            state
                .domains
                .insert("recently-expired-cert.com".to_string(), recent_expired);
        }

        // Verify state
        assert_eq!(state.domains.len(), 7);

        // Run cleanup
        state.cleanup_stale_domains(now);

        // Verify results - 4 domains remain (has-cert, has-task, fresh, recently-expired-cert)
        assert_eq!(state.domains.len(), 4);

        // Remaining domains
        assert!(state.domains.get(&"has-cert.com".to_string()).is_some());
        assert!(state.domains.get(&"has-task.com".to_string()).is_some());
        assert!(state.domains.get(&"fresh.com".to_string()).is_some());
        assert!(
            state
                .domains
                .get(&"recently-expired-cert.com".to_string())
                .is_some()
        );

        // Removed domains
        assert!(state.domains.get(&"old.com".to_string()).is_none());
        assert!(state.domains.get(&"just-expired.com".to_string()).is_none());
        assert!(state.domains.get(&"expired-cert.com".to_string()).is_none());

        // The certificate for a removed domain must not linger orphaned
        assert!(
            state
                .certificates
                .get(&"expired-cert.com".to_string())
                .is_none()
        );
    }

    #[test]
    fn test_submit_task_result_domain_not_found() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let task_id = 1;

        let task_result = TaskResult {
            domain: "nonexistent.com".to_string(),
            task_id,
            task_kind: TaskKind::Issue,
            outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
                canister_id: Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap(),
                enc_cert: b"certificate_data".to_vec(),
                enc_priv_key: b"private_key_data".to_vec(),
                not_before: 1000,
                not_after: 2000,
            })),
            duration_secs: 30,
        };

        let result = state.submit_task_result(task_result, now);
        assert!(matches!(
            result,
            Err(SubmitTaskError::DomainNotFound(domain)) if domain == "nonexistent.com"
        ));
    }

    #[test]
    fn test_submit_task_result_invalid_task_id() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let wrong_task_id = 1;
        let correct_task_id = 2;

        // Create a domain with a taken task
        let mut domain = DomainEntry::new(Some(TaskKind::Issue), now);
        domain.taken_at = Some(correct_task_id);
        state.domains.insert("test.com".to_string(), domain);

        let task_result = TaskResult {
            domain: "test.com".to_string(),
            task_id: wrong_task_id,
            task_kind: TaskKind::Issue,
            outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
                canister_id: Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap(),
                enc_cert: b"certificate_data".to_vec(),
                enc_priv_key: b"private_key_data".to_vec(),
                not_before: 1000,
                not_after: 2000,
            })),
            duration_secs: 30,
        };

        let result = state.submit_task_result(task_result, now);
        assert!(matches!(
            result,
            Err(SubmitTaskError::NonExistingTaskSubmitted(task_id)) if task_id == wrong_task_id
        ));

        // Verify domain state unchanged
        let domain_entry = state.domains.get(&"test.com".to_string()).unwrap();
        assert_eq!(domain_entry.taken_at, Some(correct_task_id));
        assert_eq!(domain_entry.task, Some(TaskKind::Issue));
    }

    #[test]
    fn test_submit_task_result_success_issue_new_certificate() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let task_id = 2u64;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Create a domain with an Issue task
        let mut domain = DomainEntry::new(Some(TaskKind::Issue), now);
        domain.taken_at = Some(task_id);
        domain.canister_id = Some(canister_id);
        state.domains.insert("test.com".to_string(), domain);

        let certificate_data = b"certificate_data".to_vec();
        let private_key_data = b"private_key_data".to_vec();
        let not_before = 1000u64;
        let not_after = 2000u64;
        let task_result = TaskResult {
            domain: "test.com".to_string(),
            task_id,
            task_kind: TaskKind::Issue,
            outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
                canister_id,
                enc_cert: certificate_data.clone(),
                enc_priv_key: private_key_data.clone(),
                not_before,
                not_after,
            })),
            duration_secs: 30,
        };

        let result = state.submit_task_result(task_result, now);
        assert!(result.is_ok());

        // Verify domain state updated correctly
        let domain_entry = state.domains.get(&"test.com".to_string()).unwrap();
        assert_eq!(domain_entry.not_before, Some(not_before));
        assert_eq!(domain_entry.not_after, Some(not_after));
        assert_eq!(domain_entry.canister_id, Some(canister_id));
        assert_eq!(domain_entry.task, None);
        assert_eq!(domain_entry.taken_at, None);
        assert_eq!(domain_entry.failures_count, 0);
        assert_eq!(domain_entry.rate_limit_failures_count, 0);
        assert_eq!(domain_entry.last_fail_time, None);
        assert_eq!(domain_entry.last_failure_reason, None);

        // Verify the certificate landed in the certificates map, not the domain entry
        let cert = state.certificates.get(&"test.com".to_string()).unwrap();
        assert_eq!(cert.enc_cert, certificate_data);
        assert_eq!(cert.enc_priv_key, private_key_data);

        // Verify last_change timestamp updated
        assert_eq!(*state.last_change.get(), now);
    }

    #[test]
    fn test_submit_task_result_success_update_certificate() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let task_id = 2u64;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let new_canister_id = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();

        // Create a domain with an Update task and existing certificate
        let mut domain = DomainEntry::new(Some(TaskKind::Update), now);
        domain.taken_at = Some(task_id);
        domain.canister_id = Some(canister_id);
        state.domains.insert("test.com".to_string(), domain);
        state.certificates.insert(
            "test.com".to_string(),
            CertificateEntry {
                enc_cert: b"old_certificate".to_vec(),
                enc_priv_key: b"old_private_key".to_vec(),
            },
        );

        let task_result = TaskResult {
            domain: "test.com".to_string(),
            task_id,
            task_kind: TaskKind::Update,
            outcome: TaskOutcome::Success(TaskOutput::Update(new_canister_id)),
            duration_secs: 30,
        };

        let result = state.submit_task_result(task_result, now);
        assert!(result.is_ok());

        // Verify domain state updated correctly
        let domain_entry = state.domains.get(&"test.com".to_string()).unwrap();
        assert_eq!(domain_entry.canister_id, Some(new_canister_id));
        assert_eq!(domain_entry.task, None);
        assert_eq!(domain_entry.taken_at, None);
        assert_eq!(domain_entry.failures_count, 0);
        assert_eq!(domain_entry.rate_limit_failures_count, 0);
        assert_eq!(domain_entry.last_fail_time, None);
        assert_eq!(domain_entry.last_failure_reason, None);
        // Certificate and private key should remain unchanged
        let cert = state.certificates.get(&"test.com".to_string()).unwrap();
        assert_eq!(cert.enc_cert, b"old_certificate");
        assert_eq!(cert.enc_priv_key, b"old_private_key");

        // Verify last_change timestamp updated
        assert_eq!(*state.last_change.get(), now);
    }

    #[test]
    fn test_submit_task_result_success_delete_domain() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let task_id = 2u64;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Create a domain with a Delete task
        let mut domain = DomainEntry::new(Some(TaskKind::Delete), now);
        domain.taken_at = Some(task_id);
        domain.canister_id = Some(canister_id);
        state.domains.insert("test.com".to_string(), domain);
        state.certificates.insert(
            "test.com".to_string(),
            CertificateEntry {
                enc_cert: b"certificate_data".to_vec(),
                enc_priv_key: b"private_key_data".to_vec(),
            },
        );

        let task_result = TaskResult {
            domain: "test.com".to_string(),
            task_id,
            task_kind: TaskKind::Delete,
            outcome: TaskOutcome::Success(TaskOutput::Delete),
            duration_secs: 30,
        };

        let result = state.submit_task_result(task_result, now);
        assert!(result.is_ok());

        // Verify domain was completely removed
        assert!(state.domains.get(&"test.com".to_string()).is_none());

        // The certificate must not linger orphaned in the certificates map
        assert!(state.certificates.get(&"test.com".to_string()).is_none());

        // Verify last_change timestamp updated
        assert_eq!(*state.last_change.get(), now);
    }

    #[test]
    fn test_submit_task_result_success_renew_certificate() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let task_id = 42u64;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Create a domain with a Renew task
        let mut domain = DomainEntry::new(Some(TaskKind::Renew), now);
        domain.taken_at = Some(task_id);
        domain.canister_id = Some(canister_id);
        domain.not_before = Some(500);
        domain.not_after = Some(1500);
        state.domains.insert("test.com".to_string(), domain);
        state.certificates.insert(
            "test.com".to_string(),
            CertificateEntry {
                enc_cert: b"old_certificate".to_vec(),
                enc_priv_key: b"old_private_key".to_vec(),
            },
        );

        let new_certificate_data = b"new_certificate_data".to_vec();
        let new_private_key_data = b"new_private_key_data".to_vec();
        let new_not_before = 1000u64;
        let new_not_after = 2500u64;
        let task_result = TaskResult {
            domain: "test.com".to_string(),
            task_id,
            task_kind: TaskKind::Renew,
            outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
                canister_id,
                enc_cert: new_certificate_data.clone(),
                enc_priv_key: new_private_key_data.clone(),
                not_before: new_not_before,
                not_after: new_not_after,
            })),
            duration_secs: 45,
        };

        let result = state.submit_task_result(task_result, now);
        assert!(result.is_ok());

        // Verify domain state updated correctly
        let domain_entry = state.domains.get(&"test.com".to_string()).unwrap();
        assert_eq!(domain_entry.not_before, Some(new_not_before));
        assert_eq!(domain_entry.not_after, Some(new_not_after));
        assert_eq!(domain_entry.task, None);
        assert_eq!(domain_entry.taken_at, None);
        assert_eq!(domain_entry.failures_count, 0);
        assert_eq!(domain_entry.rate_limit_failures_count, 0);
        assert_eq!(domain_entry.last_fail_time, None);
        assert_eq!(domain_entry.last_failure_reason, None);

        // Verify the certificate was replaced with the new one
        let cert = state.certificates.get(&"test.com".to_string()).unwrap();
        assert_eq!(cert.enc_cert, new_certificate_data);
        assert_eq!(cert.enc_priv_key, new_private_key_data);

        // Verify last_change timestamp updated
        assert_eq!(*state.last_change.get(), now);
    }

    #[test]
    fn test_submit_task_result_clears_previous_failure_state() {
        let mut state = create_test_empty_state();
        let now = 1000;
        let task_id = 42u64;
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();

        // Create a domain with previous failures and a new task
        let mut domain = DomainEntry::new(Some(TaskKind::Issue), now);
        domain.taken_at = Some(task_id);
        domain.canister_id = Some(canister_id);
        domain.failures_count = 5;
        domain.rate_limit_failures_count = 3;
        domain.last_fail_time = Some(now - 100);
        domain.last_failure_reason =
            Some(TaskFailReason::GenericFailure("Previous error".to_string()));
        state.domains.insert("test.com".to_string(), domain);

        let certificate_data = b"certificate_data".to_vec();
        let private_key_data = b"private_key_data".to_vec();
        let task_result = TaskResult {
            domain: "test.com".to_string(),
            task_id,
            task_kind: TaskKind::Issue,
            outcome: TaskOutcome::Success(TaskOutput::Issue(IssueCertificateOutput {
                canister_id,
                enc_cert: certificate_data.clone(),
                enc_priv_key: private_key_data.clone(),
                not_before: 1000,
                not_after: 2000,
            })),
            duration_secs: 40,
        };

        let result = state.submit_task_result(task_result, now);
        assert!(result.is_ok());

        // Verify all failure state was cleared on success
        let domain_entry = state.domains.get(&"test.com".to_string()).unwrap();
        let cert = state.certificates.get(&"test.com".to_string()).unwrap();
        assert_eq!(cert.enc_cert, certificate_data);
        assert_eq!(cert.enc_priv_key, private_key_data);
        assert_eq!(domain_entry.task, None);
        assert_eq!(domain_entry.taken_at, None);
        assert_eq!(domain_entry.failures_count, 0);
        assert_eq!(domain_entry.rate_limit_failures_count, 0);
        assert_eq!(domain_entry.last_fail_time, None);
        assert_eq!(domain_entry.last_failure_reason, None);

        // Verify last_change timestamp updated
        assert_eq!(*state.last_change.get(), now);
    }

    #[test]
    fn test_canister_max_domains_storage() {
        let mut state = create_test_empty_state();
        state.max_domains = 1;
        let now = 1000;

        let task1 = InputTask {
            domain: "example.com".to_string(),
            kind: TaskKind::Issue,
            wildcard: None,
        };
        let task2 = InputTask {
            domain: "example1.com".to_string(),
            kind: TaskKind::Issue,
            wildcard: None,
        };

        // First task should succeed
        state.try_add_task(task1, now).unwrap();
        // Second task should fail due to max domains limit
        let result = state.try_add_task(task2, now);
        assert!(
            matches!(result, Err(TryAddTaskError::InternalError(err) ) if err == "Maximum domains count reached")
        );
    }
}
