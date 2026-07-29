use ahash::AHashSet;
use async_trait::async_trait;
use candid::Principal;
use ic_agent::{Agent, AgentError, agent::SubnetType, hash_tree::SubtreeLookupResult};

/// Represents a single canister range of a subnet.
/// start & end are inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanisterRange {
    pub start: Principal,
    pub end: Principal,
}

/// Subnet's canister ranges & its type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetData {
    pub subnet_type: SubnetType,
    pub ranges: Vec<CanisterRange>,
}

/// A collection of useful shortcut functions for Agent
#[async_trait]
pub trait AgentExt {
    /// Returns the list of all subnet IDs as reported by the NNS state tree.
    async fn fetch_subnet_ids(
        &self,
        root_subnet_id: Principal,
    ) -> Result<AHashSet<Principal>, AgentError>;

    /// Returns a [`SubnetData`] struct that contains the subnet type and its canister ranges
    async fn fetch_subnet_data(&self, subnet_id: &Principal) -> Result<SubnetData, AgentError>;
}

#[async_trait]
impl AgentExt for Agent {
    /// Returns the list of all subnet IDs as reported by the NNS state tree.
    async fn fetch_subnet_ids(
        &self,
        root_subnet_id: Principal,
    ) -> Result<AHashSet<Principal>, AgentError> {
        let cert = self
            .read_subnet_state_raw(vec![vec!["subnet".into()]], root_subnet_id)
            .await
            .map_err(|e| {
                AgentError::MessageError(format!("failed to read /subnet from NNS: {e:#}"))
            })?;

        let SubtreeLookupResult::Found(subnet_tree) =
            cert.tree.lookup_subtree([b"subnet".as_ref()])
        else {
            return Err(AgentError::MessageError(
                "/subnet subtree not found in NNS state tree".into(),
            ));
        };

        // list_paths() returns one entry per leaf, so the same subnet ID appears
        // multiple times (once per sub-key: "type", "public_key", "node/...",
        // etc.).  The AHashSet deduplicates them.
        let subnet_ids = subnet_tree
            .list_paths()
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| {
                Principal::try_from_slice(p[0].as_bytes()).map_err(|e| {
                    AgentError::MessageError(format!(
                        "Malformed subnet ID in the NNS state tree: {e:#}"
                    ))
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(subnet_ids)
    }

    async fn fetch_subnet_data(&self, subnet_id: &Principal) -> Result<SubnetData, AgentError> {
        let subnet = self
            .fetch_subnet_by_id(subnet_id)
            .await
            .map_err(|e| AgentError::MessageError(format!("Failed to fetch subnet info: {e:#}")))?;

        let ranges = subnet
            .iter_canister_ranges()
            .map(|r| CanisterRange {
                start: *r.start(),
                end: *r.end(),
            })
            .collect();

        let Some(subnet_type) = subnet.subnet_type().cloned() else {
            return Err(AgentError::MessageError("Missing subnet type".into()));
        };

        Ok(SubnetData {
            ranges,
            subnet_type,
        })
    }
}
