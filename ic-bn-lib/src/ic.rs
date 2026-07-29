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

/// End-to-end tests that spin up a fake replica HTTP server and feed it hand-signed
/// certificates, so that `AgentExt`'s state-tree parsing is exercised through a real
/// `Agent` rather than by unit-testing internal logic directly.
///
/// Certificates are normally signed by the IC's real (threshold BLS) root key, which
/// obviously can't be reproduced here. Instead each test generates its own throwaway
/// BLS keypair, signs the fake state tree with it, and points the `Agent` at that key
/// via `set_root_key`
#[cfg(test)]
mod test {
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::Router;
    use ic_agent::{
        Certificate,
        export::serde_bytes,
        hash_tree::{HashTree, empty, fork, label, leaf},
    };
    use ic_verify_bls_signature::PrivateKey;
    use tokio::net::TcpListener;

    use super::*;

    type Tree = HashTree<Vec<u8>>;

    // ic_agent's own DER prefix for BLS12-381 public keys and its state-root domain
    // separator (agent/response_authentication.rs, agent/mod.rs) - not exported by the
    // crate, so reproduced here to build a certificate it will accept.
    const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
    const DOMAIN_SEPARATOR: &[u8; 14] = b"\x0dic-state-root";

    fn leb128(mut v: u64) -> Vec<u8> {
        let mut buf = vec![];
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                buf.push(byte);
                return buf;
            }
            buf.push(byte | 0x80);
        }
    }

    /// Folds `(label, subtree)` pairs into a single tree. Entries are sorted by label
    /// since the hash tree lookup logic assumes a sorted tree and uses that to short-
    /// circuit its search.
    fn tree_of(mut entries: Vec<(Vec<u8>, Tree)>) -> Tree {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut iter = entries.into_iter().map(|(l, t)| label(l, t));
        let first = iter.next().expect("at least one entry");
        iter.fold(first, fork)
    }

    /// Generates a fake root keypair and signs `tree` with it, returning the
    /// DER-encoded public key (to be passed to `Agent::set_root_key`) alongside the
    /// resulting certificate.
    fn certify(tree: Tree) -> (Vec<u8>, Certificate) {
        let sk = PrivateKey::random(&mut rand::thread_rng());

        let mut root_key = DER_PREFIX.to_vec();
        root_key.extend_from_slice(&sk.public_key().serialize());

        let mut msg = DOMAIN_SEPARATOR.to_vec();
        msg.extend_from_slice(&tree.digest());
        let signature = sk.sign(&msg).serialize().to_vec();

        (
            root_key,
            Certificate {
                tree,
                signature,
                delegation: None,
            },
        )
    }

    /// CBOR-encodes a `Certificate` the same way a real replica's `read_state`
    /// endpoint would.
    fn read_state_response_body(cert: &Certificate) -> Vec<u8> {
        #[derive(serde::Serialize)]
        struct ReadStateResponse {
            #[serde(with = "serde_bytes")]
            certificate: Vec<u8>,
        }

        serde_cbor::to_vec(&ReadStateResponse {
            certificate: serde_cbor::to_vec(cert).unwrap(),
        })
        .unwrap()
    }

    /// Spins up a fake replica that answers every request with the same canned
    /// `read_state` response, and returns its base URL.
    async fn spawn_fake_replica(body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = Router::new().fallback(move || {
            let body = body.clone();
            async move { body }
        });

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetch_subnet_ids_verifies_against_fake_root_key() {
        let root_subnet_id = Principal::from_slice(&[0xaa; 10]);
        let subnet_a = Principal::from_slice(&[0x01; 10]);
        let subnet_b = Principal::from_slice(&[0x02; 10]);

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let subnet_tree = tree_of(vec![
            (subnet_a.as_slice().to_vec(), leaf(vec![1])),
            (subnet_b.as_slice().to_vec(), leaf(vec![1])),
        ]);
        let tree = tree_of(vec![
            (b"subnet".to_vec(), subnet_tree),
            (b"time".to_vec(), leaf(leb128(now_ns))),
        ]);

        let (root_key, cert) = certify(tree);
        let url = spawn_fake_replica(read_state_response_body(&cert)).await;

        let agent = Agent::builder().with_url(&url).build().unwrap();
        agent.set_root_key(root_key);

        let ids = agent.fetch_subnet_ids(root_subnet_id).await.unwrap();
        assert_eq!(ids, AHashSet::from_iter([subnet_a, subnet_b]));
    }

    #[tokio::test]
    async fn fetch_subnet_data_verifies_against_fake_root_key() {
        let subnet_id = Principal::from_slice(&[0x03; 10]);
        let range_start = Principal::from_slice(&[0x00; 10]);
        let range_end = Principal::from_slice(&[0xff; 10]);

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let subnet_inner = tree_of(vec![
            (b"node".to_vec(), empty()),
            (b"public_key".to_vec(), leaf(vec![9, 9, 9])),
            (b"type".to_vec(), leaf(b"application".to_vec())),
        ]);

        let ranges_cbor = serde_cbor::to_vec(&vec![(range_start, range_end)]).unwrap();
        let shard_tree = tree_of(vec![(b"shard".to_vec(), leaf(ranges_cbor))]);

        let tree = tree_of(vec![
            (
                b"canister_ranges".to_vec(),
                tree_of(vec![(subnet_id.as_slice().to_vec(), shard_tree)]),
            ),
            (
                b"subnet".to_vec(),
                tree_of(vec![(subnet_id.as_slice().to_vec(), subnet_inner)]),
            ),
            (b"time".to_vec(), leaf(leb128(now_ns))),
        ]);

        let (root_key, cert) = certify(tree);
        let url = spawn_fake_replica(read_state_response_body(&cert)).await;

        let agent = Agent::builder().with_url(&url).build().unwrap();
        agent.set_root_key(root_key);

        let data = agent.fetch_subnet_data(&subnet_id).await.unwrap();
        assert_eq!(data.subnet_type, SubnetType::Application);
        assert_eq!(
            data.ranges,
            vec![CanisterRange {
                start: range_start,
                end: range_end
            }]
        );
    }
}
