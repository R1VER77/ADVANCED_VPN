//! The node database (`NodeDB`) and the chain-selection rules.
//!
//! A member's directory is a set of descriptors verified and written by the
//! control plane; this reader validates each one again at use time. Chains
//! are selected for *diversity first* — every hop a different operator,
//! provider and country — then health, then budget fairness, so one malicious
//! operator or one compelled provider never sees more than one vantage.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

use crate::config::private_read;
use crate::mesh::descriptor::{Descriptor, Role};
use crate::mesh::identity::MemberId;

/// The on-disk directory: verified descriptors plus the read timestamp.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryFile {
    schema: u32,
    descriptors: Vec<Descriptor>,
}

/// A constraint set for building one chain.
#[derive(Clone, Debug)]
pub struct ChainRequest {
    /// Hops in the chain (1..=3; each hop a distinct operator, provider and
    /// country unless `allow_weaker_diversity` is set).
    pub hops: usize,
    /// Restrict the chain to this group ("public" or a private-group hash).
    pub group: String,
    /// Required country for the exit, if any.
    pub exit_country: Option<String>,
    /// Prefer this node somewhere in the chain (e.g. the member's own node).
    pub prefer: Option<MemberId>,
    /// Testing escape hatch: allow two hops to share a provider or country
    /// (never an operator). Defaults false.
    pub allow_weaker_diversity: bool,
}

/// The verified local view of the mesh.
pub struct NodeDb {
    nodes: Vec<Descriptor>,
}

impl NodeDb {
    /// Load and re-validate a directory file (a private file written by the
    /// control plane after signature verification).
    pub fn load(path: &Path, now: u64) -> Result<Self> {
        let f: DirectoryFile = serde_json::from_slice(&private_read(path, 1 << 20)?)
            .context("invalid mesh directory")?;
        ensure!(f.schema == 1, "unsupported directory schema");
        let mut nodes = vec![];
        for d in f.descriptors {
            if d.validate(now).is_ok() {
                nodes.push(d);
            }
        }
        Ok(Self { nodes })
    }

    /// All live nodes, for `avpn mesh nodes`.
    pub fn nodes(&self) -> &[Descriptor] {
        &self.nodes
    }

    /// Rank nodes for one role: health first (uptime, then latency), then
    /// budget headroom (declared cover budget), stable by node id.
    fn ranked<'a>(&'a self, role: Role, group: &str) -> Vec<&'a Descriptor> {
        let mut v: Vec<&Descriptor> = self
            .nodes
            .iter()
            .filter(|d| d.roles.contains(&role) && d.group == group)
            .collect();
        v.sort_by(|a, b| {
            b.health
                .uptime_30d
                .partial_cmp(&a.health.uptime_30d)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.health.latency_ms_p50.cmp(&b.health.latency_ms_p50))
                .then(
                    b.capacity
                        .cover_budget_mib_day
                        .cmp(&a.capacity.cover_budget_mib_day),
                )
                .then(a.node_id.cmp(&b.node_id))
        });
        v
    }

    /// Pick a chain of `req.hops` nodes honouring the diversity rule:
    /// distinct operators always; distinct providers and countries unless
    /// explicitly weakened. Greedy over the health ranking; returns the
    /// chosen nodes in chain order (entry .. exit).
    pub fn select_chain(&self, req: &ChainRequest) -> Result<Vec<Descriptor>> {
        ensure!((1..=3).contains(&req.hops), "chains have 1 to 3 hops");
        let roles = match req.hops {
            1 => vec![Role::Exit],
            2 => vec![Role::Entry, Role::Exit],
            _ => vec![Role::Entry, Role::Relay, Role::Exit],
        };
        let mut chosen: Vec<&Descriptor> = vec![];
        let mut operators: BTreeSet<MemberId> = BTreeSet::new();
        let mut providers: BTreeSet<String> = BTreeSet::new();
        let mut countries: BTreeSet<String> = BTreeSet::new();
        for (i, role) in roles.iter().enumerate() {
            let is_exit = i == roles.len() - 1;
            let mut candidates = self.ranked(*role, &req.group);
            if let Some(p) = req.prefer {
                candidates.sort_by_key(|d| if d.node_id == p { 0 } else { 1 });
            }
            let pick = candidates.iter().copied().find(|d| {
                if operators.contains(&d.operator) {
                    return false; // never twice the same operator in one chain
                }
                if chosen.iter().any(|c| c.node_id == d.node_id) {
                    return false;
                }
                if is_exit
                    && let Some(c) = &req.exit_country
                    && &d.country != c
                {
                    return false;
                }
                req.allow_weaker_diversity
                    || (!providers.contains(&d.provider) && !countries.contains(&d.country))
            });
            let Some(node) = pick else {
                anyhow::bail!(
                    "no {:?} node in group `{}` satisfies the diversity rule; \
                     widen the mesh or relax constraints",
                    role,
                    req.group
                )
            };
            operators.insert(node.operator);
            providers.insert(node.provider.clone());
            countries.insert(node.country.clone());
            chosen.push(node);
        }
        Ok(chosen.into_iter().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::descriptor::{Capacity, DESCRIPTOR_TTL_SECONDS, Health};

    fn node(name: &str, roles: Vec<Role>, provider: &str, country: &str, op: &str) -> Descriptor {
        let key = format!("key-{name}");
        Descriptor {
            schema: 1,
            node_id: MemberId::from_public_key(key.as_bytes()),
            node_public_key: key,
            wg_public_key: "d2c".into(),
            cloak_endpoint: "203.0.113.8:443".into(),
            roles,
            provider: provider.into(),
            country: country.into(),
            capacity: Capacity {
                egress_gib_month: 10240,
                cover_budget_mib_day: 2048,
            },
            health: Health {
                uptime_30d: 0.99,
                latency_ms_p50: 20,
            },
            group: "public".into(),
            operator: MemberId::from_public_key(op.as_bytes()),
            published: 1_000,
            expires: 1_000 + DESCRIPTOR_TTL_SECONDS,
            signature: "c2ln".into(),
        }
    }

    fn req(hops: usize) -> ChainRequest {
        ChainRequest {
            hops,
            group: "public".into(),
            exit_country: None,
            prefer: None,
            allow_weaker_diversity: false,
        }
    }

    #[test]
    fn chains_span_distinct_operators_providers_countries() {
        let db = NodeDb {
            nodes: vec![
                node("e1", vec![Role::Entry], "oci", "DE", "alice"),
                node("e2", vec![Role::Entry], "oci", "DE", "alice"),
                node("r1", vec![Role::Relay], "aws", "SE", "bob"),
                node("x1", vec![Role::Exit], "host", "CH", "carol"),
            ],
        };
        let chain = db.select_chain(&req(3)).unwrap();
        assert_eq!(chain.len(), 3);
        let ops: BTreeSet<_> = chain.iter().map(|d| d.operator).collect();
        let provs: BTreeSet<_> = chain.iter().map(|d| d.provider.clone()).collect();
        let cts: BTreeSet<_> = chain.iter().map(|d| d.country.clone()).collect();
        assert_eq!(ops.len(), 3);
        assert_eq!(provs.len(), 3);
        assert_eq!(cts.len(), 3);
    }

    #[test]
    fn a_chain_never_reuses_an_operator() {
        // Only one operator in the mesh: a two-hop chain must fail.
        let db = NodeDb {
            nodes: vec![
                node("e1", vec![Role::Entry], "oci", "DE", "alice"),
                node("x1", vec![Role::Exit], "host", "CH", "alice"),
            ],
        };
        assert!(db.select_chain(&req(2)).is_err());
    }

    #[test]
    fn exit_country_is_honoured() {
        let db = NodeDb {
            nodes: vec![
                node("e1", vec![Role::Entry], "oci", "DE", "alice"),
                node("x1", vec![Role::Exit], "host", "CH", "carol"),
            ],
        };
        let mut r = req(2);
        r.exit_country = Some("IS".into());
        assert!(db.select_chain(&r).is_err());
        r.exit_country = Some("CH".into());
        assert!(db.select_chain(&r).is_ok());
    }
}
