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

/// The legal sphere a node's operator answers to: its provider's parent jurisdiction
/// (the US CLOUD Act reaches US providers wherever the server stands), or, for a
/// self-hosted node or an unknown provider, the node's own country. Derived from fields
/// every descriptor already signs. Mirrors `legal_parent` in tools/mesh.py.
pub fn legal_parent(provider: &str, country: &str) -> String {
    match provider {
        "oci" | "aws" | "gcp" | "azure" | "racknerd" => "US".into(),
        "hetzner" | "netcup" | "ionos" => "DE".into(),
        "ovh" => "FR".into(),
        "1984" => "IS".into(),
        "infomaniak" | "exoscale" => "CH".into(),
        _ => country.to_ascii_uppercase(),
    }
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
    /// The requesting member: a node it operates is preferred as the entry, so no
    /// stranger ever learns the member's address.
    pub own_operator: Option<MemberId>,
    /// Allow the entry and the exit to answer to the same legal sphere ([`legal_parent`]).
    /// Off by default: one legal order should never reach both ends of a chain.
    pub allow_same_jurisdiction: bool,
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
            // The member's own node is its entry when it offers one (stable sort).
            if i == 0
                && req.hops > 1
                && let Some(me) = req.own_operator
            {
                candidates.sort_by_key(|d| if d.operator == me { 0 } else { 1 });
            }
            let entry_sphere = chosen
                .first()
                .map(|e| legal_parent(&e.provider, &e.country));
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
                // Different legal spheres at the two ends (the middle does not help).
                if is_exit
                    && !req.allow_same_jurisdiction
                    && entry_sphere
                        .as_ref()
                        .is_some_and(|s| *s == legal_parent(&d.provider, &d.country))
                {
                    return false;
                }
                req.allow_weaker_diversity
                    || (!providers.contains(&d.provider) && !countries.contains(&d.country))
            });
            let Some(node) = pick else {
                anyhow::bail!(
                    "no {:?} node in group `{}` satisfies the diversity rule (distinct operator, \
                     provider and country; the exit in another legal sphere than the entry); \
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
            own_operator: None,
            allow_same_jurisdiction: false,
        }
    }

    #[test]
    fn shared_selection_cases_match_the_control_plane() {
        // The same file drives tools/test_mesh.py: both planes must choose alike.
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../tools/testdata/chain_selection.json"))
                .unwrap();
        for case in doc["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let role = |r: &str| match r {
                "entry" => Role::Entry,
                "relay" => Role::Relay,
                _ => Role::Exit,
            };
            let nodes: Vec<Descriptor> = case["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| {
                    node(
                        n[0].as_str().unwrap(),
                        n[1].as_array()
                            .unwrap()
                            .iter()
                            .map(|r| role(r.as_str().unwrap()))
                            .collect(),
                        n[2].as_str().unwrap(),
                        n[3].as_str().unwrap(),
                        n[4].as_str().unwrap(),
                    )
                })
                .collect();
            let names: std::collections::BTreeMap<MemberId, String> = case["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| {
                    let key = format!("key-{}", n[0].as_str().unwrap());
                    (
                        MemberId::from_public_key(key.as_bytes()),
                        n[0].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            let db = NodeDb { nodes };
            let mut r = req(case["hops"].as_u64().unwrap() as usize);
            r.allow_same_jurisdiction = case["allow_same_jurisdiction"].as_bool().unwrap_or(false);
            r.own_operator = case["own_operator"]
                .as_str()
                .map(|o| MemberId::from_public_key(o.as_bytes()));
            let got = db.select_chain(&r).ok().map(|c| {
                c.iter()
                    .map(|d| names[&d.node_id].clone())
                    .collect::<Vec<_>>()
            });
            let want = case["expect"].as_array().map(|a| {
                a.iter()
                    .map(|x| x.as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            });
            assert_eq!(got, want, "{name}");
        }
    }

    #[test]
    fn legal_spheres_follow_the_provider_then_the_country() {
        assert_eq!(legal_parent("oci", "DE"), "US");
        assert_eq!(legal_parent("aws", "SE"), "US");
        assert_eq!(legal_parent("1984", "IS"), "IS");
        assert_eq!(legal_parent("host", "ch"), "CH");
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
