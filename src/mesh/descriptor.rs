//! The signed node descriptor: what a contributed server announces to the mesh.
//!
//! This is the AVPN/Mesh equivalent of Meshtastic's NodeInfo gossip. Every
//! contributed node periodically publishes one, signed with its ML-DSA-65 node
//! key by the control plane (`tools/mesh.py`). Descriptors flood the mesh with
//! a hop limit of 3 and duplicate suppression; beacons store-and-forward them
//! for offline peers. This crate validates structure only — signature
//! verification happens at ingestion in the control plane before a descriptor
//! may enter the directory.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::mesh::identity::MemberId;

/// Current descriptor schema version.
pub const DESCRIPTOR_SCHEMA: u32 = 1;
/// Maximum descriptor lifetime in seconds (7 days); stale nodes drop out of
/// the directory without any central eviction.
pub const DESCRIPTOR_TTL_SECONDS: u64 = 7 * 24 * 3600;
/// Gossip hop limit (Meshtastic's default): far enough to span the mesh,
/// small enough to bound flooding.
pub const GOSSIP_HOP_LIMIT: u8 = 3;

/// What a node offers to do for other members. Relaying is the default duty
/// of every contributed node; exiting is a separate explicit opt-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// First hop: sees the member's address, carries only cloaked ciphertext.
    Entry,
    /// Middle hop: sees only its two neighbours.
    Relay,
    /// Last hop: sees destinations, never the member. Opt-in with abuse and
    /// provider-ToS guidance (`avpn mesh offer --guided`, role exit).
    Exit,
}

/// Declared capacity, cross-checked by directory probes.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    /// Monthly egress the operator contributes, in GiB (e.g. 10240 for an
    /// Oracle Always Free VM).
    pub egress_gib_month: u32,
    /// Daily strong-mode cover budget the node will spend, in MiB. The
    /// controller enforces it; chains never see a weakened defense.
    pub cover_budget_mib_day: u32,
}

/// Probe-measured health, written by the directory's own challenge-response
/// probes, not self-reported.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Health {
    /// 30-day uptime fraction (0..=1).
    pub uptime_30d: f64,
    /// Median probe latency in milliseconds.
    pub latency_ms_p50: u32,
}

/// What an exit admits, as a signed fact (docs/PATH_SELECTION_DESIGN.md §2;
/// tools/exit_policy.py holds the same rules). Default refuse; inbound accepts are
/// opt-in, static-manual, and must name their plan and an abuse contact.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExitPolicy {
    /// Policy schema version (1).
    pub schema: u32,
    /// The only supported default is "refuse".
    pub default: String,
    /// Ordered rules; the first match wins.
    pub rules: Vec<PolicyRule>,
    /// Monthly egress the exit offers, in GiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_ceiling_gib_month: Option<u64>,
    /// "none" (the default when absent) or "static-manual".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_admission: Option<String>,
    /// Free text for people.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// One exit-policy rule.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// "tcp" or "udp".
    pub proto: String,
    /// "N" or "N-M" within 1-65535.
    pub ports: String,
    /// "outbound" or "inbound".
    pub direction: String,
    /// "accept" or "reject".
    pub effect: String,
    /// The plan an inbound accept serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// Where abuse reports go (required on an inbound accept).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_contact: Option<String>,
}

/// A dated streaming measurement for one service (tools/stream_check.py): a fact
/// about this exit at a time, never a promise.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamingRow {
    /// The service probed.
    pub service: String,
    /// The catalogue region seen, or null.
    pub region: Option<String>,
    /// "eligible", "blocked" or "unknown".
    pub result: String,
    /// When it was measured (ISO 8601).
    pub checked: String,
    /// The client transport profile used.
    pub transport_profile: String,
}

/// The exit's advertised IPv6 egress (IPV6_TUNNELING_DESIGN.md section 3, stage 1;
/// the same rules as tools/mesh.py `_is_global_v6_prefix`). Absent on a descriptor:
/// the exit egresses v4 only, exactly the pre-v6 posture.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V6Egress {
    /// A globally routable /64 the tunnel egresses from (2000::/3; never a
    /// ULA or link-local prefix - that would be a lie the planner refuses).
    pub prefix: String,
    /// "both" carries native v6 payloads; "v6" is v6-only; "v4" is v4-only
    /// even though the operator runs v6 locally (a routing fact).
    pub egress: String,
}

impl V6Egress {
    /// The same structural rules as tools/mesh.py's `v6` validation: a
    /// 2000::/3 /64 and a known egress word.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.egress.as_str(), "both" | "v4" | "v6"),
            "v6 egress must be both, v4 or v6"
        );
        ensure!(self.prefix.len() <= 64, "v6 prefix too long");
        // Parsed as a whole address, exactly as tools/mesh.py does with inet_pton:
        // a first-group check alone would admit a malformed rest.
        let addr = self
            .prefix
            .strip_suffix("/64")
            .ok_or_else(|| anyhow::anyhow!("v6 prefix must be a /64"))?;
        let ip: std::net::Ipv6Addr = addr
            .parse()
            .map_err(|_| anyhow::anyhow!("malformed v6 prefix"))?;
        // Global scope: 2000::/3, the top three bits 001 (tools/ipv6_leak_suite.py
        // is_global_v6 pins the same rule).
        ensure!(
            ip.octets()[0] & 0xE0 == 0x20,
            "v6 prefix must be global (2000::/3)"
        );
        Ok(())
    }
}

fn ports_ok(spec: &str) -> bool {
    let (lo, hi) = spec.split_once('-').unwrap_or((spec, spec));
    let parse = |x: &str| {
        (!x.is_empty() && x.len() <= 5 && x.bytes().all(|b| b.is_ascii_digit()))
            .then(|| x.parse::<u32>().ok())
            .flatten()
    };
    matches!((parse(lo), parse(hi)), (Some(a), Some(b)) if (1..=65535).contains(&a) && (1..=65535).contains(&b) && a <= b)
}

impl ExitPolicy {
    /// The same structural rules as tools/exit_policy.py `validate_policy`.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema == 1, "unsupported exit_policy schema");
        ensure!(
            self.default == "refuse",
            "the only supported default is refuse (fail-closed)"
        );
        ensure!(self.rules.len() <= 256, "too many exit_policy rules");
        let mut inbound_accept = false;
        for r in &self.rules {
            ensure!(
                r.proto == "tcp" || r.proto == "udp",
                "proto must be tcp or udp"
            );
            ensure!(
                r.direction == "outbound" || r.direction == "inbound",
                "direction must be outbound or inbound"
            );
            ensure!(
                r.effect == "accept" || r.effect == "reject",
                "effect must be accept or reject"
            );
            ensure!(ports_ok(&r.ports), "ports must be N or N-M within 1-65535");
            if r.effect == "accept" && r.direction == "inbound" {
                inbound_accept = true;
                ensure!(
                    r.plan.as_deref().is_some_and(|p| !p.is_empty()),
                    "an inbound accept must name its plan"
                );
                ensure!(
                    r.abuse_contact.as_deref().is_some_and(|c| !c.is_empty()),
                    "an inbound accept must carry an abuse_contact"
                );
            }
        }
        ensure!(
            self.egress_ceiling_gib_month != Some(0),
            "egress_ceiling_gib_month must be a positive integer"
        );
        let admission = self.inbound_admission.as_deref().unwrap_or("none");
        ensure!(
            admission == "none" || admission == "static-manual",
            "inbound_admission must be none or static-manual"
        );
        ensure!(
            !inbound_accept || admission == "static-manual",
            "inbound accepts require inbound_admission: static-manual"
        );
        Ok(())
    }
}

/// One signed node announcement.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    /// Descriptor schema version (must equal [`DESCRIPTOR_SCHEMA`]).
    pub schema: u32,
    /// Node identity: `!xxxxxxxx` of the node's ML-DSA-65 public key.
    pub node_id: MemberId,
    /// The node's ML-DSA-65 public key (DER, base64). The descriptor signature
    /// is verified against this key before the descriptor enters a directory.
    pub node_public_key: String,
    /// GotaTun WireGuard public key for the carrier (base64).
    pub wg_public_key: String,
    /// Cloaked endpoint (HTTP/3 on UDP 443): `host:port`.
    pub cloak_endpoint: String,
    /// Roles offered to the mesh.
    pub roles: Vec<Role>,
    /// Cloud provider slug ("oci", "aws", "gcp", "host", ...).
    pub provider: String,
    /// ISO 3166-1 alpha-2 country of the node.
    pub country: String,
    /// Declared capacity.
    pub capacity: Capacity,
    /// Probe-measured health.
    pub health: Health,
    /// "public" for the open pool, or a private-group identifier hash.
    pub group: String,
    /// The contributing member (hardware-anchored, see [`MemberId`]).
    pub operator: MemberId,
    /// Publication time, seconds since the Unix epoch.
    pub published: u64,
    /// Expiry, seconds since the Unix epoch; at most
    /// `published + [`DESCRIPTOR_TTL_SECONDS`]`.
    pub expires: u64,
    /// What this exit admits; absent: nothing beyond the tunnel's own carrier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_policy: Option<ExitPolicy>,
    /// Dated streaming measurements, one per service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<Vec<StreamingRow>>,
    /// The exit's advertised IPv6 egress (stage 1 of the tunneling design).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<V6Egress>,
    /// ML-DSA-65 signature over the canonical serialization of every field
    /// above (base64). Verified in the control plane at ingestion.
    pub signature: String,
}

impl Descriptor {
    /// Structural validation that does not need the signature: schema,
    /// identity binding, freshness and field shapes. Called on every
    /// descriptor before use, even on already-verified directory reads.
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(
            self.schema == DESCRIPTOR_SCHEMA,
            "unsupported descriptor schema"
        );
        ensure!(
            self.node_id == MemberId::from_public_key(self.node_public_key.as_bytes()),
            "node id does not match the node public key"
        );
        ensure!(
            !self.roles.is_empty(),
            "a node must offer at least one role"
        );
        ensure!(self.expires > now, "descriptor expired");
        ensure!(
            self.expires <= self.published + DESCRIPTOR_TTL_SECONDS,
            "descriptor lifetime above the TTL"
        );
        ensure!(self.published <= now + 3600, "descriptor from the future");
        ensure!(
            (0.0..=1.0).contains(&self.health.uptime_30d),
            "uptime out of range"
        );
        ensure!(
            self.country.len() == 2 && self.country.bytes().all(|b| b.is_ascii_uppercase()),
            "country must be ISO alpha-2 uppercase"
        );
        ensure!(
            !self.cloak_endpoint.is_empty() && self.cloak_endpoint.len() <= 260,
            "cloak endpoint required"
        );
        if let Some(v6) = &self.v6 {
            v6.validate()?;
        }
        if let Some(policy) = &self.exit_policy {
            policy.validate()?;
        }
        if let Some(rows) = &self.streaming {
            ensure!(rows.len() <= 64, "too many streaming rows");
            let mut seen = std::collections::BTreeSet::new();
            for r in rows {
                ensure!(
                    !r.service.is_empty() && r.service.len() <= 64,
                    "streaming service name required"
                );
                ensure!(
                    seen.insert(r.service.as_str()),
                    "one streaming row per service"
                );
                ensure!(
                    matches!(r.result.as_str(), "eligible" | "blocked" | "unknown"),
                    "streaming result must be eligible, blocked or unknown"
                );
                ensure!(
                    !r.checked.is_empty() && r.checked.len() <= 40,
                    "streaming rows must be dated"
                );
                ensure!(
                    r.transport_profile.len() <= 64,
                    "transport profile too long"
                );
                ensure!(
                    r.region.as_deref().is_none_or(|g| g.len() <= 64),
                    "streaming region too long"
                );
            }
        }
        Ok(())
    }

    /// True when the node may serve as an exit for strangers.
    pub fn is_exit(&self) -> bool {
        self.roles.contains(&Role::Exit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Descriptor {
        let key = "node-public-key".to_string();
        Descriptor {
            schema: DESCRIPTOR_SCHEMA,
            node_id: MemberId::from_public_key(key.as_bytes()),
            node_public_key: key,
            wg_public_key: "d2c".into(),
            cloak_endpoint: "203.0.113.8:443".into(),
            roles: vec![Role::Entry, Role::Relay],
            provider: "oci".into(),
            country: "DE".into(),
            capacity: Capacity {
                egress_gib_month: 10240,
                cover_budget_mib_day: 2048,
            },
            health: Health {
                uptime_30d: 0.997,
                latency_ms_p50: 18,
            },
            group: "public".into(),
            operator: MemberId::from_public_key(b"operator-device-key"),
            published: 1_000,
            expires: 1_000 + DESCRIPTOR_TTL_SECONDS,
            exit_policy: None,
            streaming: None,
            v6: None,
            signature: "c2ln".into(),
        }
    }

    fn with(extra: serde_json::Value) -> std::result::Result<Descriptor, serde_json::Error> {
        let mut v = serde_json::to_value(sample()).unwrap();
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        serde_json::from_value(v)
    }

    #[test]
    fn exit_policy_and_streaming_are_accepted_and_round_trip_byte_for_byte() {
        // The exact shapes tools/exit_policy.py and tools/stream_check.py write: Rust nodes
        // must accept them (they refused them as unknown fields before) and re-serialize them
        // unchanged, or the Python-made signature would no longer match.
        let extra = serde_json::json!({
            "exit_policy": {"schema": 1, "default": "refuse", "rules": [
                {"proto": "tcp", "ports": "1-65535", "direction": "outbound", "effect": "accept"},
                {"proto": "tcp", "ports": "25", "direction": "outbound", "effect": "reject"},
                {"proto": "tcp", "ports": "6881-6889", "direction": "inbound", "effect": "accept",
                 "plan": "bulk", "abuse_contact": "operator@mesh"}],
                "egress_ceiling_gib_month": 4096, "inbound_admission": "static-manual"},
            "streaming": [{"service": "netflix", "region": null, "result": "blocked",
                           "checked": "2026-11-21T00:00:00Z", "transport_profile": "cli"}]
        });
        let d = with(extra.clone()).unwrap();
        d.validate(2_000).unwrap();
        let back = serde_json::to_value(&d).unwrap();
        for k in ["exit_policy", "streaming"] {
            assert_eq!(back[k], extra[k], "{k} changed in the round trip");
        }
        // Absent fields stay absent: older descriptors serialize exactly as before.
        let plain = serde_json::to_value(sample()).unwrap();
        assert!(plain.get("exit_policy").is_none() && plain.get("streaming").is_none());
    }

    #[test]
    fn the_shared_fixture_is_accepted_and_refused_exactly_as_python_does() {
        // tests/fixtures/descriptor_fields.json: tools/test_descriptor_fields.py runs the
        // same cases through tools/mesh.py, so the two validators cannot drift apart.
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/descriptor_fields.json"))
                .unwrap();
        for (i, case) in fixture["accept"].as_array().unwrap().iter().enumerate() {
            let d =
                with(case.clone()).unwrap_or_else(|e| panic!("accept case {i} did not parse: {e}"));
            d.validate(2_000)
                .unwrap_or_else(|e| panic!("accept case {i} refused: {e}"));
            let back = serde_json::to_value(&d).unwrap();
            for (k, v) in case.as_object().unwrap() {
                assert_eq!(
                    &back[k], v,
                    "accept case {i}: {k} changed in the round trip"
                );
            }
        }
        for (i, case) in fixture["refuse"].as_array().unwrap().iter().enumerate() {
            let refused = with(case.clone())
                .map(|d| d.validate(2_000).is_err())
                .unwrap_or(true);
            assert!(refused, "refuse case {i} was accepted");
        }
    }

    #[test]
    fn a_valid_descriptor_passes() {
        sample().validate(2_000).unwrap();
    }

    #[test]
    fn expired_descriptors_are_refused() {
        let d = sample();
        assert!(d.validate(d.expires + 1).is_err());
    }

    #[test]
    fn a_forged_node_id_is_refused() {
        let mut d = sample();
        d.node_id = MemberId::from_public_key(b"someone-else");
        assert!(d.validate(2_000).is_err());
    }
}
