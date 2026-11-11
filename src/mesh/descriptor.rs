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
#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
    /// ML-DSA-65 signature over the canonical serialization of every field
    /// above (base64). Verified in the control plane at ingestion.
    pub signature: String,
}

impl Descriptor {
    /// Structural validation that does not need the signature: schema,
    /// identity binding, freshness and field shapes. Called on every
    /// descriptor before use, even on already-verified directory reads.
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(self.schema == DESCRIPTOR_SCHEMA, "unsupported descriptor schema");
        ensure!(
            self.node_id == MemberId::from_public_key(self.node_public_key.as_bytes()),
            "node id does not match the node public key"
        );
        ensure!(!self.roles.is_empty(), "a node must offer at least one role");
        ensure!(self.expires > now, "descriptor expired");
        ensure!(
            self.expires <= self.published + DESCRIPTOR_TTL_SECONDS,
            "descriptor lifetime above the TTL"
        );
        ensure!(
            self.published <= now + 3600,
            "descriptor from the future"
        );
        ensure!(
            (0.0..=1.0).contains(&self.health.uptime_30d),
            "uptime out of range"
        );
        ensure!(
            self.country.len() == 2
                && self.country.bytes().all(|b| b.is_ascii_uppercase()),
            "country must be ISO alpha-2 uppercase"
        );
        ensure!(
            !self.cloak_endpoint.is_empty() && self.cloak_endpoint.len() <= 260,
            "cloak endpoint required"
        );
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
            signature: "c2ln".into(),
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
