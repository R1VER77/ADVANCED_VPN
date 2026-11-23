//! cypherpunk_vpn data plane: nested hybrid post-quantum QUIC layers (X25519MLKEM768,
//! ML-DSA-65 authentication), one per hop, carried inside WireGuard + DAITA.
#![deny(missing_docs)]
/// HTTP/3 camouflage for the WireGuard carrier to the first hop.
pub mod cloak;
/// Data-plane configuration files and inherited key descriptors.
pub mod config;
/// The DAITA (Maybenot) machines of the WireGuard carrier: strong, on every hop.
pub mod daita;
/// DC-net control channel for CPVPN/Mesh (library only: no command reaches it yet).
/// One-time pads only (docs/DCNET_CONTROL_DESIGN.md): information-theoretic among members
/// joined by pads handed over in person, computational for pads sent over the network.
pub mod dcnet;
/// Constant-rate, encrypted links between consecutive servers (per-hop shaping).
pub mod link;
mod link_bounds;
/// CPVPN/Mesh: community node identity, signed descriptors, the node directory
/// and unlinkable contribution credits. See docs/MESH_DESIGN.md.
pub mod mesh;
/// Relay, exit and client session loops.
pub mod run;
/// Post-startup confinement of the daemons (seccomp and Landlock).
pub mod sandbox;
/// Hardware session authorization: a client's FIDO2 key signs each session's leaves.
pub mod session_auth;
/// QUIC/TLS settings: hybrid-PQ key exchange, ML-DSA-65 only, pinning, layer sizes.
pub mod tls;
/// TUN devices and packet admission checks.
pub mod tun;

/// Entry points for coverage-guided fuzzing (`fuzz/`, built with `cfg(fuzzing)` only):
/// parsers of attacker-controlled bytes that are private to their modules.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    /// The cloak's parse of an HTTP request carrying a client's proof.
    pub fn cloak_http_proof(request: &[u8]) {
        let _ = crate::cloak::parse_http_proof(request);
    }
}
