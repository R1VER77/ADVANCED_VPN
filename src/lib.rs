//! ADVANCED_VPN data plane: nested hybrid post-quantum QUIC layers (X25519MLKEM768,
//! ML-DSA-65 authentication), one per hop, carried inside WireGuard + DAITA.
#![deny(missing_docs)]
/// HTTP/3 camouflage for the WireGuard carrier to the first hop.
pub mod cloak;
/// Data-plane configuration files and inherited key descriptors.
pub mod config;
/// The DAITA (Maybenot) machines of the WireGuard carrier: strong, on every hop.
pub mod daita;
/// Constant-rate, encrypted links between consecutive servers (per-hop shaping).
pub mod link;
/// AVPN/Mesh: community node identity, signed descriptors, the node directory
/// and unlinkable contribution credits. See docs/MESH_DESIGN.md.
pub mod mesh;
/// Relay, exit and client session loops.
pub mod run;
/// QUIC/TLS settings: hybrid-PQ key exchange, ML-DSA-65 only, pinning, layer sizes.
pub mod tls;
/// TUN devices and packet admission checks.
pub mod tun;
