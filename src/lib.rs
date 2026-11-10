//! ADVANCED_VPN data plane: nested hybrid post-quantum QUIC layers (X25519MLKEM768,
//! ML-DSA-65 authentication), one per hop, carried inside WireGuard + DAITA.
#![deny(missing_docs)]
/// Data-plane configuration files and inherited key descriptors.
pub mod config;
/// The DAITA (Maybenot) machines of the WireGuard carrier.
pub mod daita;
/// Relay, exit and client session loops.
pub mod run;
/// QUIC/TLS settings: hybrid-PQ key exchange, ML-DSA-65 only, pinning, layer sizes.
pub mod tls;
/// TUN devices and packet admission checks.
pub mod tun;
