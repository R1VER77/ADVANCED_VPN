//! AVPN/Mesh: the community layer of ADVANCED_VPN.
//!
//! Every member contributes at least one server (an always-free cloud VM is
//! enough); in return they build chains across nodes contributed by other
//! members. There are no accounts: **a member is their hardware device** — a
//! FIDO2 hmac-secret token (Nitrokey preferred, it is open source; any capable
//! token that can generate the keys works) whose credential signs membership
//! proofs and whose public key hash is the member ID. See
//! `docs/MESH_DESIGN.md`.
//!
//! Trust split: descriptors are signed and verified in the *control plane*
//! (`tools/mesh.py`, ML-DSA-65 via the hash-locked Python environment). The
//! data plane only consumes directory files that were verified before being
//! written, and reads them as private files (0600, no symlink following).
//!
//! - [`identity`]: hardware-anchored member and node identity.
//! - [`descriptor`]: the signed node announcement schema (the gossip payload).
//! - [`directory`]: the local node database and the chain-selection rules.
//! - [`tokens`]: unlinkable contribution credits (VOPRF scaffolding).
pub mod descriptor;
pub mod directory;
pub mod identity;
pub mod tokens;
