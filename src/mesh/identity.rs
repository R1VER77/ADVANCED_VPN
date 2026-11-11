//! Hardware-anchored identity.
//!
//! There is no account number and no server-side user record anywhere in the
//! mesh. A member *is* a key that lives on a hardware device:
//!
//! - preferred: a Nitrokey (open source) FIDO2 hmac-secret credential, the
//!   same credential class ADVANCED_VPN already seals client keys with;
//! - accepted: any hardware token able to generate and hold the required keys
//!   (FIDO2 hmac-secret for the Ed25519 membership credential; the operator
//!   ML-DSA-65 key sealed under it, as in `avpn init`).
//!
//! The device private key never leaves the token. Everything the mesh knows
//! about a member is derived from public material: [`MemberId`] is the
//! truncated SHA-256 of the device's membership public key, rendered as
//! `!xxxxxxxx` like a Meshtastic node number.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A member or node identifier: `!` plus 8 lowercase hex characters, the
/// first 4 bytes of SHA-256 over the public key. Public, pseudonymous, and
/// stable for as long as the member keeps the device key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct MemberId(pub [u8; 4]);

impl MemberId {
    /// Derive the identifier of a public key (device membership key or node key).
    pub fn from_public_key(public_key: &[u8]) -> Self {
        let h = Sha256::digest(public_key);
        Self(h[..4].try_into().expect("sha256 is 32 bytes"))
    }

    /// Parse the `!xxxxxxxx` display form.
    pub fn parse(s: &str) -> Result<Self> {
        let h = s.strip_prefix('!').unwrap_or(s);
        ensure!(h.len() == 8, "member id is ! plus 8 hex characters");
        let b = hex::decode(h)?;
        Ok(Self(b.try_into().expect("length checked")))
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "!{}", hex::encode(self.0))
    }
}

impl fmt::Debug for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl TryFrom<String> for MemberId {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}

impl From<MemberId> for String {
    fn from(id: MemberId) -> String {
        id.to_string()
    }
}

/// A signed proof that the holder controls a hardware membership credential,
/// produced by the control plane at publish time (FIDO2 signature over a
/// random challenge plus the member's node descriptor hash). The mesh never
/// sees the credential itself.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipProof {
    /// The member this proof belongs to.
    pub member: MemberId,
    /// The membership public key (FIDO2 Ed25519 credential public key, DER).
    pub device_public_key: String,
    /// Random challenge that was signed, hex.
    pub challenge: String,
    /// Signature over challenge || descriptor hash, hex.
    pub signature: String,
    /// True when the credential is confirmed hardware-bound (hmac-secret on a
    /// FIDO2 token). Software fallbacks must set false and are ranked below
    /// hardware members in the directory.
    pub hardware_bound: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_id_roundtrip() {
        let id = MemberId::from_public_key(b"a-device-public-key");
        let s = id.to_string();
        assert_eq!(s.len(), 9);
        assert!(s.starts_with('!'));
        assert_eq!(MemberId::parse(&s).unwrap(), id);
        assert_eq!(MemberId::parse(&s[1..]).unwrap(), id);
    }

    #[test]
    fn member_id_is_stable_and_public() {
        assert_eq!(
            MemberId::from_public_key(b"k"),
            MemberId::from_public_key(b"k")
        );
        assert_ne!(
            MemberId::from_public_key(b"k"),
            MemberId::from_public_key(b"k2")
        );
    }
}
