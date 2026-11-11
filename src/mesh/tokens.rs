//! Unlinkable contribution credits.
//!
//! The mesh has no accounts and no ledger, so contribution cannot be tracked
//! by identity. Instead: when your node relays traffic for the mesh, the
//! clients it served issue it blind-signed tokens; to build a chain through
//! other members' nodes you spend tokens, which nodes redeem anonymously.
//! Issuance cannot be linked to redemption (VOPRF blind signatures, the
//! Privacy-Pass primitive family), and tokens rotate daily so redemptions
//! cannot be correlated across epochs.
//!
//! This module is the *scaffolding*: the wire types and the verification
//! boundary. The VOPRF evaluation itself lives in the control plane
//! (`tools/mesh.py`, hash-locked Python) until a reviewed Rust VOPRF crate is
//! vendored. Verification here is therefore fail-closed: an unverifiable
//! token is rejected, never accepted.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::mesh::identity::MemberId;

/// A blind-signed credit earned by relaying, one per hop-day-band.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenGrant {
    /// Daily epoch this token belongs to (days since the Unix epoch).
    pub epoch: u64,
    /// The VOPRF output the member unblinded (base64).
    pub token: String,
    /// Issuing node's public key identifier the token must be redeemed with.
    pub issuer: MemberId,
}

/// A token presented when building a chain through someone's node.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSpend {
    /// The grant being spent.
    pub grant: TokenGrant,
    /// Fresh redemption proof binding the token to this chain request
    /// (base64), so a relayed spend cannot be replayed elsewhere.
    pub redemption: String,
}

/// Verify a spend at redemption time.
///
/// Fail-closed by construction: until the VOPRF verifier is vendored into the
/// data plane, every spend is rejected and chains may only be built on
/// capacity the controller vouches for out of band (the member's own nodes
/// and private groups). The public pool opens when the verifier lands.
pub fn verify_spend(spend: &TokenSpend, now_epoch: u64) -> Result<()> {
    if spend.grant.epoch != now_epoch {
        bail!("token from another epoch");
    }
    bail!("VOPRF verification is not yet vendored; spend rejected (fail-closed)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spend(epoch: u64) -> TokenSpend {
        TokenSpend {
            grant: TokenGrant {
                epoch,
                token: "dG9rZW4".into(),
                issuer: MemberId::from_public_key(b"issuer"),
            },
            redemption: "cmVkZWVt".into(),
        }
    }

    #[test]
    fn stale_epochs_are_rejected() {
        assert!(verify_spend(&spend(7), 8).is_err());
    }

    #[test]
    fn verification_is_fail_closed_until_vendored() {
        assert!(verify_spend(&spend(8), 8).is_err());
    }
}
