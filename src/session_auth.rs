//! Hardware session authorization (docs/HARDWARE_BOUND_SESSIONS.md).
//!
//! A client whose identity keys live on a computer still needs its FIDO2 key, touched and
//! PIN-unlocked, for every session: the key signs a statement naming the SHA-256 of each
//! layer's public key and a window of at most 12 hours, and the statement plus the key's
//! WebAuthn assertion ride in the client's leaf certificate as a non-critical extension.
//! A hop that pins the client's device key refuses a leaf without a valid one. The
//! reference implementation and the shared test vectors are `tools/session_auth.py` and
//! `tools/testdata/session_auth.json`.

use crate::config::PeerDevice;
use anyhow::{Context, Result, bail, ensure};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x509_parser::prelude::*;

/// The extension's OID: a UUID arc (ITU-T X.667), so it needs no registration.
pub const OID: &str = "2.25.304735596916668360143454144096617811569";
/// Its DER content bytes. The arc exceeds 64 bits, which x509-parser prints only as hex,
/// so the extension is matched on these bytes (checked against `OID` in the tests).
const OID_DER: [u8; 20] = [
    0x69, 0x83, 0xca, 0xc1, 0xf8, 0xbb, 0xac, 0xb5, 0x92, 0x90, 0x91, 0xb5, 0xa2, 0xa7, 0xca, 0xb2,
    0x8c, 0xeb, 0x9c, 0x71,
];
/// The statement's version tag.
pub const VERSION: &str = "cypherpunk-vpn/session/v1";
const RP: &str = "cypherpunk-vpn.local";
const ORIGIN: &str = "https://cypherpunk-vpn.local";
/// The longest a statement may authorize: the client's leaf lifetime.
pub const MAX_SECONDS: i64 = 43200;
const UP_UV: u8 = 0x05;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Extension {
    authorization: String,
    authenticator_data: String,
    client_data: String,
    signature: String,
}

/// Fields in sorted order, so serializing gives the canonical bytes the key signed.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    layers: BTreeMap<String, String>,
    not_after: i64,
    not_before: i64,
    v: String,
}

fn b64url(raw: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
    for chunk in raw.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Check the hardware session authorization in a peer's leaf: signed by `device` after a
/// touch and the PIN, over a statement that names this leaf's public key, with `now` and
/// the leaf's whole validity inside the statement's window of at most 12 hours.
pub fn verify(device: &PeerDevice, leaf: &[u8], now: i64) -> Result<()> {
    verify_with_domain(device, leaf, now, VERSION, RP, ORIGIN)
}

fn verify_with_domain(
    device: &PeerDevice,
    leaf: &[u8],
    now: i64,
    version: &str,
    rp: &str,
    origin: &str,
) -> Result<()> {
    let (_, cert) =
        parse_x509_certificate(leaf).map_err(|_| anyhow::anyhow!("invalid peer certificate"))?;
    let raw = cert
        .extensions()
        .iter()
        .find(|e| e.oid.as_bytes() == OID_DER)
        .context("no hardware session authorization")?
        .value;
    let ext: Extension = serde_json::from_slice(raw).context("malformed session authorization")?;
    let statement = hex::decode(&ext.authorization).context("malformed session authorization")?;
    let auth = hex::decode(&ext.authenticator_data).context("malformed session authorization")?;
    let client_data = hex::decode(&ext.client_data).context("malformed session authorization")?;
    let signature = hex::decode(&ext.signature).context("malformed session authorization")?;
    let s: Statement =
        serde_json::from_slice(&statement).context("malformed session authorization")?;
    ensure!(
        s.v == version && serde_json::to_vec(&s)? == statement,
        "malformed session authorization"
    );
    ensure!(
        auth.len() >= 37 && auth[..32] == Sha256::digest(rp.as_bytes())[..],
        "wrong relying party"
    );
    ensure!(auth[32] & UP_UV == UP_UV, "touch and PIN required");
    let c: serde_json::Value = serde_json::from_slice(&client_data).context("wrong client data")?;
    ensure!(
        c["type"] == "webauthn.get" && c["origin"] == origin,
        "wrong client data"
    );
    ensure!(
        c["challenge"] == b64url(&Sha256::digest(&statement)).as_str(),
        "assertion is for another statement"
    );
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let public = hex::decode(&device.public_hex).context("bad device key")?;
    let verified = match device.alg.as_str() {
        "es256" => {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public).verify(&signed, &signature)
        }
        "eddsa" => UnparsedPublicKey::new(&ED25519, &public).verify(&signed, &signature),
        _ => bail!("unknown device key algorithm"),
    };
    verified.map_err(|_| anyhow::anyhow!("not signed by the enrolled key"))?;
    let spki = format!("{:x}", Sha256::digest(cert.tbs_certificate.subject_pki.raw));
    ensure!(
        s.layers.values().any(|v| v == &spki),
        "the authorization does not name this key"
    );
    ensure!(
        0 < s.not_after - s.not_before && s.not_after - s.not_before <= MAX_SECONDS,
        "a session lasts at most 12 hours"
    );
    ensure!(
        s.not_before <= now && now < s.not_after,
        "session authorization expired or not yet valid"
    );
    ensure!(
        cert.validity().not_before.timestamp() >= s.not_before
            && cert.validity().not_after.timestamp() <= s.not_after,
        "the leaf outlives its authorization"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors tools/session_auth.py also checks: both verifiers accept the same
    /// leaves and refuse each broken one for the same reason.
    #[test]
    fn agrees_with_the_python_reference_on_every_vector() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tools/testdata/session_auth.json")).unwrap();
        assert_eq!(doc["oid"], OID);
        let now = doc["now"].as_i64().unwrap();
        let vectors = doc["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 17);
        for v in vectors {
            let device: PeerDevice = serde_json::from_value(v["device"].clone()).unwrap();
            let leaf = hex::decode(v["leaf"].as_str().unwrap()).unwrap();
            let got = verify(&device, &leaf, now).err().map(|e| e.to_string());
            assert_eq!(got.as_deref(), v["error"].as_str(), "vector {}", v["name"]);
        }
    }

    /// Real assertions: each emulated firmware's recorded lab run
    /// (tools/device_compatibility_lab.py, phase `hardware_session_authorization`) signed
    /// a session whose leaf this verifier must accept, at the time it was recorded, and
    /// refuse once the session has ended.
    #[test]
    fn real_firmware_sessions_from_the_lab_verify() {
        for (name, evidence) in [
            (
                "Solo 1",
                include_str!("../docs/evidence/SOLO1_PC_VPN_OPERATIONS_20261118.json"),
            ),
            (
                "Solo 2",
                include_str!("../docs/evidence/SOLO2_PC_VPN_OPERATIONS_20261119.json"),
            ),
            (
                "CanoKey",
                include_str!("../docs/evidence/CANOKEY_UDP_VPN_OPERATIONS_20261119.json"),
            ),
            (
                "TKey",
                include_str!("../docs/evidence/TKEY_QEMU_VPN_OPERATIONS_20261119.json"),
            ),
        ] {
            let doc: serde_json::Value = serde_json::from_str(evidence).unwrap();
            let v = &doc["phases"]["hardware_session_authorization"]["vector"];
            let device: PeerDevice = serde_json::from_value(v["device"].clone()).unwrap();
            let leaf = hex::decode(v["leaf"].as_str().unwrap()).unwrap();
            let now = v["now"].as_i64().unwrap();
            let (_, cert) = parse_x509_certificate(&leaf).unwrap();
            let raw = cert
                .extensions()
                .iter()
                .find(|e| e.oid.as_bytes() == OID_DER)
                .unwrap()
                .value;
            let ext: Extension = serde_json::from_slice(raw).unwrap();
            let s: Statement =
                serde_json::from_slice(&hex::decode(&ext.authorization).unwrap()).unwrap();
            let c: serde_json::Value =
                serde_json::from_slice(&hex::decode(&ext.client_data).unwrap()).unwrap();
            let origin = c["origin"].as_str().unwrap();
            let rp = origin.strip_prefix("https://").unwrap();
            verify_with_domain(&device, &leaf, now, &s.v, rp, origin)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(
                verify_with_domain(&device, &leaf, now + MAX_SECONDS, &s.v, rp, origin).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn the_oid_bytes_encode_the_documented_arc() {
        // 2.25.N: first byte 2*40+25, then N in base 128, high bit set on all but the last.
        let n: u128 = OID.strip_prefix("2.25.").unwrap().parse().unwrap();
        let mut arc = vec![(n & 0x7f) as u8];
        let mut rest = n >> 7;
        while rest > 0 {
            arc.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        arc.push(2 * 40 + 25);
        arc.reverse();
        assert_eq!(arc, OID_DER);
    }

    #[test]
    fn base64url_matches_rfc4648_without_padding() {
        for (raw, want) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"\xfb\xff", "-_8"),
        ] {
            assert_eq!(b64url(raw), want);
        }
    }
}
