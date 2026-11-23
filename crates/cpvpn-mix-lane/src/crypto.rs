//! Audited-primitive layer for the option E production port.
//!
//! Every function here is a thin, byte-exact adapter over an audited crate:
//!
//! | Function | Crate | Notes |
//! |---|---|---|
//! | [`sha256`], [`hkdf_sha256`] | `sha2`, `hkdf` (RustCrypto) | RFC 6234 / RFC 5869 |
//! | [`blake3_keyed`] | `blake3` (official, SIMD) | keyed mode |
//! | [`chacha20_keystream`] | `chacha20` (RustCrypto) | IETF 96-bit-nonce variant (RFC 8439) |
//! | [`aead_seal`], [`aead_open`] | `chacha20poly1305` (RustCrypto) | RFC 8439 AEAD |
//! | [`x25519`], [`x25519_base`] | `x25519-dalek` 2.x | clamps scalars per RFC 7748 |
//! | [`mlkem_keygen`], [`mlkem_encaps`], [`mlkem_decaps`] | `ml-kem` (RustCrypto) | FIPS 203 final, `deterministic` feature for seed-driven KATs |
//!
//! Byte-identity with the std-only reference crate (`pq_sphinx_pack`) is
//! enforced by `tests/vectors.rs` + `tests/cells.rs`.
//!
//! Two documented ERROR-PATH differences from the reference (both benign for
//! well-formed descriptors, flagged for the reviewer):
//! 1. `ml-kem` 0.2.3 does not re-run the FIPS 203 modulus check when decoding
//!    an encapsulation key from bytes; the reference does. Keys enter this
//!    crate only from our own gossip descriptors (PKI-signed), but the check
//!    should be restored upstream (see IMPLEMENTATION_NOTES.md).
//! 2. `ml-kem` 0.2.3 `DecapsulationKey::from_bytes` does not verify the
//!    embedded `H(ek)` field against the embedded `ek` (their own code
//!    carries an XXX note); the reference rejects such keys. Our own DKs are
//!    always self-consistent.

use ml_kem::kem::Decapsulate;
use ml_kem::{
    Ciphertext, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768, B32,
};

/// ML-KEM-768 wire sizes (FIPS 203).
pub const MLKEM_EK_LEN: usize = 1184;
pub const MLKEM_DK_LEN: usize = 2400;
pub const MLKEM_CT_LEN: usize = 1088;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

// ---------------------------------------------------------------------------
// Hash / KDF
// ---------------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let d = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// RFC 5869 HKDF-SHA256: extract(salt, ikm) then expand(info, len).
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let h = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    h.expand(info, &mut okm)
        .expect("okm length <= 255*32 (protocol max 32)");
    okm
}

pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

// ---------------------------------------------------------------------------
// Stream cipher / AEAD
// ---------------------------------------------------------------------------

/// Raw ChaCha20 keystream (IETF 96-bit nonce), `len` bytes.
pub fn chacha20_keystream(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Vec<u8> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;
    let mut c = ChaCha20::new(key.into(), nonce.into());
    let mut buf = vec![0u8; len];
    c.apply_keystream(&mut buf);
    buf
}

/// ChaCha20-Poly1305 seal: ciphertext || 16-byte tag.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("chacha20poly1305 encrypt is infallible for heap-allocated output")
}

/// ChaCha20-Poly1305 open: `None` on tag mismatch.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ct_and_tag,
                aad,
            },
        )
        .ok()
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*scalar, *point)
}

pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519_dalek::x25519(*scalar, base)
}

// ---------------------------------------------------------------------------
// ML-KEM-768 (FIPS 203 final)
// ---------------------------------------------------------------------------

/// Deterministic keygen from seeds (d, z): returns (ek, dk) wire bytes.
pub fn mlkem_keygen(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let d: B32 = B32::try_from(d.as_slice()).expect("32-byte seed");
    let z: B32 = B32::try_from(z.as_slice()).expect("32-byte seed");
    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
}

/// An ML-KEM key or ciphertext of the wrong length or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KemError;

impl std::fmt::Display for KemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed ML-KEM-768 key or ciphertext")
    }
}

impl std::error::Error for KemError {}

/// Deterministic encapsulation to `ek` with message seed `m`: returns (K, c).
pub fn mlkem_encaps(ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), KemError> {
    if ek.len() != MLKEM_EK_LEN {
        return Err(KemError);
    }
    let enc = Encoded::<Ek>::try_from(ek).map_err(|_| KemError)?;
    let ek = Ek::from_bytes(&enc);
    let m: B32 = B32::try_from(m.as_slice()).map_err(|_| KemError)?;
    let (ct, k) = ek.encapsulate_deterministic(&m).map_err(|_| KemError)?;
    Ok((k.to_vec(), ct.to_vec()))
}

/// Decapsulation with FIPS 203 implicit rejection (never fails on
/// well-formed lengths; tampered ciphertext yields a deterministic junk key).
pub fn mlkem_decaps(dk: &[u8], ct: &[u8]) -> Result<Vec<u8>, KemError> {
    if dk.len() != MLKEM_DK_LEN || ct.len() != MLKEM_CT_LEN {
        return Err(KemError);
    }
    let enc = Encoded::<Dk>::try_from(dk).map_err(|_| KemError)?;
    let dk = Dk::from_bytes(&enc);
    let ct = Ciphertext::<MlKem768>::try_from(ct).map_err(|_| KemError)?;
    let k = dk.decapsulate(&ct).map_err(|_| KemError)?;
    Ok(k.to_vec())
}
