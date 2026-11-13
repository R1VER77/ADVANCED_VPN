//! ML-KEM-768 (FIPS 203) — entry-hop key agreement for option E.
//!
//! Conventions follow the KAT-verified kyber-py reference (FIPS 203 final):
//! plain-arithmetic NTT with zetas[i] = 17^bitrev7(i) mod 3329, basemul
//! pairs (4i, 4i+1) with +zetas[64+i] and (4i+2, 4i+3) with −zetas[64+i],
//! ExpandA XOF input ρ‖j‖i, G(d‖k) domain separation, decapsulation keys
//! taken from G(m′‖h) with implicit rejection J(z‖c).
//!
//! Cross-verified against kyber-py on deterministic seeds in vectors.json.
//!
//! NOT constant-time (plain i32 arithmetic, branching in sampling): this is
//! a wire-format-correct reference. Swap in the audited `ml-kem` crate at
//! integration.

use crate::keccak::{sha3_256, sha3_512, shake128, shake256};
use std::sync::OnceLock;

pub const Q: i32 = 3329;
pub const N: usize = 256;
pub const K: usize = 3; // ML-KEM-768
pub const ETA1: usize = 2;
pub const ETA2: usize = 2;
pub const DU: usize = 10;
pub const DV: usize = 4;

pub const EK_LEN: usize = 384 * K + 32; // 1184
pub const DK_LEN: usize = 768 * K + 96; // 2400
pub const CT_LEN: usize = 32 * (DU * K + DV); // 1088
pub const SS_LEN: usize = 32;

fn bitrev7(mut i: usize) -> usize {
    let mut r = 0usize;
    for _ in 0..7 {
        r = (r << 1) | (i & 1);
        i >>= 1;
    }
    r
}

fn pow_mod(mut base: i64, mut exp: u32, m: i64) -> i64 {
    let mut acc: i64 = 1;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % m;
        }
        base = base * base % m;
        exp >>= 1;
    }
    acc
}

struct Tables {
    zetas: [i32; 128],
    inv_n: i32, // 128^-1 mod q = 3303
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut zetas = [0i32; 128];
        for (i, z) in zetas.iter_mut().enumerate() {
            *z = pow_mod(17, bitrev7(i) as u32, Q as i64) as i32;
        }
        Tables {
            zetas,
            inv_n: pow_mod(128, (Q - 2) as u32, Q as i64) as i32,
        }
    })
}

type Poly = [i32; N]; // coefficients in [0, q)

fn add_mod(a: i32, b: i32) -> i32 {
    (a + b).rem_euclid(Q)
}

fn sub_mod(a: i32, b: i32) -> i32 {
    (a - b).rem_euclid(Q)
}

fn mul_mod(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) % Q as i64) as i32
}

/// Cooley-Tukey NTT (kyber-py `to_ntt` structure exactly).
pub fn ntt(p: &mut Poly) {
    let zetas = &tables().zetas;
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = zetas[k];
            k += 1;
            for j in start..start + len {
                let t = mul_mod(zeta, p[j + len]);
                p[j + len] = sub_mod(p[j], t);
                p[j] = add_mod(p[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Gentleman-Sande inverse NTT + 128^-1 scale (kyber-py `from_ntt`).
pub fn invntt(p: &mut Poly) {
    let zetas = &tables().zetas;
    let inv_n = tables().inv_n;
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = zetas[k];
            k -= 1;
            for j in start..start + len {
                let t = p[j];
                p[j] = add_mod(t, p[j + len]);
                p[j + len] = mul_mod(zeta, sub_mod(p[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in p.iter_mut() {
        *c = mul_mod(*c, inv_n);
    }
}

/// Pointwise multiply two NTT reps into `out` (kyber-py basemul pairing).
fn ntt_mul(a: &Poly, b: &Poly) -> Poly {
    let zetas = &tables().zetas;
    let mut out = [0i32; N];
    for i in 0..64 {
        let z = zetas[64 + i];
        // pair (4i, 4i+1) with +z
        let (a0, a1) = (a[4 * i], a[4 * i + 1]);
        let (b0, b1) = (b[4 * i], b[4 * i + 1]);
        let t = mul_mod(a1, b1);
        out[4 * i] = add_mod(mul_mod(a0, b0), mul_mod(z, t));
        out[4 * i + 1] = add_mod(mul_mod(a0, b1), mul_mod(a1, b0));
        // pair (4i+2, 4i+3) with -z
        let (a0, a1) = (a[4 * i + 2], a[4 * i + 3]);
        let (b0, b1) = (b[4 * i + 2], b[4 * i + 3]);
        let t = mul_mod(a1, b1);
        out[4 * i + 2] = add_mod(mul_mod(a0, b0), mul_mod(sub_mod(0, z), t));
        out[4 * i + 3] = add_mod(mul_mod(a0, b1), mul_mod(a1, b0));
    }
    out
}

// ---------------------------------------------------------------------------
// Sampling and serialization
// ---------------------------------------------------------------------------

/// SampleNTT / Parse: 3-byte rejection sampling from a SHAKE-128 stream.
/// The stream is extended on demand (prefix-consistent with a fixed 840-byte
/// request, so identical to the reference whenever consumption fits).
fn sample_ntt_stream(seed: &[u8], idx_i: u8, idx_j: u8) -> Poly {
    let mut input = Vec::with_capacity(seed.len() + 2);
    input.extend_from_slice(seed);
    input.push(idx_j);
    input.push(idx_i);
    let mut stream = shake128(&input, 840);
    let mut pos = 0usize;
    let mut p = [0i32; N];
    let mut j = 0usize;
    while j < N {
        if pos + 3 > stream.len() {
            let more = shake128(&input, stream.len() + 840);
            stream = more;
        }
        let b0 = stream[pos] as i32;
        let b1 = stream[pos + 1] as i32;
        let b2 = stream[pos + 2] as i32;
        pos += 3;
        let d1 = b0 + 256 * (b1 % 16);
        let d2 = b1 / 16 + 16 * b2;
        if d1 < Q {
            p[j] = d1;
            j += 1;
        }
        if d2 < Q && j < N {
            p[j] = d2;
            j += 1;
        }
    }
    p
}

/// CBD_η (η = 2): PRF = SHAKE-256(σ‖b, 64η bytes); each coefficient
/// consumes 2η = 4 bits (always nibble-aligned inside one byte).
fn cbd_eta2(seed: &[u8], nonce: u8) -> Poly {
    let mut input = Vec::with_capacity(seed.len() + 1);
    input.extend_from_slice(seed);
    input.push(nonce);
    let bytes = shake256(&input, 64 * ETA2);
    let mut p = [0i32; N];
    for (i, c) in p.iter_mut().enumerate() {
        let byte = bytes[i / 2];
        let x = (byte >> ((i % 2) * 4)) & 0xF;
        let a = (x & 0b11).count_ones() as i32;
        let b = ((x >> 2) & 0b11).count_ones() as i32;
        *c = (a - b).rem_euclid(Q);
    }
    p
}

/// ByteEncode_d: little-endian d-bit packing (d ∈ {1,4,10,12}).
fn byte_encode_d(p: &Poly, d: usize) -> Vec<u8> {
    let total_bits = N * d;
    let mut out = vec![0u8; total_bits / 8];
    let mut bitpos = 0usize;
    for &c in p.iter() {
        for b in 0..d {
            if (c >> b) & 1 == 1 {
                out[(bitpos + b) / 8] |= 1 << ((bitpos + b) % 8);
            }
        }
        bitpos += d;
    }
    out
}

/// ByteDecode_d; for d = 12 the value is reduced mod q (FIPS 203).
fn byte_decode_d(bytes: &[u8], d: usize) -> Poly {
    let mut p = [0i32; N];
    let mut bitpos = 0usize;
    for c in p.iter_mut() {
        let mut v = 0i32;
        for b in 0..d {
            let bit = (bytes[(bitpos + b) / 8] >> ((bitpos + b) % 8)) & 1;
            v |= (bit as i32) << b;
        }
        *c = if d == 12 { v % Q } else { v };
        bitpos += d;
    }
    p
}

/// Compress_d: round(2^d/q · x) mod 2^d.
fn compress(x: i32, d: u32) -> i32 {
    let t = 1i64 << d;
    let y = (t * x as i64 + Q as i64 / 2) / Q as i64;
    (y % t) as i32
}

/// Decompress_d: round(q/2^d · y).
fn decompress(y: i32, d: u32) -> i32 {
    ((Q as i64 * y as i64 + (1i64 << (d - 1))) >> d) as i32
}

// ---------------------------------------------------------------------------
// K-PKE
// ---------------------------------------------------------------------------

/// ExpandA: data[i][j] = SampleNTT(XOF(ρ, j, i)) — kyber-py byte order.
fn expand_a(rho: &[u8]) -> [[Poly; K]; K] {
    let mut a = [[[0i32; N]; K]; K];
    for i in 0..K {
        for j in 0..K {
            a[i][j] = sample_ntt_stream(rho, i as u8, j as u8);
        }
    }
    a
}

/// Algorithm 13 (K-PKE.KeyGen). Returns (ek_pke, dk_pke).
fn k_pke_keygen(d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut g_input = Vec::with_capacity(33);
    g_input.extend_from_slice(d);
    g_input.push(K as u8); // FIPS 203: G(d || k)
    let g = sha3_512(&g_input);
    let (rho, sigma) = g.split_at(32);

    let a = expand_a(rho);
    let mut s_hat = [[0i32; N]; K];
    let mut e_hat = [[0i32; N]; K];
    for i in 0..K {
        s_hat[i] = cbd_eta2(sigma, i as u8);
        ntt(&mut s_hat[i]);
    }
    for i in 0..K {
        e_hat[i] = cbd_eta2(sigma, (K + i) as u8);
        ntt(&mut e_hat[i]);
    }
    // t_hat = A · s_hat + e_hat, with A[i][j] = data[i][j]
    let mut t_hat = [[0i32; N]; K];
    for i in 0..K {
        for j in 0..K {
            let prod = ntt_mul(&a[i][j], &s_hat[j]);
            for idx in 0..N {
                t_hat[i][idx] = add_mod(t_hat[i][idx], prod[idx]);
            }
        }
        for idx in 0..N {
            t_hat[i][idx] = add_mod(t_hat[i][idx], e_hat[i][idx]);
        }
    }
    let mut ek = Vec::with_capacity(EK_LEN);
    for t in &t_hat {
        ek.extend_from_slice(&byte_encode_d(t, 12));
    }
    ek.extend_from_slice(rho);
    let mut dk = Vec::with_capacity(384 * K);
    for s in &s_hat {
        dk.extend_from_slice(&byte_encode_d(s, 12));
    }
    (ek, dk)
}

/// Algorithm 14 (K-PKE.Encrypt). `m` is 32 bytes, `r` is 32 bytes.
fn k_pke_encrypt(ek_pke: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    assert_eq!(ek_pke.len(), EK_LEN, "type check failed");
    let (t_bytes, rho) = ek_pke.split_at(384 * K);
    let mut t_hat = [[0i32; N]; K];
    for i in 0..K {
        t_hat[i] = byte_decode_d(&t_bytes[384 * i..384 * (i + 1)], 12);
    }
    // Modulus check: canonical re-encoding must match.
    for i in 0..K {
        debug_assert_eq!(
            byte_encode_d(&t_hat[i], 12),
            &t_bytes[384 * i..384 * (i + 1)]
        );
    }

    let a = expand_a(rho);
    let mut y_hat = [[0i32; N]; K];
    for i in 0..K {
        y_hat[i] = cbd_eta2(r, i as u8);
        ntt(&mut y_hat[i]);
    }
    // u = A^T · y_hat + e1 (A^T[i][j] = data[j][i])
    let mut u = [[0i32; N]; K];
    for i in 0..K {
        for j in 0..K {
            let prod = ntt_mul(&a[j][i], &y_hat[j]);
            for idx in 0..N {
                u[i][idx] = add_mod(u[i][idx], prod[idx]);
            }
        }
        invntt(&mut u[i]);
        let e1 = cbd_eta2(r, (K + i) as u8);
        for idx in 0..N {
            u[i][idx] = add_mod(u[i][idx], e1[idx]);
        }
    }
    // v = t_hat . y_hat + e2 + mu
    let mut v_acc = [0i32; N];
    for i in 0..K {
        let prod = ntt_mul(&t_hat[i], &y_hat[i]);
        for idx in 0..N {
            v_acc[idx] = add_mod(v_acc[idx], prod[idx]);
        }
    }
    invntt(&mut v_acc);
    let e2 = cbd_eta2(r, (2 * K) as u8);
    let m_poly = byte_decode_d(m, 1);
    for idx in 0..N {
        v_acc[idx] = add_mod(v_acc[idx], e2[idx]);
        v_acc[idx] = add_mod(v_acc[idx], decompress(m_poly[idx], 1));
    }

    let mut ct = Vec::with_capacity(CT_LEN);
    for ui in &u {
        let mut comp = *ui;
        for c in comp.iter_mut() {
            *c = compress(*c, DU as u32);
        }
        ct.extend_from_slice(&byte_encode_d(&comp, DU));
    }
    let mut vc = v_acc;
    for c in vc.iter_mut() {
        *c = compress(*c, DV as u32);
    }
    ct.extend_from_slice(&byte_encode_d(&vc, DV));
    ct
}

/// Algorithm 15 (K-PKE.Decrypt). Returns the 32-byte message.
fn k_pke_decrypt(dk_pke: &[u8], c: &[u8]) -> [u8; 32] {
    let n = K * DU * 32;
    let (c1, c2) = c.split_at(n);
    let mut u = [[0i32; N]; K];
    for i in 0..K {
        let mut ui = byte_decode_d(&c1[32 * DU * i..32 * DU * (i + 1)], DU);
        for c in ui.iter_mut() {
            *c = decompress(*c, DU as u32);
        }
        ntt(&mut ui);
        u[i] = ui;
    }
    let mut v = byte_decode_d(c2, DV);
    for c in v.iter_mut() {
        *c = decompress(*c, DV as u32);
    }
    let mut s_hat = [[0i32; N]; K];
    for i in 0..K {
        s_hat[i] = byte_decode_d(&dk_pke[384 * i..384 * (i + 1)], 12);
    }
    let mut w = [0i32; N];
    for i in 0..K {
        let prod = ntt_mul(&s_hat[i], &u[i]);
        for idx in 0..N {
            w[idx] = add_mod(w[idx], prod[idx]);
        }
    }
    invntt(&mut w);
    for idx in 0..N {
        w[idx] = sub_mod(v[idx], w[idx]);
    }
    let mut m = [0i32; N];
    for idx in 0..N {
        m[idx] = compress(w[idx], 1);
    }
    let enc = byte_encode_d(&m, 1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&enc);
    out
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203 Algorithms 16-21)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct MlKemError {
    pub reason: &'static str,
}

/// Algorithm 16: deterministic keygen from (d, z).
pub fn keygen_internal(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek, dk_pke) = k_pke_keygen(d);
    let mut dk = dk_pke;
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&sha3_256(&ek));
    dk.extend_from_slice(z);
    (ek, dk)
}

/// Random-seed keygen: caller supplies entropy (SWAPPABLE: use the platform
/// CSPRNG at the integration point).
pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    keygen_internal(d, z)
}

/// Algorithm 17: deterministic encapsulation given message `m`.
/// Returns (K, c).
pub fn encaps_internal(ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), MlKemError> {
    if ek.len() != EK_LEN {
        return Err(MlKemError {
            reason: "encapsulation key type check failed",
        });
    }
    // Modulus check: re-decode and re-encode t_hat bytes.
    let t_bytes = &ek[..384 * K];
    for i in 0..K {
        let p = byte_decode_d(&t_bytes[384 * i..384 * (i + 1)], 12);
        if byte_encode_d(&p, 12) != &t_bytes[384 * i..384 * (i + 1)] {
            return Err(MlKemError {
                reason: "encapsulation key modulus check failed",
            });
        }
    }
    let h = sha3_256(ek);
    let mut g_in = Vec::with_capacity(64);
    g_in.extend_from_slice(m);
    g_in.extend_from_slice(&h);
    let g = sha3_512(&g_in);
    let (k_bar, r) = g.split_at(32);
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(r);
    let c = k_pke_encrypt(ek, m, &r_arr);
    Ok((k_bar.to_vec(), c))
}

/// Algorithm 18: decapsulation with implicit rejection.
pub fn decaps(dk: &[u8], c: &[u8]) -> Result<Vec<u8>, MlKemError> {
    if c.len() != CT_LEN {
        return Err(MlKemError {
            reason: "ciphertext type check failed",
        });
    }
    if dk.len() != DK_LEN {
        return Err(MlKemError {
            reason: "decapsulation key type check failed",
        });
    }
    let (dk_pke, rest) = dk.split_at(384 * K);
    let (ek_pke, rest) = rest.split_at(EK_LEN);
    let (h, z) = rest.split_at(32);
    if sha3_256(ek_pke) != h {
        return Err(MlKemError {
            reason: "hash check failed",
        });
    }
    let m_prime = k_pke_decrypt(dk_pke, c);
    let mut g_in = Vec::with_capacity(64);
    g_in.extend_from_slice(&m_prime);
    g_in.extend_from_slice(h);
    let g = sha3_512(&g_in);
    let (k_prime, r_prime) = g.split_at(32);
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(r_prime);
    let c_prime = k_pke_encrypt(ek_pke, &m_prime, &r_arr);
    // Implicit rejection (NOT constant-time here; documented in notes).
    if c_prime == c {
        Ok(k_prime.to_vec())
    } else {
        let mut j_in = Vec::with_capacity(32 + CT_LEN);
        j_in.extend_from_slice(z);
        j_in.extend_from_slice(c);
        Ok(shake256(&j_in, 32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det_bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (seed.wrapping_mul(31) + i as u8).wrapping_mul(17))
            .collect()
    }

    #[test]
    fn ntt_invntt_roundtrip() {
        for seed in 0..5u8 {
            let mut p: Poly =
                core::array::from_fn(|i| ((seed as i32 * 131 + i as i32 * 7) % Q).max(0));
            let orig = p;
            ntt(&mut p);
            invntt(&mut p);
            assert_eq!(p, orig, "seed {seed}");
        }
    }

    #[test]
    fn ntt_is_ring_homomorphism_into_pairs() {
        // f·g mod X^256+1 must equal invntt(ntt(f) ⊛ ntt(g)).
        let f: Poly = core::array::from_fn(|i| ((i as i32 * 97 + 5) % Q).max(0));
        let g: Poly = core::array::from_fn(|i| ((i as i32 * 41 + 11) % Q).max(0));
        // schoolbook mod X^256+1
        let mut direct = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let v = f[i] as i64 * g[j] as i64;
                if i + j < N {
                    direct[i + j] += v;
                } else {
                    direct[i + j - N] -= v;
                }
            }
        }
        let mut expect = [0i32; N];
        for i in 0..N {
            expect[i] = (direct[i] % Q as i64).rem_euclid(Q as i64) as i32;
        }
        let mut fh = f;
        let mut gh = g;
        ntt(&mut fh);
        ntt(&mut gh);
        let mut prod = ntt_mul(&fh, &gh);
        invntt(&mut prod);
        assert_eq!(prod, expect);
    }

    #[test]
    fn zeta_table_head_matches_known_values() {
        let t = tables();
        assert_eq!(t.zetas[1], 1729);
        assert_eq!(t.inv_n, 3303);
        assert_eq!(t.zetas[0], 1);
    }

    #[test]
    fn keygen_encaps_decaps_agreement() {
        for seed in 1..6u8 {
            let d: [u8; 32] = det_bytes(seed, 32).try_into().unwrap();
            let z: [u8; 32] = det_bytes(seed + 100, 32).try_into().unwrap();
            let (ek, dk) = keygen_internal(&d, &z);
            assert_eq!(ek.len(), EK_LEN);
            assert_eq!(dk.len(), DK_LEN);
            let m: [u8; 32] = det_bytes(seed + 200, 32).try_into().unwrap();
            let (k, c) = encaps_internal(&ek, &m).unwrap();
            assert_eq!(c.len(), CT_LEN);
            let k2 = decaps(&dk, &c).unwrap();
            assert_eq!(k, k2, "seed {seed}");
        }
    }

    #[test]
    fn tampered_ciphertext_yields_implicit_rejection_not_error() {
        let d: [u8; 32] = det_bytes(9, 32).try_into().unwrap();
        let z: [u8; 32] = det_bytes(10, 32).try_into().unwrap();
        let (ek, dk) = keygen_internal(&d, &z);
        let m: [u8; 32] = det_bytes(11, 32).try_into().unwrap();
        let (k, c) = encaps_internal(&ek, &m).unwrap();
        let mut bad = c.clone();
        bad[17] ^= 0x40;
        let k_bad = decaps(&dk, &bad).unwrap();
        assert_eq!(k_bad.len(), 32);
        assert_ne!(k_bad, k, "implicit rejection must not leak the real key");
        // Deterministic rejection: same tampering -> same garbage key.
        let bad2 = {
            let mut b = c.clone();
            b[17] ^= 0x40;
            b
        };
        assert_eq!(k_bad, decaps(&dk, &bad2).unwrap());
    }

    #[test]
    fn validation_checks_fire() {
        let d: [u8; 32] = det_bytes(1, 32).try_into().unwrap();
        let z: [u8; 32] = det_bytes(2, 32).try_into().unwrap();
        let (ek, dk) = keygen_internal(&d, &z);
        let m: [u8; 32] = det_bytes(3, 32).try_into().unwrap();
        let (_, c) = encaps_internal(&ek, &m).unwrap();
        assert!(encaps_internal(&ek[..100], &m).is_err());
        assert!(decaps(&dk, &c[..100]).is_err());
        assert!(decaps(&dk[..100], &c).is_err());
        // Hash check: corrupt the stored H(ek) inside dk.
        let mut dk_bad = dk.clone();
        let idx = 384 * K + EK_LEN + 3;
        dk_bad[idx] ^= 1;
        assert!(decaps(&dk_bad, &c).is_err());
    }

    #[test]
    fn compress_decompress_modular_closeness() {
        // decompress(compress(x)) ≡ x (mod q) up to quantization: the
        // modular distance must be small even though the plain distance can
        // be large (1-bit compression wraps).
        for x in [0i32, 1, Q - 1, Q / 2, 100, 3200] {
            for d in [1u32, 4, 10] {
                let y = compress(x, d);
                assert!(y >= 0 && y < (1 << d));
                let back = decompress(y, d);
                let diff = (back - x).rem_euclid(Q);
                let diff = diff.min(Q - diff);
                let slack = Q / (1i32 << d) + 2;
                assert!(diff <= slack, "x={x} d={d} y={y} back={back} diff={diff}");
            }
        }
    }
}
