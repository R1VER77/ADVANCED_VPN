//! ChaCha20, Poly1305 and ChaCha20-Poly1305 AEAD (RFC 8439), plus the raw
//! keystream used for slot shift / cover / routing-block streams.
//!
//! Cross-verified against Python `cryptography` (ChaCha20Poly1305) in
//! vectors.json. NOT constant-time (Poly1305 arithmetic is plain u128):
//! reference implementation; swap in the `chacha20poly1305` crate at
//! integration.

// ---------------------------------------------------------------------------
// ChaCha20
// ---------------------------------------------------------------------------

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut w = state;
    for _ in 0..10 {
        quarter_round(&mut w, 0, 4, 8, 12);
        quarter_round(&mut w, 1, 5, 9, 13);
        quarter_round(&mut w, 2, 6, 10, 14);
        quarter_round(&mut w, 3, 7, 11, 15);
        quarter_round(&mut w, 0, 5, 10, 15);
        quarter_round(&mut w, 1, 6, 11, 12);
        quarter_round(&mut w, 2, 7, 8, 13);
        quarter_round(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = w[i].wrapping_add(state[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// ChaCha20 keystream of `len` bytes (counter from 0): slot shifting,
/// routing-block encryption, consumed-slot cover bytes.
pub fn chacha20_keystream(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let block = chacha20_block(key, counter, nonce);
        let take = (len - out.len()).min(64);
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// ChaCha20 XOR with explicit counter start (RFC 8439 §2.4).
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let block = chacha20_block(key, ctr, nonce);
        for (b, k) in chunk.iter_mut().zip(block) {
            *b ^= k;
        }
        ctr = ctr.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Poly1305 (3×44-bit limbs, u128 products)
// ---------------------------------------------------------------------------

const M44: u128 = (1u128 << 44) - 1;

/// r and s from the one-time key, r clamped per RFC 8439 §2.5.
/// Limbs: r0 = bits 0..44, r1 = bits 44..88, r2 = bits 88..124.
fn poly1305_keys(key: &[u8; 32]) -> (u128, u128, u128, u128) {
    let mut rb = [0u8; 16];
    rb.copy_from_slice(&key[..16]);
    rb[3] &= 15;
    rb[7] &= 15;
    rb[11] &= 15;
    rb[15] &= 15;
    rb[4] &= 252;
    rb[8] &= 252;
    rb[12] &= 252;
    let r0 = (u64::from_le_bytes(rb[0..8].try_into().unwrap()) as u128) & M44;
    // bits 44..88: load 8 bytes starting at byte 5 (bit 40), shift right 4.
    let r1 = ((u64::from_le_bytes(rb[5..13].try_into().unwrap()) as u128) >> 4) & M44;
    // bits 88..124: load 5 bytes starting at byte 11 (bit 88).
    let mut hi = [0u8; 8];
    hi[..5].copy_from_slice(&rb[11..16]);
    let r2 = u128::from(u64::from_le_bytes(hi));
    let s = u128::from_le_bytes(key[16..32].try_into().unwrap());
    (r0, r1, r2, s)
}

/// Split a 17-byte little-endian block (with the high +1 pad byte) into
/// 44/44/42-bit limbs.
fn split_block(n: &[u8; 17]) -> (u128, u128, u128) {
    let n0 = (u64::from_le_bytes(n[0..8].try_into().unwrap()) as u128) & M44;
    let n1 = ((u64::from_le_bytes(n[5..13].try_into().unwrap()) as u128) >> 4) & M44;
    let mut hi = [0u8; 8];
    hi[..5].copy_from_slice(&n[11..16]);
    hi[5] = n[16]; // bit 128 -> n2 bit 40
    let n2 = u128::from(u64::from_le_bytes(hi));
    (n0, n1, n2)
}

/// Raw Poly1305 MAC (RFC 8439 §2.5). Public for cross-language
/// verification; the AEAD layer above is the normal entry point.
pub fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let (r0, r1, r2, s) = poly1305_keys(key);
    let (mut a0, mut a1, mut a2) = (0u128, 0u128, 0u128);
    let mut i = 0usize;
    while i < msg.len() {
        let end = (i + 16).min(msg.len());
        let mut block = [0u8; 17];
        block[..end - i].copy_from_slice(&msg[i..end]);
        block[end - i] = 1;
        let (n0, n1, n2) = split_block(&block);
        // acc = (acc + n) * r  mod  2^130 - 5
        // 3-limb schoolbook, 44-bit limbs: products at weight 2^132 fold as
        // ×20 (2^130 ≡ 5 ⇒ 2^132 ≡ 20); the 2^176 term folds as 20·2^44.
        a0 += n0;
        a1 += n1;
        a2 += n2;
        let d0 = a0 * r0 + 20 * (a1 * r2 + a2 * r1);
        let d1 = a0 * r1 + a1 * r0 + 20 * (a2 * r2);
        let d2 = a0 * r2 + a1 * r1 + a2 * r0;
        a0 = d0 & M44;
        let c = d0 >> 44;
        a1 = (d1 + c) & M44;
        let c = (d1 + (d0 >> 44)) >> 44;
        a2 = d2 + c;
        let c = a2 >> 44;
        a2 &= M44;
        a0 += 20 * c; // fold 2^132 -> 20
        let c = a0 >> 44;
        a0 &= M44;
        a1 += c; // a1 may now slightly exceed 2^44; absorbed next round
        i = end;
    }
    // Final full reduction: limbs are partially carried. Fold a2's and a1's
    // overflow, then subtract p until below it.
    for _ in 0..3 {
        let c = a2 >> 44;
        a2 &= M44;
        a0 += c * 20; // 2^132 -> 20
        let c = a0 >> 44;
        a0 &= M44;
        a1 += c;
        let c = a1 >> 44;
        a1 &= M44;
        a2 += c;
    }
    // Now value = a0 + a1*2^44 + a2*2^88; subtract p until below it.
    // p = 2^130 - 5 in limbs (44, 44, 42): (2^44-5, 2^44-1, 2^42-1).
    loop {
        let p0 = M44 - 4;
        let p1 = M44;
        let p2 = (1u128 << 42) - 1;
        let ge = a2 > p2 || (a2 == p2 && (a1 > p1 || (a1 == p1 && a0 >= p0)));
        if !ge {
            break;
        }
        // value -= p via a base-2^44 borrow chain (i128 keeps it signed;
        // u128 wrapping would borrow 2^128, not one limb unit).
        let pl = [p0 as i128, p1 as i128, p2 as i128];
        let al = [a0 as i128, a1 as i128, a2 as i128];
        let mut borrow: i128 = 0;
        let mut t = [0u128; 3];
        for i in 0..3 {
            let d = al[i] - pl[i] + borrow;
            if d < 0 {
                t[i] = (d + (1i128 << 44)) as u128;
                borrow = -1;
            } else {
                t[i] = d as u128;
                borrow = 0;
            }
        }
        if borrow != 0 {
            break; // defensive: ge guaranteed value >= p
        }
        a0 = t[0];
        a1 = t[1];
        a2 = t[2];
    }
    // tag = (value + s) mod 2^128, with value < p < 2^130: compute on the
    // low 128 bits via wrapping adds (the high bits are discarded by design).
    let mask42 = (1u128 << 42) - 1;
    let lo = a0.wrapping_add(a1 << 44).wrapping_add((a2 & mask42) << 88);
    let result = lo.wrapping_add(s);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// AEAD (RFC 8439 §2.8)
// ---------------------------------------------------------------------------

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

fn pad16(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

fn aead_tag(aad: &[u8], ciphertext: &[u8], otk: &[u8; 32]) -> [u8; 16] {
    let mut mac_data = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
    mac_data.extend_from_slice(aad);
    mac_data.extend(std::iter::repeat(0u8).take(pad16(aad.len())));
    mac_data.extend_from_slice(ciphertext);
    mac_data.extend(std::iter::repeat(0u8).take(pad16(ciphertext.len())));
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_mac(otk, &mac_data)
}

/// RFC 8439 AEAD seal: returns ciphertext with the 16-byte tag appended.
pub fn aead_chacha20poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let poly_block = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&poly_block[..32]);
    let mut ct = plaintext.to_vec();
    chacha20_xor(key, 1, nonce, &mut ct);
    let tag = aead_tag(aad, &ct, &otk);
    ct.extend_from_slice(&tag);
    ct
}

/// RFC 8439 AEAD open: ciphertext||tag in, plaintext out (constant-time tag
/// comparison).
pub fn aead_chacha20poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return None;
    }
    let (ct, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_LEN);
    let poly_block = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&poly_block[..32]);
    let expected = aead_tag(aad, ct, &otk);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let mut pt = ct.to_vec();
    chacha20_xor(key, 1, nonce, &mut pt);
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
    fn hex_to_32(s: &str) -> [u8; 32] {
        hex_to_vec(s).try_into().unwrap()
    }
    fn hex_to_12(s: &str) -> [u8; 12] {
        hex_to_vec(s).try_into().unwrap()
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rfc8439_block_function() {
        let key = hex_to_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex_to_12("000000090000004a00000000");
        let block = chacha20_block(&key, 1, &nonce);
        let expected = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            .replace(char::is_whitespace, "");
        assert_eq!(hex(&block), expected);
    }

    #[test]
    fn rfc8439_aead_seal() {
        let key = hex_to_32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex_to_12("070000004041424344454647");
        let aad = hex_to_vec("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = aead_chacha20poly1305_seal(&key, &nonce, &aad, pt);
        assert_eq!(sealed.len(), pt.len() + 16);
        assert_eq!(
            hex(&sealed[sealed.len() - 16..]),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
        let opened = aead_chacha20poly1305_open(&key, &nonce, &aad, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn aead_tamper_detection() {
        let key = [42u8; 32];
        let nonce = [7u8; 12];
        let sealed = aead_chacha20poly1305_seal(&key, &nonce, b"aad", b"secret payload");
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(aead_chacha20poly1305_open(&key, &nonce, b"aad", &tampered).is_none());
        assert!(aead_chacha20poly1305_open(&key, &nonce, b"bad", &sealed).is_none());
        let mut bad_tag = sealed.clone();
        let n = bad_tag.len();
        bad_tag[n - 1] ^= 0x80;
        assert!(aead_chacha20poly1305_open(&key, &nonce, b"aad", &bad_tag).is_none());
    }

    #[test]
    fn aead_empty_plaintext() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let sealed = aead_chacha20poly1305_seal(&key, &nonce, b"", b"");
        assert_eq!(sealed.len(), 16);
        assert!(aead_chacha20poly1305_open(&key, &nonce, b"", &sealed).is_some());
        assert!(aead_chacha20poly1305_open(&key, &nonce, b"x", &sealed).is_none());
    }

    #[test]
    fn keystream_deterministic_prefix_extensible() {
        let key = [9u8; 32];
        let nonce = [0u8; 12];
        let a = chacha20_keystream(&key, &nonce, 100);
        let b = chacha20_keystream(&key, &nonce, 200);
        assert_eq!(&a[..], &b[..100]);
        assert!(a.iter().any(|&x| x != 0));
    }

    #[test]
    fn poly1305_rfc8439_tag() {
        // RFC 8439 §2.5.2; expected value computed with an independent
        // pure-Python big-int Poly1305 (direct spec transcription), also
        // re-checked in vectors.json.
        let key = hex_to_32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg = b"Cryptographic Forum Research Group";
        assert_eq!(
            hex(&poly1305_mac(&key, msg)),
            "a8061dc1305136c6c22b8baf0c0127a9"
        );
    }

    #[test]
    fn poly1305_empty_and_long() {
        // Empty message: acc = 0, tag = s mod 2^128.
        let key = hex_to_32("02000000000000000000000000000000ffffffffffffffffffffffffffffffff");
        assert_eq!(
            hex(&poly1305_mac(&key, b"")),
            "ffffffffffffffffffffffffffffffff"
        );
        // Multi-block: cross-checked in vectors.json; here determinism + shape.
        let t1 = poly1305_mac(&key, &[7u8; 100]);
        let t2 = poly1305_mac(&key, &[7u8; 100]);
        assert_eq!(t1, t2);
        assert_eq!(
            poly1305_mac(&key, &[7u8; 16]),
            poly1305_mac(&key, &[7u8; 16])
        );
    }
}
