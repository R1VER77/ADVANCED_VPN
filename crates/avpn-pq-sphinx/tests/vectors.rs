//! Cross-language verification against independent Python implementations
//! (gen_vectors.py): hashlib/hmac, the `blake3` package, `cryptography`
//! (X25519, ChaCha20-Poly1305), a pure big-int Poly1305, and kyber-py's
//! FIPS 203 ML-KEM-768. kyber-py is itself validated against the official
//! NIST KATs, so ek/dk/c/K agreement here transitively pins this crate's
//! ML-KEM wire format to the standard.

use avpn_pq_sphinx::blake3;
use avpn_pq_sphinx::chacha::{aead_chacha20poly1305_seal, poly1305_mac};
use avpn_pq_sphinx::keccak::{sha3_256, sha3_512, shake128, shake256};
use avpn_pq_sphinx::mlkem768::{decaps, encaps_internal, keygen_internal};
use avpn_pq_sphinx::sha2::{hkdf_sha256, hmac_sha256, sha256};
use avpn_pq_sphinx::x25519::{x25519, x25519_base};

use std::collections::HashMap;
use std::fs;

type VecMap = HashMap<(String, String), Vec<u8>>;

fn vectors() -> VecMap {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors.txt");
    let text = fs::read_to_string(path).expect("vectors.txt next to Cargo.toml");
    let mut map = HashMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('|').collect();
        assert_eq!(parts.len(), 3, "bad line: {line}");
        let bytes: Vec<u8> = (0..parts[2].len() / 2)
            .map(|i| u8::from_str_radix(&parts[2][2 * i..2 * i + 2], 16).unwrap())
            .collect();
        map.insert((parts[0].to_string(), parts[1].to_string()), bytes);
    }
    map
}

fn get(m: &VecMap, name: &str, field: &str) -> Vec<u8> {
    m.get(&(name.to_string(), field.to_string()))
        .unwrap_or_else(|| panic!("missing {name}|{field}"))
        .clone()
}

fn arr32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}
fn arr12(b: &[u8]) -> [u8; 12] {
    b.try_into().unwrap()
}

#[test]
fn cross_sha2_family() {
    let v = vectors();
    for i in 0..5 {
        let name = format!("sha256_{i}");
        let data = get(&v, &name, "data");
        assert_eq!(sha256(&data), arr32(&get(&v, &name, "digest")), "{name}");
    }
    for i in 0..3 {
        let name = format!("hmac_{i}");
        assert_eq!(
            hmac_sha256(&get(&v, &name, "key"), &get(&v, &name, "msg")),
            arr32(&get(&v, &name, "digest")),
            "{name}"
        );
    }
    for i in 0..3 {
        let name = format!("hkdf_{i}");
        let ln = get(&v, &name, "len")[0] as usize;
        assert_eq!(
            hkdf_sha256(
                &get(&v, &name, "salt"),
                &get(&v, &name, "ikm"),
                &get(&v, &name, "info"),
                ln
            ),
            get(&v, &name, "okm"),
            "{name}"
        );
    }
}

#[test]
fn cross_sha3_shake() {
    let v = vectors();
    for i in 0..4 {
        let name = format!("sha3_256_{i}");
        assert_eq!(
            sha3_256(&get(&v, &name, "data")),
            arr32(&get(&v, &name, "digest")),
            "{name}"
        );
        let name = format!("sha3_512_{i}");
        assert_eq!(
            &sha3_512(&get(&v, &name, "data"))[..],
            &get(&v, &name, "digest")[..],
            "{name}"
        );
        let name = format!("shake128_{i}");
        assert_eq!(
            shake128(&get(&v, &name, "data"), 64),
            get(&v, &name, "digest"),
            "{name}"
        );
        let name = format!("shake256_{i}");
        assert_eq!(
            shake256(&get(&v, &name, "data"), 200),
            get(&v, &name, "digest"),
            "{name}"
        );
    }
}

#[test]
fn cross_blake3() {
    let v = vectors();
    for ln in [
        0usize, 1, 2, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 4097, 5000,
    ] {
        let name = format!("blake3_{ln}");
        let data = unkeyed_data(&v, ln);
        assert_eq!(
            blake3::hash(&data),
            arr32(&get(&v, &name, "hash")),
            "{name}"
        );
    }
    for ln in [
        0usize, 1, 64, 65, 1023, 1024, 1025, 2048, 2049, 3072, 4096, 4097, 5000,
    ] {
        let name = format!("blake3k_{ln}");
        let data = get(&v, &name, "data");
        let key = arr32(&get(&v, &name, "key"));
        assert_eq!(
            blake3::keyed_hash(&key, &data),
            arr32(&get(&v, &name, "hash")),
            "{name}"
        );
    }
}

fn unkeyed_data(v: &VecMap, ln: usize) -> Vec<u8> {
    // The unkeyed cases share the data recorded with the keyed cases.
    get(v, &format!("blake3k_{ln}"), "data")
}

#[test]
fn cross_x25519() {
    let v = vectors();
    for i in 0..6 {
        let name = format!("x25519_{i}");
        let ask = arr32(&get(&v, &name, "ask"));
        let bpub = arr32(&get(&v, &name, "bpub"));
        assert_eq!(
            x25519(&ask, &bpub),
            arr32(&get(&v, &name, "ss")),
            "{name} shared secret"
        );
        assert_eq!(
            x25519_base(&ask),
            arr32(&get(&v, &name, "apub")),
            "{name} base mult"
        );
        let bsk = arr32(&get(&v, &name, "bsk"));
        let ss2 = x25519(&bsk, &arr32(&get(&v, &name, "apub")));
        assert_eq!(ss2, arr32(&get(&v, &name, "ss")), "{name} symmetry");
    }
}

#[test]
fn cross_poly1305_and_aead() {
    let v = vectors();
    for i in 0..4 {
        let name = format!("poly1305_{i}");
        let tag: [u8; 16] = get(&v, &name, "tag")[..16].try_into().unwrap();
        assert_eq!(
            poly1305_mac(&arr32(&get(&v, &name, "key")), &get(&v, &name, "msg")),
            tag,
            "{name}"
        );
    }
    for i in 0..3 {
        let name = format!("aead_{i}");
        let sealed = aead_chacha20poly1305_seal(
            &arr32(&get(&v, &name, "key")),
            &arr12(&get(&v, &name, "nonce")),
            &get(&v, &name, "aad"),
            &get(&v, &name, "pt"),
        );
        assert_eq!(sealed, get(&v, &name, "sealed"), "{name}");
    }
}

#[test]
fn cross_mlkem768() {
    let v = vectors();
    for i in 0..4 {
        let name = format!("mlkem_{i}");
        let d = arr32(&get(&v, &name, "d"));
        let z = arr32(&get(&v, &name, "z"));
        let (ek, dk) = keygen_internal(&d, &z);
        assert_eq!(ek, get(&v, &name, "ek"), "{name} ek (wire format!)");
        assert_eq!(dk, get(&v, &name, "dk"), "{name} dk (wire format!)");
        let m = arr32(&get(&v, &name, "m"));
        let (k, c) = encaps_internal(&ek, &m).unwrap();
        assert_eq!(k, get(&v, &name, "K"), "{name} shared secret");
        assert_eq!(c, get(&v, &name, "c"), "{name} ciphertext (wire format!)");
        let k2 = decaps(&dk, &c).unwrap();
        assert_eq!(k2, get(&v, &name, "K"), "{name} decaps");
        // Implicit rejection: same tamper, same deterministic garbage key.
        let mut bad = c.clone();
        bad[17] ^= 0x40;
        assert_eq!(
            decaps(&dk, &bad).unwrap(),
            get(&v, &name, "Kbad"),
            "{name} implicit rejection"
        );
    }
}
