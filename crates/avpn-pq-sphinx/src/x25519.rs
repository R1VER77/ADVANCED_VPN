//! X25519 (RFC 7748) — inner-hop key agreement for option E.
//!
//! 5×51-bit limb field arithmetic over GF(2^255−19), Montgomery ladder.
//! Cross-verified against Python `cryptography` (X25519) in vectors.json.
//!
//! NOT constant-time: reference implementation; swap in curve25519-dalek at
//! integration.

const MASK51: u64 = (1u64 << 51) - 1;
const A24: u64 = 121665;

#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

impl Fe {
    const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load64 = |i: usize| -> u64 {
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(v)
        };
        Fe([
            load64(0) & MASK51,
            (load64(6) >> 3) & MASK51,
            (load64(12) >> 6) & MASK51,
            (load64(19) >> 1) & MASK51,
            (load64(24) >> 12) & MASK51,
        ])
    }

    fn to_bytes(&self) -> [u8; 32] {
        let mut t = self.reduced();
        // Canonical representative: subtract p if t >= p
        // (p limbs: (2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1)).
        let pl = [
            (1u64 << 51) - 19,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
            (1u64 << 51) - 1,
        ];
        let mut sub = [0u64; 5];
        let mut borrow: u64 = 0;
        for i in 0..5 {
            let (d, b) = (t.0[i]).overflowing_sub(pl[i] + borrow);
            sub[i] = d;
            borrow = b as u64;
        }
        // borrow == 1  ->  t < p, keep t; borrow == 0 -> t >= p, use sub.
        let mask = borrow.wrapping_sub(1); // all-ones iff borrow == 0
        for i in 0..5 {
            t.0[i] = (t.0[i] & !mask) | (sub[i] & mask);
        }
        let mut out = [0u8; 32];
        let mut carry: u128 = 0;
        let mut carry_bits = 0usize;
        let mut pos = 0usize;
        for limb in t.0.iter() {
            carry |= (*limb as u128) << carry_bits;
            carry_bits += 51;
            while carry_bits >= 8 && pos < 32 {
                out[pos] = (carry & 0xFF) as u8;
                carry >>= 8;
                carry_bits -= 8;
                pos += 1;
            }
        }
        while pos < 32 && carry != 0 {
            out[pos] = (carry & 0xFF) as u8;
            carry >>= 8;
            pos += 1;
        }
        out
    }

    /// Full reduction to a canonical representative < p (limbs < 2^51,
    /// value < 2^255-19 ... value < p after final conditional subtract done
    /// in to_bytes; here we only bound limbs and fold 2^255).
    fn reduced(&self) -> Fe {
        let mut t = *self;
        for _ in 0..2 {
            let mut carry: u64 = 0;
            let mut l = [0u64; 5];
            for i in 0..5 {
                let v = t.0[i] + carry;
                l[i] = v & MASK51;
                carry = v >> 51;
            }
            l[0] += carry.wrapping_mul(19);
            let mut again = true;
            while again {
                again = false;
                for i in 0..5 {
                    let hi = l[i] >> 51;
                    if hi != 0 {
                        l[i] &= MASK51;
                        l[(i + 1) % 5] += if i == 4 { hi * 19 } else { hi };
                        if i == 4 {
                            again = true;
                        }
                    }
                }
            }
            t = Fe(l);
        }
        t
    }

    fn add(&self, other: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + other.0[i];
        }
        Fe(r)
    }

    fn sub(&self, other: &Fe) -> Fe {
        // Add 2p first so every limb stays positive before reduction.
        const P2_0: u64 = 2 * ((1u64 << 51) - 19);
        const P2_I: u64 = 2 * ((1u64 << 51) - 1);
        let mut r = [0u64; 5];
        r[0] = self.0[0] + P2_0 - other.0[0];
        for i in 1..5 {
            r[i] = self.0[i] + P2_I - other.0[i];
        }
        Fe(r).reduced()
    }

    fn mul(&self, other: &Fe) -> Fe {
        let a = &self.0;
        let b = &other.0;
        let b1_19 = (b[1] as u128) * 19;
        let b2_19 = (b[2] as u128) * 19;
        let b3_19 = (b[3] as u128) * 19;
        let b4_19 = (b[4] as u128) * 19;
        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;
        let b0 = b[0] as u128;
        let b1 = b[1] as u128;
        let b2 = b[2] as u128;
        let b3 = b[3] as u128;
        let b4 = b[4] as u128;

        let c0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let c1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let c2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
        carry_reduce([c0, c1, c2, c3, c4])
    }

    fn sq(&self) -> Fe {
        self.mul(self)
    }

    /// Multiplicative inverse via exponentiation by p−2 = 2^255−21.
    /// (Square-and-multiply over the exponent bits; slower than an addition
    /// chain but trivially auditable.)
    fn invert(&self) -> Fe {
        // p - 2 = 2^255 - 21, little-endian bytes.
        let mut exp = [0u8; 32];
        exp[31] = 0x80;
        let mut borrow: i64 = 21;
        for i in 0..32 {
            let v = exp[i] as i64 - borrow;
            if v < 0 {
                exp[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                exp[i] = v as u8;
                borrow = 0;
            }
        }
        let mut acc = Fe::ONE;
        let mut started = false;
        for byte_i in (0..32).rev() {
            for bit_i in (0..8).rev() {
                let bit = (exp[byte_i] >> bit_i) & 1;
                if !started {
                    if bit == 1 {
                        started = true;
                        acc = *self; // leading set bit: start at v^1
                    }
                    continue;
                }
                acc = acc.sq();
                if bit == 1 {
                    acc = acc.mul(self);
                }
            }
        }
        acc
    }

    fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }
}

fn carry_reduce(c: [u128; 5]) -> Fe {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..5 {
        let v = c[i] + carry;
        out[i] = (v as u64) & MASK51;
        carry = v >> 51;
    }
    out[0] += (carry as u64) * 19;
    for i in 0..4 {
        let hi = out[i] >> 51;
        out[i] &= MASK51;
        out[i + 1] += hi;
    }
    let hi = out[4] >> 51;
    out[4] &= MASK51;
    out[0] += hi * 19;
    let fin = out[0] >> 51;
    out[0] &= MASK51;
    out[1] += fin;
    Fe(out)
}

fn clamp(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// RFC 7748 X25519: `scalar` × point `u` on Curve25519 (Montgomery ladder).
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    clamp(&mut k);
    let mut ub = *u;
    ub[31] &= 0x7f;
    let x1 = Fe::from_bytes(&ub);

    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap: u64 = 0;

    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        Fe::cswap(swap, &mut x2, &mut x3);
        Fe::cswap(swap, &mut z2, &mut z3);
        swap = kt;

        // RFC 7748 §5 step (all field ops, no branching).
        let a = x2.add(&z2);
        let b = x2.sub(&z2);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        let aa = a.sq();
        let bb = b.sq();
        let e = aa.sub(&bb);

        x3 = da.add(&cb).sq();
        z3 = x1.mul(&da.sub(&cb).sq());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&Fe([A24, 0, 0, 0, 0]).mul(&e)));
    }
    Fe::cswap(swap, &mut x2, &mut x3);
    Fe::cswap(swap, &mut z2, &mut z3);

    x2.mul(&z2.invert()).to_bytes()
}

/// Multiply the base point (u = 9): public-key generation.
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut g = [0u8; 32];
    g[0] = 9;
    x25519(scalar, &g)
}

/// True for all-zero shared secrets (small-order / degenerate inputs).
pub fn is_all_zero(b: &[u8; 32]) -> bool {
    b.iter().all(|&x| x == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rfc7748_vector_1() {
        let scalar = hex_to_32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex_to_32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            hex(&x25519(&scalar, &u)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    #[test]
    fn rfc7748_vector_2() {
        let scalar = hex_to_32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = hex_to_32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        assert_eq!(
            hex(&x25519(&scalar, &u)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        let alice = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = x25519_base(&alice);
        let b_pub = x25519_base(&bob);
        assert_eq!(
            hex(&a_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex(&b_pub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let ss1 = x25519(&alice, &b_pub);
        let ss2 = x25519(&bob, &a_pub);
        assert_eq!(ss1, ss2);
        assert_eq!(
            hex(&ss1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn agreement_is_symmetric() {
        for seed in 0..20u8 {
            let mut a_sk = [seed; 32];
            a_sk[0] = seed.wrapping_mul(31);
            let mut b_sk = [255 - seed; 32];
            b_sk[1] = seed.wrapping_mul(17);
            let a_pk = x25519_base(&a_sk);
            let b_pk = x25519_base(&b_sk);
            let s1 = x25519(&a_sk, &b_pk);
            let s2 = x25519(&b_sk, &a_pk);
            assert_eq!(s1, s2, "seed {seed}");
            assert!(!is_all_zero(&s1));
        }
    }
}
