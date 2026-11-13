//! Keccak-f[1600], SHA-3 (FIPS 202), SHAKE128/SHAKE256 XOFs.
//!
//! ML-KEM-768 needs SHA3-256, SHA3-512, SHAKE-128 (ExpandA) and SHAKE-256
//! (PRF, J). Cross-verified against Python `hashlib` in vectors.json.

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets, indexed RHO[x][y] (A[x][y] = a[x + 5*y]).
const RHO: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],   // x = 0
    [1, 44, 10, 45, 2],   // x = 1
    [62, 6, 43, 15, 61],  // x = 2
    [28, 55, 25, 21, 56], // x = 3
    [27, 20, 39, 8, 14],  // x = 4
];

fn keccak_f1600(a: &mut [u64; 25]) {
    for rc in RC {
        // theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }
        // rho + pi
        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(RHO[x][y]);
            }
        }
        // chi
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // iota
        a[0] ^= rc;
    }
}

struct KeccakState {
    a: [u64; 25],
    rate: usize,
    buf: Vec<u8>,
}

impl KeccakState {
    #[allow(dead_code)]
    fn new(rate: usize) -> Self {
        KeccakState {
            a: [0; 25],
            rate,
            buf: Vec::with_capacity(rate),
        }
    }
    fn absorb_block(&mut self) {
        debug_assert_eq!(self.buf.len(), self.rate);
        for (i, chunk) in self.buf.chunks_exact(8).enumerate() {
            self.a[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        keccak_f1600(&mut self.a);
        self.buf.clear();
    }

    fn update(&mut self, data: &mut &[u8]) {
        while !data.is_empty() {
            let take = self.rate - self.buf.len();
            let take = take.min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            *data = &data[take..];
            if self.buf.len() == self.rate {
                self.absorb_block();
            }
        }
    }
}

fn xof(data: &[u8], rate: usize, pad: u8, out_len: usize) -> Vec<u8> {
    let mut st = KeccakState {
        a: [0; 25],
        rate,
        buf: Vec::with_capacity(rate),
    };
    let mut rest = data;
    st.update(&mut rest);
    // Pad the final partial block and absorb it.
    let mut block = vec![0u8; rate];
    block[..st.buf.len()].copy_from_slice(&st.buf);
    block[st.buf.len()] = pad;
    block[rate - 1] |= 0x80;
    st.buf = block;
    st.absorb_block();
    // Squeeze exactly out_len bytes.
    let mut out = Vec::with_capacity(out_len);
    while out.len() < out_len {
        let mut block = [0u8; 200];
        for i in 0..25 {
            block[i * 8..i * 8 + 8].copy_from_slice(&st.a[i].to_le_bytes());
        }
        let take = (out_len - out.len()).min(rate);
        out.extend_from_slice(&block[..take]);
        if out.len() < out_len {
            keccak_f1600(&mut st.a);
        }
    }
    out
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    xof(data, 136, 0x06, 32).try_into().unwrap()
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    xof(data, 72, 0x06, 64).try_into().unwrap()
}

pub fn shake128(data: &[u8], out_len: usize) -> Vec<u8> {
    xof(data, 168, 0x1f, out_len)
}

pub fn shake256(data: &[u8], out_len: usize) -> Vec<u8> {
    xof(data, 136, 0x1f, out_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha3_256_vectors() {
        assert_eq!(
            hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn sha3_512_vectors() {
        assert_eq!(
            hex(&sha3_512(b"abc")),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e1\
             0e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn shake128_vectors() {
        // Known SHAKE128("") first 32 bytes (digest length 32 KAT, cshakes... via hashlib cross-check too)
        assert_eq!(
            hex(&shake128(b"", 32)),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
        );
    }

    #[test]
    fn shake256_vectors() {
        assert_eq!(
            hex(&shake256(b"", 32)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
    }

    #[test]
    fn multi_block_and_alignment() {
        // Exercise rates across block boundaries with varying lengths.
        for len in [0usize, 1, 55, 56, 63, 64, 65, 135, 136, 137, 200, 500, 1000] {
            let data = vec![0xa3u8; len];
            let a = shake128(&data, 64);
            let b = shake256(&data, 64);
            assert_eq!(a.len(), 64);
            assert_eq!(b.len(), 64);
        }
        // Squeezing more than one block.
        let long = shake256(b"key", 300);
        assert_eq!(long.len(), 300);
        let short = shake256(b"key", 50);
        assert_eq!(
            &long[..50],
            &short[..],
            "XOF output must be a prefix-extension"
        );
    }
}
