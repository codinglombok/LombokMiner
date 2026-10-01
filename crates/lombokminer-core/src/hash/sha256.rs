// LombokMiner — Pure Rust SHA-256 implementation
// NIST FIPS 180-4 compliant, zero external dependencies.
//
// This is the scalar fallback. SIMD-accelerated variants (AVX2, SHA-NI, NEON)
// are in sibling modules and selected at runtime via `mod.rs`.

/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 hasher state.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Create a new SHA-256 hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            state: H_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        // Fill buffer if partially full
        if self.buffer_len > 0 {
            let remaining = 64 - self.buffer_len;
            let to_copy = data.len().min(remaining);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == 64 {
                let block = self.buffer;
                Self::compress(&mut self.state, &block);
                self.buffer_len = 0;
            }
        }

        // Process complete 64-byte blocks directly
        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            Self::compress(&mut self.state, &block);
            offset += 64;
        }

        // Buffer remaining bytes
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize and return the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

        // Padding: append 1 bit, then zeros, then 64-bit big-endian length
        self.update(&[0x80]);
        while self.buffer_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_len.to_be_bytes());

        let mut out = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Compress a single 512-bit (64-byte) block into the state.
    #[inline]
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        // Message schedule
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

        // 64 rounds
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute SHA-256 hash of a byte slice in one call.
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Compute SHA-256d (double SHA-256) — the Bitcoin proof-of-work hash function.
/// SHA-256d(x) = SHA-256(SHA-256(x))
#[inline]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute SHA-256d of an 80-byte block header.
/// This is the hot path for mining — optimized for exactly 80 bytes.
#[inline]
pub fn sha256d_80(header: &[u8; 80]) -> [u8; 32] {
    sha256d(header)
}

/// Compute the midstate of SHA-256 after processing the first 64 bytes of an 80-byte header.
/// This allows reusing the midstate when only the last 16 bytes (containing the nonce) change.
///
/// For mining, this halves the SHA-256 work per nonce iteration:
/// - Compute midstate once for the first 64 bytes
/// - For each nonce: compress only the remaining 16 bytes (padded to 64) + finalize
#[inline]
pub fn sha256_midstate(first_64_bytes: &[u8; 64]) -> [u32; 8] {
    let mut state = H_INIT;
    Sha256::compress(&mut state, first_64_bytes);
    state
}

/// Complete a SHA-256 hash from a midstate and the remaining 16 bytes of the header.
/// Used in the mining hot loop: midstate is precomputed, only the nonce changes.
pub fn sha256_from_midstate(midstate: &[u32; 8], last_16_bytes: &[u8; 16]) -> [u8; 32] {
    let mut state = *midstate;

    // Build the final padded block:
    // [16 bytes data] [0x80] [zeros] [64-bit big-endian bit length = 80*8 = 640 = 0x280]
    let mut block = [0u8; 64];
    block[..16].copy_from_slice(last_16_bytes);
    block[16] = 0x80;
    // Total message length = 80 bytes = 640 bits = 0x0000000000000280
    block[62] = 0x02;
    block[63] = 0x80;

    Sha256::compress(&mut state, &block);

    let mut first_hash = [0u8; 32];
    for (i, &word) in state.iter().enumerate() {
        first_hash[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }

    // Second SHA-256 pass (the 'd' in SHA-256d)
    sha256(&first_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        assert_eq!(
            hex::encode(hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_long() {
        // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let hash = sha256(input);
        assert_eq!(
            hex::encode(hash),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256d() {
        // SHA-256d("hello") — known Bitcoin test vector
        let hash = sha256d(b"hello");
        let first = sha256(b"hello");
        let second = sha256(&first);
        assert_eq!(hash, second);
    }

    #[test]
    fn test_sha256d_80_matches_sha256d() {
        let header = [0x42u8; 80];
        assert_eq!(sha256d_80(&header), sha256d(&header));
    }

    #[test]
    fn test_midstate_optimization() {
        // Verify midstate optimization produces identical results to full hash
        let mut header = [0u8; 80];
        for (i, byte) in header.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let full_hash = sha256d(&header);

        let first_64: [u8; 64] = header[..64].try_into().unwrap();
        let last_16: [u8; 16] = header[64..].try_into().unwrap();

        let midstate = sha256_midstate(&first_64);
        let midstate_hash = sha256_from_midstate(&midstate, &last_16);

        assert_eq!(full_hash, midstate_hash);
    }

    #[test]
    fn test_midstate_nonce_iteration() {
        // Simulate mining: change nonce (bytes 76-79), verify midstate reuse works
        let mut header = [0xABu8; 80];
        let first_64: [u8; 64] = header[..64].try_into().unwrap();
        let midstate = sha256_midstate(&first_64);

        for nonce in 0u32..100 {
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
            let last_16: [u8; 16] = header[64..].try_into().unwrap();

            let full = sha256d(&header);
            let optimized = sha256_from_midstate(&midstate, &last_16);
            assert_eq!(full, optimized, "Mismatch at nonce {nonce}");
        }
    }

    /// Bitcoin Genesis Block header test vector
    #[test]
    fn test_genesis_block_hash() {
        // Bitcoin genesis block header (80 bytes, little-endian)
        let header_hex = concat!(
            "01000000",                                                         // version
            "0000000000000000000000000000000000000000000000000000000000000000",   // prev_block
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",   // merkle_root
            "29ab5f49",                                                         // timestamp
            "ffff001d",                                                         // bits
            "1dac2b7c"                                                          // nonce
        );
        let header_bytes = hex::decode(header_hex).unwrap();
        assert_eq!(header_bytes.len(), 80);

        let hash = sha256d(&header_bytes);

        // Genesis block hash (displayed in big-endian / RPC byte order)
        let mut hash_be = hash;
        hash_be.reverse();
        assert_eq!(
            hex::encode(hash_be),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }
}
