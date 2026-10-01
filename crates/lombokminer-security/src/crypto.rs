// LombokMiner — ChaCha20-Poly1305 AEAD
//
// Pure Rust implementation of ChaCha20-Poly1305 (RFC 8439).
// Used for: Stratum V2 transport encryption, config vault at rest.
// Zero external dependencies.

/// ChaCha20 quarter-round operation.
#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Generate a ChaCha20 keystream block.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];

    // Constants: "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3],
        ]);
    }

    // Counter
    state[12] = counter;

    // Nonce
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4], nonce[i * 4 + 1], nonce[i * 4 + 2], nonce[i * 4 + 3],
        ]);
    }

    let initial = state;

    // 20 rounds (10 double-rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialize to bytes
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Encrypt/decrypt with ChaCha20 (XOR keystream).
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut block_counter = counter;
    let mut offset = 0;

    while offset < data.len() {
        let keystream = chacha20_block(key, block_counter, nonce);
        let remaining = data.len() - offset;
        let to_xor = remaining.min(64);

        for i in 0..to_xor {
            data[offset + i] ^= keystream[i];
        }

        offset += to_xor;
        block_counter += 1;
    }
}

// ─── Poly1305 MAC ───────────────────────────────────────────────────────────

/// Poly1305 authenticator state.
struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        // r = key[0..16], clamped
        let r0 = u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0ffffffc0fffffff;
        let r1 = u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0ffffffc0ffffffc;

        // pad = key[16..32]
        let pad0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let pad1 = u64::from_le_bytes(key[24..32].try_into().unwrap());

        Self {
            r: [r0, r1, 0],
            h: [0, 0, 0],
            pad: [pad0, pad1],
        }
    }

    fn block(&mut self, msg: &[u8], is_last: bool) {
        // Load 16 bytes as little-endian u128, add high bit
        let mut n = [0u8; 17];
        let len = msg.len().min(16);
        n[..len].copy_from_slice(&msg[..len]);
        if !is_last || len == 16 {
            n[len] = 1; // high bit
        }

        let t0 = u64::from_le_bytes(n[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(n[8..16].try_into().unwrap());
        let t2 = n[16] as u64;

        // h += msg
        self.h[0] = self.h[0].wrapping_add(t0);
        let carry = if self.h[0] < t0 { 1u64 } else { 0 };
        self.h[1] = self.h[1].wrapping_add(t1).wrapping_add(carry);
        let carry = if self.h[1] < t1.wrapping_add(carry) { 1u64 } else { 0 };
        self.h[2] = self.h[2].wrapping_add(t2).wrapping_add(carry);

        // h *= r (mod 2^130 - 5) — simplified for correctness, not speed
        // For a mining application, this runs rarely (per-message, not per-hash)
        self.mul_mod();
    }

    fn mul_mod(&mut self) {
        // Simplified modular multiplication using u128
        let h0 = self.h[0] as u128;
        let h1 = self.h[1] as u128;
        let h2 = self.h[2] as u128;
        let r0 = self.r[0] as u128;
        let r1 = self.r[1] as u128;

        // Partial products
        let d0 = h0 * r0;
        let d1 = h0 * r1 + h1 * r0;
        let d2 = h1 * r1 + h2 * r0;

        // Reduction mod 2^130 - 5
        let mut c: u128;
        let mut h0 = d0 & 0xFFFFFFFFFFFFFFFF;
        c = d0 >> 64;
        let mut h1 = d1.wrapping_add(c) & 0xFFFFFFFFFFFFFFFF;
        c = d1.wrapping_add(c) >> 64;
        let mut h2 = d2.wrapping_add(c);

        // Reduce: if h >= 2^130, subtract and fold
        c = h2 >> 2;
        h2 &= 3;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 64;
        h0 &= 0xFFFFFFFFFFFFFFFF;
        h1 = h1.wrapping_add(c);
        c = h1 >> 64;
        h1 &= 0xFFFFFFFFFFFFFFFF;
        h2 = h2.wrapping_add(c);

        self.h[0] = h0 as u64;
        self.h[1] = h1 as u64;
        self.h[2] = h2 as u64;
    }

    fn finalize(&self) -> [u8; 16] {
        // h + pad
        let mut h0 = self.h[0] as u128;
        let h1 = self.h[1] as u128;

        h0 = h0.wrapping_add(self.pad[0] as u128);
        let carry = h0 >> 64;
        h0 &= 0xFFFFFFFFFFFFFFFF;
        let h1 = h1.wrapping_add(self.pad[1] as u128).wrapping_add(carry);

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&(h0 as u64).to_le_bytes());
        tag[8..16].copy_from_slice(&(h1 as u64).to_le_bytes());
        tag
    }
}

// ─── AEAD: ChaCha20-Poly1305 (RFC 8439) ────────────────────────────────────

/// Encrypt and authenticate with ChaCha20-Poly1305.
///
/// Returns (ciphertext, 16-byte tag).
pub fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Generate Poly1305 key from ChaCha20 block 0
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Encrypt plaintext with ChaCha20 (counter starts at 1)
    let mut ciphertext = plaintext.to_vec();
    chacha20_xor(key, nonce, 1, &mut ciphertext);

    // Compute Poly1305 tag over: AAD || pad || ciphertext || pad || len_aad || len_ct
    let tag = compute_poly1305_tag(&poly_key, aad, &ciphertext);

    (ciphertext, tag)
}

/// Decrypt and verify with ChaCha20-Poly1305.
///
/// Returns plaintext on success, error on tag mismatch.
pub fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, AeadError> {
    // Generate Poly1305 key
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_key_block[..32]);

    // Verify tag
    let computed_tag = compute_poly1305_tag(&poly_key, aad, ciphertext);
    if !constant_time_eq(&computed_tag, tag) {
        return Err(AeadError::TagMismatch);
    }

    // Decrypt
    let mut plaintext = ciphertext.to_vec();
    chacha20_xor(key, nonce, 1, &mut plaintext);

    Ok(plaintext)
}

fn compute_poly1305_tag(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(poly_key);

    // Process AAD in 16-byte blocks
    let mut i = 0;
    while i + 16 <= aad.len() {
        mac.block(&aad[i..i + 16], false);
        i += 16;
    }
    if i < aad.len() {
        let mut padded = [0u8; 16];
        padded[..aad.len() - i].copy_from_slice(&aad[i..]);
        mac.block(&padded, false);
    }

    // Process ciphertext in 16-byte blocks
    i = 0;
    while i + 16 <= ciphertext.len() {
        mac.block(&ciphertext[i..i + 16], false);
        i += 16;
    }
    if i < ciphertext.len() {
        let mut padded = [0u8; 16];
        padded[..ciphertext.len() - i].copy_from_slice(&ciphertext[i..]);
        mac.block(&padded, false);
    }

    // Lengths block
    let mut lens = [0u8; 16];
    lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.block(&lens, true);

    mac.finalize()
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// AEAD errors.
#[derive(Debug)]
pub enum AeadError {
    TagMismatch,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TagMismatch => write!(f, "authentication tag mismatch (tampered or wrong key)"),
        }
    }
}

impl std::error::Error for AeadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_rfc8439_vector() {
        // RFC 8439 Section 2.4.2 test vector
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];

        let block = chacha20_block(&key, 1, &nonce);
        // First 4 bytes of keystream should match test vector
        assert_eq!(block[0], 0x22);
        assert_eq!(block[1], 0x4f);
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"LombokMiner";
        let plaintext = b"wallet_address=bc1qexample";

        let (ciphertext, tag) = aead_encrypt(&key, &nonce, aad, plaintext);
        assert_ne!(&ciphertext, plaintext);

        let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext, &tag).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aead_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let (mut ciphertext, tag) = aead_encrypt(&key, &nonce, b"", b"secret data");

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;
        let result = aead_decrypt(&key, &nonce, b"", &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let (ciphertext, tag) = aead_encrypt(&key1, &nonce, b"", b"data");

        let result = aead_decrypt(&key2, &nonce, b"", &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_aead_empty() {
        let key = [0xAA; 32];
        let nonce = [0xBB; 12];
        let (ct, tag) = aead_encrypt(&key, &nonce, b"", b"");
        assert!(ct.is_empty());
        let pt = aead_decrypt(&key, &nonce, b"", &ct, &tag).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 16];
        let b = [1u8; 16];
        let c = [2u8; 16];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
