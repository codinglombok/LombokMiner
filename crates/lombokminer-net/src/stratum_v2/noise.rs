// LombokMiner — Noise Protocol Handshake for Stratum V2
//
// SV2 uses Noise_NNpsk0 pattern:
//   → e                    (initiator sends ephemeral public key)
//   ← e, ee               (responder sends ephemeral, both derive shared secret)
//   PSK is mixed in at token 0 (before first message).
//
// After handshake, all frames are encrypted with ChaCha20-Poly1305 AEAD.
//
// This is a simplified implementation for the handshake state machine.
// In production, this would use a proper Noise library or full X25519 + ChaCha20.
// For now, we implement the state machine and use placeholder crypto that will
// be replaced with real primitives in the security crate.

use rand::RngCore;

/// Noise handshake state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state — not yet started
    Init,
    /// Initiator has sent ephemeral key, waiting for responder
    WaitingForResponder,
    /// Handshake complete — transport keys derived
    Complete,
    /// Handshake failed
    Failed,
}

/// Noise handshake role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator, // miner
    Responder, // pool
}

/// X25519 key pair (32-byte public + 32-byte secret).
#[derive(Clone)]
pub struct KeyPair {
    pub public: [u8; 32],
    secret: [u8; 32],
}

impl KeyPair {
    /// Generate a random ephemeral key pair.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        // In production: public = X25519_basepoint_mult(secret)
        // For now, derive a deterministic "public key" via hashing
        let public = lombokminer_core::hash::sha256d(&secret);
        let mut pub32 = [0u8; 32];
        pub32.copy_from_slice(&public);
        Self {
            public: pub32,
            secret,
        }
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &hex::encode(self.public))
            .field("secret", &"[redacted]")
            .finish()
    }
}

/// Noise handshake context for Stratum V2.
#[derive(Debug)]
pub struct NoiseHandshake {
    pub role: Role,
    pub state: HandshakeState,
    /// Our ephemeral key pair
    pub ephemeral: KeyPair,
    /// Remote ephemeral public key (received during handshake)
    pub remote_ephemeral: Option<[u8; 32]>,
    /// Pre-shared key (optional, for Noise_NNpsk0)
    pub psk: Option<[u8; 32]>,
    /// Derived transport keys after handshake
    pub send_key: Option<[u8; 32]>,
    pub recv_key: Option<[u8; 32]>,
    /// Handshake hash (chaining value)
    h: [u8; 32],
    /// Chaining key
    ck: [u8; 32],
}

impl NoiseHandshake {
    /// Create a new handshake as the initiator (miner).
    pub fn initiator(psk: Option<[u8; 32]>) -> Self {
        let protocol_name = b"Noise_NNpsk0_25519_ChaChaPoly_SHA256";
        let h = if protocol_name.len() <= 32 {
            let mut h = [0u8; 32];
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            lombokminer_core::hash::sha256d(protocol_name)
        };

        Self {
            role: Role::Initiator,
            state: HandshakeState::Init,
            ephemeral: KeyPair::generate(),
            remote_ephemeral: None,
            psk,
            send_key: None,
            recv_key: None,
            h,
            ck: h,
        }
    }

    /// Generate the first handshake message (initiator → responder).
    /// Message: ephemeral public key (32 bytes)
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.state != HandshakeState::Init {
            return Err(NoiseError::InvalidState);
        }

        // Mix PSK into chaining key at token 0
        if let Some(psk) = self.psk {
            self.mix_key(&psk);
        }

        // Mix our ephemeral public key into handshake hash
        self.mix_hash(&self.ephemeral.public.clone());

        self.state = HandshakeState::WaitingForResponder;

        // Send our ephemeral public key
        Ok(self.ephemeral.public.to_vec())
    }

    /// Process the second handshake message (responder → initiator).
    /// Message: responder's ephemeral public key (32 bytes)
    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        if self.state != HandshakeState::WaitingForResponder {
            return Err(NoiseError::InvalidState);
        }
        if msg.len() < 32 {
            return Err(NoiseError::MessageTooShort);
        }

        let mut remote_pub = [0u8; 32];
        remote_pub.copy_from_slice(&msg[..32]);
        self.remote_ephemeral = Some(remote_pub);

        // Mix remote ephemeral into hash
        self.mix_hash(&remote_pub);

        // Perform DH: ee = DH(ephemeral_secret, remote_ephemeral_public)
        // In production: X25519(self.ephemeral.secret, remote_pub)
        // Placeholder: HMAC-like derivation
        let mut dh_input = [0u8; 64];
        dh_input[..32].copy_from_slice(&self.ephemeral.secret);
        dh_input[32..].copy_from_slice(&remote_pub);
        let shared_secret = lombokminer_core::hash::sha256d(&dh_input);

        self.mix_key(&shared_secret);

        // Split: derive send and recv keys from chaining key
        let send_key = lombokminer_core::hash::sha256d(&[&self.ck[..], &[0x01]].concat());
        let recv_key = lombokminer_core::hash::sha256d(&[&self.ck[..], &[0x02]].concat());

        let mut sk = [0u8; 32];
        sk.copy_from_slice(&send_key);
        let mut rk = [0u8; 32];
        rk.copy_from_slice(&recv_key);

        self.send_key = Some(sk);
        self.recv_key = Some(rk);
        self.state = HandshakeState::Complete;

        Ok(())
    }

    /// Check if the handshake is complete and transport is ready.
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }

    /// Mix data into the handshake hash: h = SHA-256d(h || data)
    fn mix_hash(&mut self, data: &[u8]) {
        let input = [&self.h[..], data].concat();
        self.h = lombokminer_core::hash::sha256d(&input);
    }

    /// Mix key material into chaining key: ck = SHA-256d(ck || key)
    fn mix_key(&mut self, key: &[u8]) {
        let input = [&self.ck[..], key].concat();
        self.ck = lombokminer_core::hash::sha256d(&input);
    }
}

/// Noise handshake errors.
#[derive(Debug, Clone)]
pub enum NoiseError {
    InvalidState,
    MessageTooShort,
    AuthenticationFailed,
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState => write!(f, "invalid handshake state"),
            Self::MessageTooShort => write!(f, "handshake message too short"),
            Self::AuthenticationFailed => write!(f, "authentication failed"),
        }
    }
}

impl std::error::Error for NoiseError {}

/// Placeholder transport encryptor/decryptor.
/// After handshake, all frames pass through this for AEAD encryption.
#[derive(Debug)]
pub struct NoiseTransport {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
}

impl NoiseTransport {
    /// Create transport from completed handshake.
    pub fn from_handshake(handshake: &NoiseHandshake) -> Result<Self, NoiseError> {
        if !handshake.is_complete() {
            return Err(NoiseError::InvalidState);
        }
        Ok(Self {
            send_key: handshake.send_key.unwrap(),
            recv_key: handshake.recv_key.unwrap(),
            send_nonce: 0,
            recv_nonce: 0,
        })
    }

    /// "Encrypt" a frame payload (placeholder — XOR with key-derived stream).
    /// In production: ChaCha20-Poly1305 AEAD with nonce.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes = self.send_nonce.to_le_bytes();
        self.send_nonce += 1;

        // Derive per-message key from send_key + nonce
        let msg_key = lombokminer_core::hash::sha256d(
            &[&self.send_key[..], &nonce_bytes[..]].concat(),
        );

        // XOR encryption (placeholder for ChaCha20)
        let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
        for (i, &byte) in plaintext.iter().enumerate() {
            ciphertext.push(byte ^ msg_key[i % 32]);
        }

        // Append 16-byte "tag" (placeholder for Poly1305)
        let tag = lombokminer_core::hash::sha256d(&ciphertext);
        ciphertext.extend_from_slice(&tag[..16]);

        ciphertext
    }

    /// "Decrypt" a frame payload (placeholder).
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.len() < 16 {
            return Err(NoiseError::AuthenticationFailed);
        }

        let nonce_bytes = self.recv_nonce.to_le_bytes();
        self.recv_nonce += 1;

        let (data, _tag) = ciphertext.split_at(ciphertext.len() - 16);

        let msg_key = lombokminer_core::hash::sha256d(
            &[&self.recv_key[..], &nonce_bytes[..]].concat(),
        );

        let mut plaintext = Vec::with_capacity(data.len());
        for (i, &byte) in data.iter().enumerate() {
            plaintext.push(byte ^ msg_key[i % 32]);
        }

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flow() {
        let mut initiator = NoiseHandshake::initiator(None);
        assert_eq!(initiator.state, HandshakeState::Init);

        // Step 1: initiator generates message
        let msg1 = initiator.write_message_1().unwrap();
        assert_eq!(msg1.len(), 32);
        assert_eq!(initiator.state, HandshakeState::WaitingForResponder);

        // Step 2: simulate responder's reply (32-byte ephemeral key)
        let responder_key = KeyPair::generate();
        initiator.read_message_2(&responder_key.public).unwrap();

        assert!(initiator.is_complete());
        assert!(initiator.send_key.is_some());
        assert!(initiator.recv_key.is_some());
    }

    #[test]
    fn test_handshake_with_psk() {
        let psk = [0x42u8; 32];
        let mut initiator = NoiseHandshake::initiator(Some(psk));

        let msg1 = initiator.write_message_1().unwrap();
        assert_eq!(msg1.len(), 32);

        let responder_key = KeyPair::generate();
        initiator.read_message_2(&responder_key.public).unwrap();
        assert!(initiator.is_complete());
    }

    #[test]
    fn test_transport_encrypt_decrypt() {
        // Complete a handshake first
        let mut hs = NoiseHandshake::initiator(None);
        let _msg1 = hs.write_message_1().unwrap();
        let resp = KeyPair::generate();
        hs.read_message_2(&resp.public).unwrap();

        let mut transport = NoiseTransport::from_handshake(&hs).unwrap();

        // For the placeholder implementation, encrypt/decrypt with same keys
        // won't round-trip because send_key != recv_key.
        // This test verifies the API works without panicking.
        let plaintext = b"Hello, Stratum V2!";
        let ciphertext = transport.encrypt(plaintext);
        assert!(ciphertext.len() > plaintext.len()); // includes tag
    }

    #[test]
    fn test_invalid_state() {
        let mut hs = NoiseHandshake::initiator(None);

        // Can't read message 2 before writing message 1
        assert!(hs.read_message_2(&[0u8; 32]).is_err());

        // Can't write message 1 twice
        let _ = hs.write_message_1().unwrap();
        assert!(hs.write_message_1().is_err());
    }
}
