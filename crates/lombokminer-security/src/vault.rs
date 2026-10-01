// LombokMiner — Config Vault
//
// Encrypted storage for sensitive configuration data (wallet addresses,
// pool credentials). Uses ChaCha20-Poly1305 AEAD with a passphrase-derived key.

use crate::crypto::{aead_encrypt, aead_decrypt, AeadError};
use lombokminer_core::hash::sha256d;

/// A sealed config vault containing encrypted secrets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfigVault {
    /// Salt for key derivation (32 bytes, hex-encoded)
    pub salt: String,
    /// Nonce for AEAD (12 bytes, hex-encoded)
    pub nonce: String,
    /// Encrypted data (hex-encoded)
    pub ciphertext: String,
    /// Authentication tag (16 bytes, hex-encoded)
    pub tag: String,
    /// KDF iteration count
    pub iterations: u32,
}

impl ConfigVault {
    /// Encrypt a plaintext config string with a passphrase.
    pub fn seal(passphrase: &str, plaintext: &str) -> Self {
        let mut salt = [0u8; 32];
        fill_random(&mut salt);

        let mut nonce = [0u8; 12];
        fill_random(&mut nonce);

        let iterations = 100_000;
        let key = derive_key(passphrase, &salt, iterations);

        let aad = b"lombokminer-config-vault-v1";
        let (ciphertext, tag) = aead_encrypt(&key, &nonce, aad, plaintext.as_bytes());

        Self {
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
            tag: hex::encode(tag),
            iterations,
        }
    }

    /// Decrypt the vault with a passphrase.
    pub fn unseal(&self, passphrase: &str) -> Result<String, VaultError> {
        let salt = hex::decode(&self.salt).map_err(|_| VaultError::CorruptedVault)?;
        let nonce = hex::decode(&self.nonce).map_err(|_| VaultError::CorruptedVault)?;
        let ciphertext = hex::decode(&self.ciphertext).map_err(|_| VaultError::CorruptedVault)?;
        let tag_bytes = hex::decode(&self.tag).map_err(|_| VaultError::CorruptedVault)?;

        if salt.len() != 32 || nonce.len() != 12 || tag_bytes.len() != 16 {
            return Err(VaultError::CorruptedVault);
        }

        let salt_arr: [u8; 32] = salt.try_into().unwrap();
        let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
        let tag_arr: [u8; 16] = tag_bytes.try_into().unwrap();

        let key = derive_key(passphrase, &salt_arr, self.iterations);
        let aad = b"lombokminer-config-vault-v1";

        let plaintext = aead_decrypt(&key, &nonce_arr, aad, &ciphertext, &tag_arr)
            .map_err(|_| VaultError::WrongPassphrase)?;

        String::from_utf8(plaintext).map_err(|_| VaultError::CorruptedVault)
    }
}

/// Key derivation function (simplified PBKDF2-like using SHA-256d).
///
/// In production, this should use Argon2id (memory-hard). We use
/// iterated SHA-256d here to maintain zero-dependency. The iteration
/// count provides brute-force resistance.
fn derive_key(passphrase: &str, salt: &[u8; 32], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];

    // Initial: SHA-256d(passphrase || salt)
    let mut input = Vec::with_capacity(passphrase.len() + 32);
    input.extend_from_slice(passphrase.as_bytes());
    input.extend_from_slice(salt);
    key = sha256d(&input);

    // Iterate
    for _ in 0..iterations {
        let mut block = Vec::with_capacity(64);
        block.extend_from_slice(&key);
        block.extend_from_slice(salt);
        key = sha256d(&block);
    }

    key
}

/// Fill a buffer with random bytes.
fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

/// Vault errors.
#[derive(Debug)]
pub enum VaultError {
    WrongPassphrase,
    CorruptedVault,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassphrase => write!(f, "wrong passphrase or tampered vault"),
            Self::CorruptedVault => write!(f, "corrupted vault data"),
        }
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_seal_unseal() {
        let secret = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let passphrase = "my_secure_passphrase_123";

        let vault = ConfigVault::seal(passphrase, secret);

        // Ciphertext should differ from plaintext
        let ct = hex::decode(&vault.ciphertext).unwrap();
        assert_ne!(&ct, secret.as_bytes());

        // Unseal with correct passphrase
        let decrypted = vault.unseal(passphrase).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_vault_wrong_passphrase() {
        let vault = ConfigVault::seal("correct_pass", "secret_data");
        let result = vault.unseal("wrong_pass");
        assert!(matches!(result, Err(VaultError::WrongPassphrase)));
    }

    #[test]
    fn test_vault_serialization() {
        let vault = ConfigVault::seal("pass", "data");
        let json = serde_json::to_string(&vault).unwrap();
        let deserialized: ConfigVault = serde_json::from_str(&json).unwrap();
        let decrypted = deserialized.unseal("pass").unwrap();
        assert_eq!(decrypted, "data");
    }

    #[test]
    fn test_vault_deterministic_key() {
        let salt = [0xAA; 32];
        let key1 = derive_key("test", &salt, 10);
        let key2 = derive_key("test", &salt, 10);
        assert_eq!(key1, key2);

        // Different passphrase = different key
        let key3 = derive_key("other", &salt, 10);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_vault_empty_plaintext() {
        let vault = ConfigVault::seal("pass", "");
        let decrypted = vault.unseal("pass").unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_vault_large_data() {
        let data = "x".repeat(10_000);
        let vault = ConfigVault::seal("pass", &data);
        let decrypted = vault.unseal("pass").unwrap();
        assert_eq!(decrypted, data);
    }
}
