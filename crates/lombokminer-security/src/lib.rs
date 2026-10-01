// LombokMiner Security Layer
//
// Pure Rust cryptographic primitives, wallet validation,
// MITM detection, hashrate hijack detection, and config encryption.

pub mod crypto;
pub mod wallet;
pub mod detection;
pub mod vault;

pub use crypto::{aead_encrypt, aead_decrypt, chacha20_xor, AeadError};
pub use wallet::{validate_address, AddressType, AddressError, Network, ValidatedAddress};
pub use detection::{MitmDetector, MitmAlert, HijackDetector, HijackAlert, ConnectionFingerprint};
pub use vault::{ConfigVault, VaultError};
