//! Fuzz AEAD: encrypt then tamper then decrypt must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 44 { return; }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let nonce: [u8; 12] = data[32..44].try_into().unwrap();
    let plaintext = &data[44..];

    let (ct, tag) = lombokminer_security::aead_encrypt(&key, &nonce, b"", plaintext);
    let _ = lombokminer_security::aead_decrypt(&key, &nonce, b"", &ct, &tag);

    // Tampered ciphertext should fail
    if !ct.is_empty() {
        let mut bad = ct.clone();
        bad[0] ^= 0xFF;
        let _ = lombokminer_security::aead_decrypt(&key, &nonce, b"", &bad, &tag);
    }
});
