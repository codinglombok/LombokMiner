# LombokMiner Security

## Threat Model

LombokMiner protects against:

1. **Eavesdropping** — all Stratum V2 traffic is encrypted (ChaCha20-Poly1305)
2. **Man-in-the-middle** — Noise_NNpsk0 handshake + connection fingerprinting
3. **Hashrate hijacking** — accept rate monitoring with EMA baseline
4. **Config theft** — sensitive data encrypted at rest in ConfigVault
5. **Address substitution** — Bech32/Bech32m/Base58Check validation on startup
6. **Memory corruption** — Rust ownership system prevents buffer overflows

## Encryption

### Transport (Stratum V2)
- **Handshake**: Noise_NNpsk0 (no static keys, pre-shared key)
- **Cipher**: ChaCha20-Poly1305 AEAD (RFC 8439)
- **Forward secrecy**: ephemeral keys per connection
- **Implementation**: pure Rust, zero external crypto dependencies

### Config Vault
- **Cipher**: ChaCha20-Poly1305 AEAD
- **KDF**: 100,000 iterations of SHA-256d (passphrase + 32-byte random salt)
- **Nonce**: 12 bytes, randomly generated per seal operation
- **Integrity**: 16-byte Poly1305 authentication tag

## Detection Systems

### MITM Detector
Tracks per-pool connection fingerprints:
- IP address consistency (alerts on unexpected changes)
- Noise static public key consistency
- TLS certificate hash consistency
- Latency anomaly detection (>3× spike suggests proxy insertion)

### Hashrate Hijack Detector
Monitors share acceptance patterns:
- 5-minute rolling windows, up to 12 windows (1 hour)
- Baseline accept rate established after 50 shares (EMA)
- Alert threshold: >20% drop from baseline
- Difficulty consistency verification

## Audit Checklist

| Check | Tool | Status |
|---|---|---|
| Memory safety | `cargo test` (140 tests) | Pass |
| Dependency CVEs | `cargo audit` | Pass |
| Lint | `cargo clippy -D warnings` | Pass |
| Format | `cargo fmt --check` | Pass |
| Fuzzing | 6 targets (SHA-256d, frame codec, header, address, AEAD, config) | Pass |
| Genesis self-test | Built into binary, runs at startup | Pass |
| Constant-time comparison | `constant_time_eq` for AEAD tags | Pass |

## Reporting Vulnerabilities

Email security@codinglombok.dev with a description and reproduction steps.
We aim to respond within 48 hours and issue a fix within 7 days for
critical vulnerabilities.
