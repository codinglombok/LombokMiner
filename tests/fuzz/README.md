# LombokMiner Fuzz Targets

Fuzz testing with cargo-fuzz (requires nightly Rust).

## Setup

```bash
cargo install cargo-fuzz
rustup install nightly
```

## Run

```bash
cd tests/fuzz

# Run a single target
cargo +nightly fuzz run fuzz_sha256d
cargo +nightly fuzz run fuzz_frame_decode
cargo +nightly fuzz run fuzz_block_header
cargo +nightly fuzz run fuzz_address_validate
cargo +nightly fuzz run fuzz_aead
cargo +nightly fuzz run fuzz_config_parse

# Run with timeout (recommended: 1 hour minimum per target)
cargo +nightly fuzz run fuzz_sha256d -- -max_total_time=3600

# Run all targets sequentially
for target in fuzz_sha256d fuzz_frame_decode fuzz_block_header fuzz_address_validate fuzz_aead fuzz_config_parse; do
    cargo +nightly fuzz run "$target" -- -max_total_time=3600
done
```

## Targets

| Target | What it tests |
|---|---|
| fuzz_sha256d | SHA-256d must never panic on arbitrary input |
| fuzz_frame_decode | Stratum V2 frame decoder on arbitrary bytes |
| fuzz_block_header | Block header deserialize + hash on arbitrary 80+ bytes |
| fuzz_address_validate | Bitcoin address validator on arbitrary strings |
| fuzz_aead | ChaCha20-Poly1305 encrypt/decrypt/tamper cycle |
| fuzz_config_parse | TOML config parser on arbitrary strings |

All targets must survive at least 1 hour of fuzzing before each release.
