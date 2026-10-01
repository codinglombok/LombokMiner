// LombokMiner — Rust Public API
//
// This crate re-exports the entire LombokMiner library as a single dependency.
//
// # Usage
//
// Add to your `Cargo.toml`:
//
// ```toml
// [dependencies]
// lombokminer = { git = "https://github.com/codinglombok/lombokminer", path = "bindings/rust" }
// ```
//
// Then:
//
// ```rust
// use lombokminer::prelude::*;
//
// let hash = sha256d(b"hello");
// let diff = difficulty_from_nbits(0x1d00ffff);
// let valid = validate_address("bc1q...");
// ```

// ─── Core: hashing, blocks, mining ─────────────────────────────────────────

/// SHA-256d hashing, block construction, merkle trees, difficulty, nonce iteration.
pub mod core {
    pub use lombokminer_core::hash;
    pub use lombokminer_core::block;
    pub use lombokminer_core::mining;

    // Direct re-exports for convenience
    pub use lombokminer_core::hash::{sha256d, sha256d_80, sha256_midstate, sha256_from_midstate};
    pub use lombokminer_core::block::{BlockHeader, CoinbaseBuilder, MerkleBranch, merkle_root};
    pub use lombokminer_core::mining::{
        Target, WorkUnit, MineResult, MineStats,
        mine_range, mine_range_timed,
        difficulty_from_nbits, format_difficulty, format_hashrate,
        expected_block_time, format_duration,
    };
    pub use lombokminer_core::{VERSION, NAME, version_string};
}

// ─── Network: Stratum V2/V1, RPC, pool management ─────────────────────────

/// Stratum V2, Stratum V1, getblocktemplate RPC, pool failover.
pub mod net {
    pub use lombokminer_net::stratum_v2;
    pub use lombokminer_net::stratum_v1;
    pub use lombokminer_net::rpc;
    pub use lombokminer_net::pool;

    pub use lombokminer_net::{PoolConfig, PoolProtocol, PoolManager, ConnectionState};
}

// ─── HAL: hardware abstraction ─────────────────────────────────────────────

/// CPU, GPU, and ASIC mining device abstraction.
pub mod hal {
    pub use lombokminer_hal::traits::*;
    pub use lombokminer_hal::cpu;
    pub use lombokminer_hal::gpu;
    pub use lombokminer_hal::asic;

    pub use lombokminer_hal::{CpuMiner, CpuConfig, MiningDevice};
    pub use lombokminer_hal::{DeviceType, DeviceInfo, DeviceSensors, DeviceWorkResult, DeviceError};
    pub use lombokminer_hal::enumerate_devices;
}

// ─── Security: crypto, wallet, detection ───────────────────────────────────

/// ChaCha20-Poly1305, wallet validation, MITM/hijack detection, config vault.
pub mod security {
    pub use lombokminer_security::crypto;
    pub use lombokminer_security::wallet;
    pub use lombokminer_security::detection;
    pub use lombokminer_security::vault;

    pub use lombokminer_security::{
        aead_encrypt, aead_decrypt, AeadError,
        validate_address, AddressType, AddressError, Network, ValidatedAddress,
        MitmDetector, MitmAlert, HijackDetector, HijackAlert, ConnectionFingerprint,
        ConfigVault, VaultError,
    };
}

// ─── Monitor: metrics, prometheus, alerts ──────────────────────────────────

/// Metrics registry, Prometheus export, alert engine.
pub mod monitor {
    pub use lombokminer_monitor::metrics;
    pub use lombokminer_monitor::prometheus;
    pub use lombokminer_monitor::alerts;

    pub use lombokminer_monitor::{
        MetricsRegistry, DeviceMetrics, PoolMetrics, MinerMetrics,
        AlertEngine, AlertRule, AlertLevel, Alert,
    };
}

// ─── Config: TOML parsing and validation ───────────────────────────────────

/// Configuration loading, parsing, and validation.
pub mod config {
    pub use lombokminer_config::*;
}

// ─── Prelude: most commonly used items ─────────────────────────────────────

/// Import everything you need with `use lombokminer::prelude::*`.
pub mod prelude {
    // Hashing
    pub use lombokminer_core::hash::{sha256d, sha256_midstate, sha256_from_midstate};
    pub use lombokminer_core::hash::detect_backend as detect_hash_backend;

    // Blocks
    pub use lombokminer_core::block::{BlockHeader, CoinbaseBuilder, MerkleBranch, merkle_root};

    // Mining
    pub use lombokminer_core::mining::{
        Target, WorkUnit, MineResult, mine_range, mine_range_timed,
        difficulty_from_nbits, format_difficulty, format_hashrate,
    };

    // HAL
    pub use lombokminer_hal::{CpuMiner, CpuConfig, MiningDevice, DeviceType};
    pub use lombokminer_hal::enumerate_devices;

    // Security
    pub use lombokminer_security::{validate_address, AddressType, Network};
    pub use lombokminer_security::{aead_encrypt, aead_decrypt};
    pub use lombokminer_security::{ConfigVault, MitmDetector, HijackDetector};

    // Config
    pub use lombokminer_config::{Config, parse_config, load_or_default};
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_prelude_sha256d() {
        let hash = sha256d(b"hello");
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_prelude_block_header() {
        let header = BlockHeader::default();
        let hash = header.hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_prelude_difficulty() {
        let diff = difficulty_from_nbits(0x1d00ffff);
        assert!((diff - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_prelude_validate_address() {
        let result = validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().address_type, AddressType::P2wpkh);
    }

    #[test]
    fn test_prelude_cpu_miner() {
        let miner = CpuMiner::new(CpuConfig { threads: 1, core_affinity: false });
        let target = Target::from_nbits(0x207fffff);
        let header = BlockHeader::default();

        let result = miner.submit_work(&header, &target, 0, 10_000).unwrap();
        assert!(matches!(result.result, MineResult::Found { .. }));
    }

    #[test]
    fn test_prelude_aead() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let (ct, tag) = aead_encrypt(&key, &nonce, b"", b"secret");
        let pt = aead_decrypt(&key, &nonce, b"", &ct, &tag).unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn test_prelude_config() {
        let cfg = parse_config("").unwrap();
        assert_eq!(cfg.general.mode, "pool");
    }

    #[test]
    fn test_prelude_detect_backend() {
        let backend = detect_hash_backend();
        println!("Hash backend: {backend}");
    }

    #[test]
    fn test_prelude_enumerate_devices() {
        let devs = enumerate_devices();
        assert!(!devs.is_empty());
        assert_eq!(devs[0].device_type, DeviceType::Cpu);
    }

    #[test]
    fn test_prelude_format() {
        assert!(format_hashrate(1_500_000.0).contains("MH/s"));
        assert!(format_difficulty(92_670_000_000_000.0).contains("T"));
    }

    #[test]
    fn test_prelude_config_vault() {
        let vault = ConfigVault::seal("pass", "data");
        let decrypted = vault.unseal("pass").unwrap();
        assert_eq!(decrypted, "data");
    }
}
