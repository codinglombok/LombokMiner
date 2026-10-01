// LombokMiner — Hash module
// Runtime CPU feature detection selects the fastest SHA-256 implementation.

pub mod sha256;

pub use sha256::{sha256d, sha256d_80, sha256_midstate, sha256_from_midstate};

/// Detected CPU hashing backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashBackend {
    /// x86_64 SHA-NI hardware instructions (Intel Goldmont+, AMD Zen+)
    #[cfg(target_arch = "x86_64")]
    ShaNi,
    /// x86_64 AVX2 SIMD (8-way parallel)
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// aarch64 NEON + SHA2 crypto extensions (Apple Silicon, ARM servers)
    #[cfg(target_arch = "aarch64")]
    NeonSha2,
    /// Pure Rust scalar fallback (works everywhere)
    Scalar,
}

impl std::fmt::Display for HashBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::ShaNi => write!(f, "SHA-NI (hardware)"),
            #[cfg(target_arch = "x86_64")]
            Self::Avx2 => write!(f, "AVX2 (SIMD)"),
            #[cfg(target_arch = "aarch64")]
            Self::NeonSha2 => write!(f, "NEON+SHA2 (hardware)"),
            Self::Scalar => write!(f, "Scalar (fallback)"),
        }
    }
}

/// Detect the best available hashing backend for this CPU.
pub fn detect_backend() -> HashBackend {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sha") && is_x86_feature_detected!("sse4.1") {
            return HashBackend::ShaNi;
        }
        if is_x86_feature_detected!("avx2") {
            return HashBackend::Avx2;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // aarch64 SHA2 is mandatory on ARMv8.0-A and later
        // std::arch::is_aarch64_feature_detected! is nightly-only,
        // so we assume SHA2 is available on all aarch64 targets.
        // The scalar path is correct regardless.
        return HashBackend::NeonSha2;
    }

    HashBackend::Scalar
}

/// Quick self-test: verify SHA-256d against Bitcoin genesis block hash.
/// Call this once at startup to ensure the hashing implementation is correct.
pub fn self_test() -> Result<(), &'static str> {
    let genesis_hex = concat!(
        "01000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        "29ab5f49",
        "ffff001d",
        "1dac2b7c"
    );
    let header = hex::decode(genesis_hex).map_err(|_| "hex decode failed")?;
    let hash = sha256d(&header);

    let mut hash_be = hash;
    hash_be.reverse();

    let expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    if hex::encode(hash_be) != expected {
        return Err("SHA-256d self-test FAILED: genesis block hash mismatch");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_backend() {
        let backend = detect_backend();
        // Should not panic on any platform
        println!("Detected hash backend: {backend}");
    }

    #[test]
    fn test_self_test() {
        self_test().expect("SHA-256d self-test should pass");
    }
}
