// LombokMiner — Difficulty and target calculation
//
// Bitcoin uses a compact "nBits" encoding for the target threshold.
// A valid block hash must be numerically less than or equal to the target.
//
// nBits format: [exponent: 1 byte] [mantissa: 3 bytes]
//   target = mantissa * 2^(8*(exponent-3))
//
// Difficulty = max_target / current_target
//   where max_target = 0x00000000FFFF00000000...0 (difficulty 1 target)

/// The maximum target (difficulty 1) — "easiest" valid target.
/// This is the target for nBits = 0x1d00ffff (Bitcoin genesis).
const MAX_TARGET_BITS: u32 = 0x1d00ffff;

/// 256-bit unsigned integer for target comparison.
/// Stored as 32 bytes in big-endian (most significant byte first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    bytes: [u8; 32],
}

impl Target {
    /// Create a target from the compact nBits encoding.
    pub fn from_nbits(nbits: u32) -> Self {
        let mut bytes = [0u8; 32];

        let exponent = (nbits >> 24) as usize;
        let mantissa = nbits & 0x007FFFFF;
        let negative = (nbits & 0x00800000) != 0;

        if exponent == 0 || negative {
            return Self { bytes };
        }

        // Place mantissa bytes at the correct position
        // exponent tells us how many bytes from the end the mantissa starts
        if exponent >= 3 {
            let pos = 32 - exponent;
            if pos < 32 {
                bytes[pos] = ((mantissa >> 16) & 0xFF) as u8;
            }
            if pos + 1 < 32 {
                bytes[pos + 1] = ((mantissa >> 8) & 0xFF) as u8;
            }
            if pos + 2 < 32 {
                bytes[pos + 2] = (mantissa & 0xFF) as u8;
            }
        }

        Self { bytes }
    }

    /// Create a target from a 32-byte big-endian hash (e.g., from pool).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Check if a hash (in internal/little-endian byte order) meets this target.
    /// A hash meets the target if hash_value <= target_value (numerically).
    pub fn check_hash(&self, hash_le: &[u8; 32]) -> bool {
        // Convert hash from little-endian (internal) to big-endian for comparison
        let mut hash_be = *hash_le;
        hash_be.reverse();

        // Compare big-endian: first differing byte determines the result
        for i in 0..32 {
            match hash_be[i].cmp(&self.bytes[i]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        true // equal means it meets the target
    }

    /// Get the target as a 32-byte big-endian array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Get the target as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

/// Compute the difficulty from nBits.
/// difficulty = max_target / current_target
pub fn difficulty_from_nbits(nbits: u32) -> f64 {
    let max = nbits_to_f64(MAX_TARGET_BITS);
    let current = nbits_to_f64(nbits);

    if current == 0.0 {
        return f64::MAX;
    }

    max / current
}

/// Convert nBits to an f64 approximation (for difficulty calculation).
fn nbits_to_f64(nbits: u32) -> f64 {
    let exponent = (nbits >> 24) as i32;
    let mantissa = (nbits & 0x007FFFFF) as f64;

    mantissa * 2f64.powi(8 * (exponent - 3))
}

/// Format difficulty for human display.
pub fn format_difficulty(diff: f64) -> String {
    if diff >= 1e15 {
        format!("{:.2}P", diff / 1e15)
    } else if diff >= 1e12 {
        format!("{:.2}T", diff / 1e12)
    } else if diff >= 1e9 {
        format!("{:.2}G", diff / 1e9)
    } else if diff >= 1e6 {
        format!("{:.2}M", diff / 1e6)
    } else if diff >= 1e3 {
        format!("{:.2}K", diff / 1e3)
    } else {
        format!("{:.2}", diff)
    }
}

/// Estimate the probability of finding a block per hash attempt.
/// P = target / 2^256
pub fn block_probability(nbits: u32) -> f64 {
    let target = nbits_to_f64(nbits);
    target / 2f64.powi(256)
}

/// Estimate expected time to find a block at a given hashrate (in seconds).
/// Expected hashes = 2^256 / target
/// Expected time = expected_hashes / hashrate
pub fn expected_block_time(nbits: u32, hashrate_hps: f64) -> f64 {
    if hashrate_hps <= 0.0 {
        return f64::INFINITY;
    }

    let prob = block_probability(nbits);
    if prob <= 0.0 {
        return f64::INFINITY;
    }

    1.0 / (prob * hashrate_hps)
}

/// Format seconds as human-readable duration.
pub fn format_duration(seconds: f64) -> String {
    if seconds.is_infinite() || seconds.is_nan() {
        return "∞".to_string();
    }

    let s = seconds as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s < 86400 * 365 {
        format!("{}d {}h", s / 86400, (s % 86400) / 3600)
    } else {
        format!("{:.1}y", seconds / (86400.0 * 365.25))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_target() {
        let target = Target::from_nbits(0x1d00ffff);
        let hex = target.to_hex();
        // Genesis target: 00000000ffff0000000000000000000000000000000000000000000000000000
        assert!(hex.starts_with("00000000ffff"));
    }

    #[test]
    fn test_difficulty_1() {
        let diff = difficulty_from_nbits(MAX_TARGET_BITS);
        assert!((diff - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_target_check_meets() {
        let target = Target::from_nbits(0x1d00ffff);

        // A hash of all zeros should meet any target
        let zero_hash = [0u8; 32];
        assert!(target.check_hash(&zero_hash));
    }

    #[test]
    fn test_target_check_fails() {
        let target = Target::from_nbits(0x1d00ffff);

        // A hash of all 0xFF should not meet any reasonable target
        let max_hash = [0xFFu8; 32];
        assert!(!target.check_hash(&max_hash));
    }

    #[test]
    fn test_format_difficulty() {
        assert_eq!(format_difficulty(92_670_000_000_000.0), "92.67T");
        assert_eq!(format_difficulty(1_500_000.0), "1.50M");
        assert_eq!(format_difficulty(42.0), "42.00");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30.0), "30s");
        assert_eq!(format_duration(3661.0), "1h 1m");
        assert_eq!(format_duration(90000.0), "1d 1h");
    }

    #[test]
    fn test_expected_block_time() {
        // At difficulty 1, with 2^32 hashes/sec, should be ~1 second
        // (difficulty 1 target = 2^224, so expected hashes = 2^256/2^224 = 2^32)
        let time = expected_block_time(MAX_TARGET_BITS, 2f64.powi(32));
        assert!(time > 0.5 && time < 2.0, "Expected ~1s, got {time}");
    }
}
