// LombokMiner — Mining worker
//
// The worker takes a block header template and iterates nonces to find
// a hash below the target. Uses midstate optimization to avoid redundant
// SHA-256 computation for the first 64 bytes of the header.

use crate::block::header::BlockHeader;
use crate::hash::{sha256_from_midstate, sha256_midstate};
use crate::mining::difficulty::Target;

/// Result of a mining attempt.
#[derive(Debug, Clone)]
pub enum MineResult {
    /// Found a hash that meets the target. Contains the winning nonce and hash.
    Found { nonce: u32, hash: [u8; 32] },
    /// Exhausted the nonce range without finding a valid hash.
    Exhausted,
}

/// A unit of mining work.
#[derive(Debug, Clone)]
pub struct WorkUnit {
    /// The block header template (nonce field will be overwritten).
    pub header: BlockHeader,
    /// The target threshold — hash must be <= this value.
    pub target: Target,
    /// Nonce range to scan: [start, end) exclusive.
    pub nonce_start: u32,
    pub nonce_end: u32,
    /// Job identifier (for correlating results with the correct block template).
    pub job_id: u64,
}

/// Mine a work unit by iterating nonces.
///
/// Uses midstate optimization: the first 64 bytes of the header are hashed once,
/// and only the last 16 bytes (containing timestamp, bits, nonce) are rehashed
/// for each nonce attempt.
///
/// Returns `MineResult::Found` if a valid nonce is found, `MineResult::Exhausted` otherwise.
pub fn mine_range(work: &WorkUnit) -> MineResult {
    let mut header = work.header;

    // Precompute the midstate from the first 64 bytes
    let (first_64, _) = header.split_for_midstate();
    let midstate = sha256_midstate(&first_64);

    // Iterate nonces
    for nonce in work.nonce_start..work.nonce_end {
        header.nonce = nonce;

        // Rebuild only the last 16 bytes: timestamp(4) + bits(4) + nonce(4) + padding
        // Actually, bytes 64..80 = merkle_root[28..32](4) + timestamp(4) + bits(4) + nonce(4)
        let (_, last_16) = header.split_for_midstate();
        let hash = sha256_from_midstate(&midstate, &last_16);

        if work.target.check_hash(&hash) {
            return MineResult::Found { nonce, hash };
        }
    }

    MineResult::Exhausted
}

/// Mining statistics for a completed work unit.
#[derive(Debug, Clone)]
pub struct MineStats {
    /// Number of hashes computed.
    pub hashes: u64,
    /// Time taken in nanoseconds.
    pub duration_ns: u64,
    /// Hashrate in H/s.
    pub hashrate: f64,
}

/// Mine a work unit and return timing statistics.
pub fn mine_range_timed(work: &WorkUnit) -> (MineResult, MineStats) {
    let start = std::time::Instant::now();
    let result = mine_range(work);
    let elapsed = start.elapsed();

    let hashes = (work.nonce_end - work.nonce_start) as u64;
    let duration_ns = elapsed.as_nanos() as u64;
    let hashrate = if duration_ns > 0 {
        hashes as f64 / (duration_ns as f64 / 1_000_000_000.0)
    } else {
        0.0
    };

    let stats = MineStats {
        hashes,
        duration_ns,
        hashrate,
    };

    (result, stats)
}

/// Format hashrate for human display.
pub fn format_hashrate(hps: f64) -> String {
    if hps >= 1e18 {
        format!("{:.2} EH/s", hps / 1e18)
    } else if hps >= 1e15 {
        format!("{:.2} PH/s", hps / 1e15)
    } else if hps >= 1e12 {
        format!("{:.2} TH/s", hps / 1e12)
    } else if hps >= 1e9 {
        format!("{:.2} GH/s", hps / 1e9)
    } else if hps >= 1e6 {
        format!("{:.2} MH/s", hps / 1e6)
    } else if hps >= 1e3 {
        format!("{:.2} KH/s", hps / 1e3)
    } else {
        format!("{:.2} H/s", hps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mine_easy_target() {
        // Set an extremely easy target (almost all bits set)
        let target = Target::from_nbits(0x207fffff); // very high target

        let header = BlockHeader {
            version: 0x20000000,
            prev_block: [0xAB; 32],
            merkle_root: [0xCD; 32],
            timestamp: 1700000000,
            bits: 0x207fffff,
            nonce: 0,
        };

        let work = WorkUnit {
            header,
            target,
            nonce_start: 0,
            nonce_end: 1000,
            job_id: 1,
        };

        match mine_range(&work) {
            MineResult::Found { nonce, hash } => {
                // Verify the found hash actually meets the target
                assert!(target.check_hash(&hash));
                println!("Found at nonce {nonce}: {}", hex::encode(hash));
            }
            MineResult::Exhausted => {
                panic!("Should have found a valid nonce with such an easy target");
            }
        }
    }

    #[test]
    fn test_mine_impossible_target() {
        // Target of zero — impossible to meet
        let target = Target::from_bytes([0u8; 32]);

        let header = BlockHeader::default();

        let work = WorkUnit {
            header,
            target,
            nonce_start: 0,
            nonce_end: 100,
            job_id: 1,
        };

        match mine_range(&work) {
            MineResult::Exhausted => {} // expected
            MineResult::Found { .. } => panic!("Should not find a hash below zero target"),
        }
    }

    #[test]
    fn test_mine_timed() {
        let target = Target::from_nbits(0x207fffff);
        let header = BlockHeader::default();

        let work = WorkUnit {
            header,
            target,
            nonce_start: 0,
            nonce_end: 10_000,
            job_id: 1,
        };

        let (result, stats) = mine_range_timed(&work);
        assert!(matches!(result, MineResult::Found { .. }));
        assert_eq!(stats.hashes, 10_000);
        assert!(stats.hashrate > 0.0);
        println!(
            "Mined {} hashes at {}",
            stats.hashes,
            format_hashrate(stats.hashrate)
        );
    }

    #[test]
    fn test_format_hashrate() {
        assert_eq!(format_hashrate(1_500_000.0), "1.50 MH/s");
        assert_eq!(format_hashrate(188_000_000_000_000.0), "188.00 TH/s");
        assert_eq!(format_hashrate(42.0), "42.00 H/s");
    }
}
