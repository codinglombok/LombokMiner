// LombokMiner — CPU Mining Backend
//
// Multi-threaded CPU miner that splits nonce ranges across OS threads.
// Uses the midstate optimization from lombokminer-core for maximum throughput.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use lombokminer_core::block::BlockHeader;
use lombokminer_core::hash;
use lombokminer_core::mining::{MineResult, Target};

use crate::traits::{
    DeviceError, DeviceInfo, DeviceSensors, DeviceType, DeviceWorkResult, MiningDevice,
};

/// CPU miner configuration.
#[derive(Debug, Clone)]
pub struct CpuConfig {
    /// Number of mining threads (0 = auto-detect)
    pub threads: usize,
    /// Pin threads to specific CPU cores
    pub core_affinity: bool,
}

impl Default for CpuConfig {
    fn default() -> Self {
        Self {
            threads: 0,
            core_affinity: false,
        }
    }
}

/// Multi-threaded CPU mining device.
pub struct CpuMiner {
    info: DeviceInfo,
    config: CpuConfig,
    threads: usize,
    /// Current hashrate (updated after each work unit)
    hashrate: AtomicU64,
    /// Total hashes computed
    total_hashes: AtomicU64,
    /// Flag to stop mining (set by shutdown)
    stop: Arc<AtomicBool>,
}

impl CpuMiner {
    /// Create a new CPU miner.
    pub fn new(config: CpuConfig) -> Self {
        let threads = if config.threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            config.threads
        };

        let info = DeviceInfo {
            name: format!("CPU ({threads} threads)"),
            device_type: DeviceType::Cpu,
            id: "cpu0".into(),
            vendor: cpu_vendor(),
            max_hashrate: None,
        };

        Self {
            info,
            config,
            threads,
            hashrate: AtomicU64::new(0),
            total_hashes: AtomicU64::new(0),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the number of mining threads.
    pub fn thread_count(&self) -> usize {
        self.threads
    }
}

impl MiningDevice for CpuMiner {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn sensors(&self) -> DeviceSensors {
        // CPU temperature reading requires platform-specific APIs.
        // On Linux: /sys/class/thermal/thermal_zone*/temp
        // For now, return empty — will be implemented per-platform.
        DeviceSensors::default()
    }

    fn hashrate(&self) -> f64 {
        f64::from_bits(self.hashrate.load(Ordering::Relaxed))
    }

    fn submit_work(
        &self,
        header: &BlockHeader,
        target: &Target,
        nonce_start: u32,
        nonce_end: u32,
    ) -> Result<DeviceWorkResult, DeviceError> {
        if self.stop.load(Ordering::Relaxed) {
            return Err(DeviceError::WorkFailed("miner stopped".into()));
        }

        let total_nonces = nonce_end.saturating_sub(nonce_start) as u64;
        if total_nonces == 0 {
            return Ok(DeviceWorkResult {
                result: MineResult::Exhausted,
                hashes: 0,
                duration_ns: 0,
                hashrate: 0.0,
            });
        }

        let start_time = Instant::now();
        let found = Arc::new(AtomicBool::new(false));
        let found_nonce = Arc::new(AtomicU64::new(0));
        let found_hash = Arc::new(std::sync::Mutex::new([0u8; 32]));

        // Precompute midstate (shared across all threads)
        let (first_64, _) = header.split_for_midstate();
        let midstate = hash::sha256_midstate(&first_64);

        // Split nonce range across threads
        let chunk_size = (total_nonces + self.threads as u64 - 1) / self.threads as u64;

        std::thread::scope(|scope| {
            for thread_idx in 0..self.threads {
                let chunk_start = nonce_start as u64 + thread_idx as u64 * chunk_size;
                let chunk_end = (chunk_start + chunk_size).min(nonce_end as u64);

                if chunk_start >= nonce_end as u64 {
                    break;
                }

                let found = Arc::clone(&found);
                let found_nonce = Arc::clone(&found_nonce);
                let found_hash = Arc::clone(&found_hash);
                let stop = Arc::clone(&self.stop);
                let header = *header;
                let target = *target;
                let midstate = midstate;

                scope.spawn(move || {
                    mine_thread(
                        &header,
                        &target,
                        &midstate,
                        chunk_start as u32,
                        chunk_end as u32,
                        &found,
                        &found_nonce,
                        &found_hash,
                        &stop,
                    );
                });
            }
        });

        let elapsed = start_time.elapsed();
        let duration_ns = elapsed.as_nanos() as u64;
        let hashrate = if duration_ns > 0 {
            total_nonces as f64 / (duration_ns as f64 / 1e9)
        } else {
            0.0
        };

        // Update stats
        self.hashrate.store(hashrate.to_bits(), Ordering::Relaxed);
        self.total_hashes.fetch_add(total_nonces, Ordering::Relaxed);

        let result = if found.load(Ordering::Relaxed) {
            let nonce = found_nonce.load(Ordering::Relaxed) as u32;
            let hash = *found_hash.lock().unwrap();
            MineResult::Found { nonce, hash }
        } else {
            MineResult::Exhausted
        };

        Ok(DeviceWorkResult {
            result,
            hashes: total_nonces,
            duration_ns,
            hashrate,
        })
    }

    fn shutdown(&self) -> Result<(), DeviceError> {
        self.stop.store(true, Ordering::Relaxed);
        Ok(())
    }
}

/// Single-thread mining worker function.
fn mine_thread(
    header: &BlockHeader,
    target: &Target,
    midstate: &[u32; 8],
    nonce_start: u32,
    nonce_end: u32,
    found: &AtomicBool,
    found_nonce: &AtomicU64,
    found_hash: &std::sync::Mutex<[u8; 32]>,
    stop: &AtomicBool,
) {
    let mut h = *header;

    for nonce in nonce_start..nonce_end {
        // Early exit: another thread found a solution or stop requested
        if found.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
            return;
        }

        h.nonce = nonce;
        let (_, last_16) = h.split_for_midstate();
        let hash = hash::sha256_from_midstate(midstate, &last_16);

        if target.check_hash(&hash) {
            // Race: first thread to set found wins
            if !found.swap(true, Ordering::SeqCst) {
                found_nonce.store(nonce as u64, Ordering::SeqCst);
                *found_hash.lock().unwrap() = hash;
            }
            return;
        }
    }
}

fn cpu_vendor() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("sha") {
            return "x86_64 (SHA-NI)".into();
        }
        if is_x86_feature_detected!("avx2") {
            return "x86_64 (AVX2)".into();
        }
        return "x86_64".into();
    }
    #[cfg(target_arch = "aarch64")]
    { return "aarch64 (NEON)".into(); }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { return std::env::consts::ARCH.into(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_miner_info() {
        let miner = CpuMiner::new(CpuConfig { threads: 2, core_affinity: false });
        let info = miner.info();
        assert_eq!(info.device_type, DeviceType::Cpu);
        assert!(info.name.contains("2 threads"));
        assert_eq!(miner.thread_count(), 2);
    }

    #[test]
    fn test_cpu_miner_easy_target() {
        let miner = CpuMiner::new(CpuConfig { threads: 2, core_affinity: false });
        let target = Target::from_nbits(0x207fffff);
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: [0xAB; 32],
            merkle_root: [0xCD; 32],
            timestamp: 1700000000,
            bits: 0x207fffff,
            nonce: 0,
        };

        let result = miner.submit_work(&header, &target, 0, 100_000).unwrap();
        match result.result {
            MineResult::Found { nonce, hash } => {
                assert!(target.check_hash(&hash));
                println!("CPU miner found nonce {nonce} with 2 threads");
            }
            MineResult::Exhausted => panic!("Should find with easy target"),
        }
        assert!(result.hashrate > 0.0);
        assert!(result.hashes > 0);
    }

    #[test]
    fn test_cpu_miner_multithread_consistency() {
        // Same work unit should find the SAME nonce regardless of thread count
        let target = Target::from_nbits(0x207fffff);
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: [0x11; 32],
            merkle_root: [0x22; 32],
            timestamp: 1700000000,
            bits: 0x207fffff,
            nonce: 0,
        };

        let miner1 = CpuMiner::new(CpuConfig { threads: 1, core_affinity: false });
        let r1 = miner1.submit_work(&header, &target, 0, 100_000).unwrap();

        // Multi-thread result should be valid (nonce may differ due to race,
        // but hash must meet target)
        let miner4 = CpuMiner::new(CpuConfig { threads: 4, core_affinity: false });
        let r4 = miner4.submit_work(&header, &target, 0, 100_000).unwrap();

        match (&r1.result, &r4.result) {
            (MineResult::Found { hash: h1, .. }, MineResult::Found { hash: h4, .. }) => {
                assert!(target.check_hash(h1));
                assert!(target.check_hash(h4));
            }
            _ => panic!("Both should find a valid nonce"),
        }
    }

    #[test]
    fn test_cpu_miner_shutdown() {
        let miner = CpuMiner::new(CpuConfig::default());
        miner.shutdown().unwrap();

        let target = Target::from_nbits(0x207fffff);
        let header = BlockHeader::default();
        let result = miner.submit_work(&header, &target, 0, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_cpu_miner_empty_range() {
        let miner = CpuMiner::new(CpuConfig::default());
        let target = Target::from_nbits(0x207fffff);
        let header = BlockHeader::default();
        let result = miner.submit_work(&header, &target, 100, 100).unwrap();
        assert!(matches!(result.result, MineResult::Exhausted));
        assert_eq!(result.hashes, 0);
    }

    #[test]
    fn test_cpu_miner_hashrate_update() {
        let miner = CpuMiner::new(CpuConfig { threads: 1, core_affinity: false });
        assert_eq!(miner.hashrate(), 0.0);

        let target = Target::from_nbits(0x01003456); // impossibly hard
        let header = BlockHeader::default();
        let result = miner.submit_work(&header, &target, 0, 1_000_000).unwrap();

        assert!(miner.hashrate() > 0.0);
        assert!((miner.hashrate() - result.hashrate).abs() < 0.1);
    }
}
