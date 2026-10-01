// LombokMiner — Metrics Registry
//
// Thread-safe, in-process metrics collection. Designed for minimal overhead
// on the mining hot path — atomic counters, no heap allocation per sample.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Top-level metrics registry for the entire miner.
#[derive(Debug)]
pub struct MetricsRegistry {
    /// Per-device metrics (indexed by device ID)
    pub devices: RwLock<Vec<DeviceMetrics>>,
    /// Per-pool metrics (indexed by pool index)
    pub pools: RwLock<Vec<PoolMetrics>>,
    /// Global miner metrics
    pub miner: MinerMetrics,
    /// Process start time
    pub start_time: Instant,
}

impl MetricsRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            devices: RwLock::new(Vec::new()),
            pools: RwLock::new(Vec::new()),
            miner: MinerMetrics::new(),
            start_time: Instant::now(),
        })
    }

    /// Register a new device and return its index.
    pub fn register_device(&self, name: &str) -> usize {
        let mut devices = self.devices.write().unwrap();
        let idx = devices.len();
        devices.push(DeviceMetrics::new(name));
        idx
    }

    /// Register a new pool and return its index.
    pub fn register_pool(&self, url: &str) -> usize {
        let mut pools = self.pools.write().unwrap();
        let idx = pools.len();
        pools.push(PoolMetrics::new(url));
        idx
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Aggregate hashrate across all devices.
    pub fn total_hashrate(&self) -> f64 {
        let devices = self.devices.read().unwrap();
        devices.iter().map(|d| d.hashrate()).collect::<Vec<_>>().iter().sum()
    }

    /// Snapshot all metrics for export.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let devices = self.devices.read().unwrap();
        let pools = self.pools.read().unwrap();

        MetricsSnapshot {
            uptime_secs: self.uptime_secs(),
            total_hashrate: devices.iter().map(|d| d.hashrate()).sum(),
            blocks_found: self.miner.blocks_found.load(Ordering::Relaxed),
            devices: devices
                .iter()
                .map(|d| DeviceSnapshot {
                    name: d.name.clone(),
                    hashrate: d.hashrate(),
                    temperature: d.temperature(),
                    fan_rpm: d.fan_rpm(),
                    power_watts: d.power_watts(),
                    hashes_total: d.hashes_total.load(Ordering::Relaxed),
                })
                .collect(),
            pools: pools
                .iter()
                .map(|p| PoolSnapshot {
                    url: p.url.clone(),
                    accepted: p.shares_accepted.load(Ordering::Relaxed),
                    rejected: p.shares_rejected.load(Ordering::Relaxed),
                    stale: p.shares_stale.load(Ordering::Relaxed),
                    latency_ms: p.latency_ms(),
                })
                .collect(),
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self {
            devices: RwLock::new(Vec::new()),
            pools: RwLock::new(Vec::new()),
            miner: MinerMetrics::new(),
            start_time: Instant::now(),
        }
    }
}

/// Per-device hardware metrics — all atomics for lock-free updates.
#[derive(Debug)]
pub struct DeviceMetrics {
    pub name: String,
    /// Total hashes computed by this device
    pub hashes_total: AtomicU64,
    /// Current hashrate in H/s (stored as f64 bits)
    hashrate_bits: AtomicU64,
    /// Temperature in °C × 100 (e.g., 6500 = 65.00°C), 0 = unavailable
    temp_centi: AtomicU64,
    /// Fan speed in RPM, 0 = unavailable
    fan: AtomicU64,
    /// Power draw in watts × 100 (e.g., 315000 = 3150.00W), 0 = unavailable
    power_centi: AtomicU64,
}

impl DeviceMetrics {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            hashes_total: AtomicU64::new(0),
            hashrate_bits: AtomicU64::new(0),
            temp_centi: AtomicU64::new(0),
            fan: AtomicU64::new(0),
            power_centi: AtomicU64::new(0),
        }
    }

    /// Add hashes to the total counter.
    #[inline]
    pub fn add_hashes(&self, count: u64) {
        self.hashes_total.fetch_add(count, Ordering::Relaxed);
    }

    /// Update the current hashrate (H/s).
    pub fn set_hashrate(&self, hps: f64) {
        self.hashrate_bits
            .store(hps.to_bits(), Ordering::Relaxed);
    }

    /// Get current hashrate.
    pub fn hashrate(&self) -> f64 {
        f64::from_bits(self.hashrate_bits.load(Ordering::Relaxed))
    }

    /// Update temperature (°C).
    pub fn set_temperature(&self, celsius: f32) {
        self.temp_centi
            .store((celsius * 100.0) as u64, Ordering::Relaxed);
    }

    /// Get temperature (°C), None if not available.
    pub fn temperature(&self) -> Option<f32> {
        let v = self.temp_centi.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v as f32 / 100.0) }
    }

    /// Update fan speed (RPM).
    pub fn set_fan_rpm(&self, rpm: u32) {
        self.fan.store(rpm as u64, Ordering::Relaxed);
    }

    pub fn fan_rpm(&self) -> Option<u32> {
        let v = self.fan.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v as u32) }
    }

    /// Update power draw (watts).
    pub fn set_power_watts(&self, watts: f32) {
        self.power_centi
            .store((watts * 100.0) as u64, Ordering::Relaxed);
    }

    pub fn power_watts(&self) -> Option<f32> {
        let v = self.power_centi.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v as f32 / 100.0) }
    }
}

/// Per-pool network metrics.
#[derive(Debug)]
pub struct PoolMetrics {
    pub url: String,
    pub shares_accepted: AtomicU64,
    pub shares_rejected: AtomicU64,
    pub shares_stale: AtomicU64,
    /// Latency in microseconds, 0 = unknown
    latency_us: AtomicU64,
}

impl PoolMetrics {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            shares_accepted: AtomicU64::new(0),
            shares_rejected: AtomicU64::new(0),
            shares_stale: AtomicU64::new(0),
            latency_us: AtomicU64::new(0),
        }
    }

    pub fn record_accepted(&self) {
        self.shares_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rejected(&self) {
        self.shares_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stale(&self) {
        self.shares_stale.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_latency_us(&self, us: u64) {
        self.latency_us.store(us, Ordering::Relaxed);
    }

    pub fn latency_ms(&self) -> Option<f32> {
        let v = self.latency_us.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v as f32 / 1000.0) }
    }

    /// Acceptance rate (0.0 to 1.0).
    pub fn accept_rate(&self) -> f64 {
        let a = self.shares_accepted.load(Ordering::Relaxed);
        let r = self.shares_rejected.load(Ordering::Relaxed);
        let s = self.shares_stale.load(Ordering::Relaxed);
        let total = a + r + s;
        if total == 0 { 1.0 } else { a as f64 / total as f64 }
    }
}

/// Global miner-level metrics.
#[derive(Debug)]
pub struct MinerMetrics {
    pub blocks_found: AtomicU64,
}

impl MinerMetrics {
    pub fn new() -> Self {
        Self {
            blocks_found: AtomicU64::new(0),
        }
    }
}

impl Default for MinerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Snapshots (for serialization / export) ────────────────────────────────

/// Point-in-time snapshot of all metrics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: f64,
    pub total_hashrate: f64,
    pub blocks_found: u64,
    pub devices: Vec<DeviceSnapshot>,
    pub pools: Vec<PoolSnapshot>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceSnapshot {
    pub name: String,
    pub hashrate: f64,
    pub temperature: Option<f32>,
    pub fan_rpm: Option<u32>,
    pub power_watts: Option<f32>,
    pub hashes_total: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolSnapshot {
    pub url: String,
    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,
    pub latency_ms: Option<f32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_metrics() {
        let dev = DeviceMetrics::new("gpu0");
        dev.add_hashes(1_000_000);
        dev.set_hashrate(1_500_000.0);
        dev.set_temperature(72.5);
        dev.set_fan_rpm(3200);
        dev.set_power_watts(320.0);

        assert_eq!(dev.hashes_total.load(Ordering::Relaxed), 1_000_000);
        assert!((dev.hashrate() - 1_500_000.0).abs() < 0.1);
        assert!((dev.temperature().unwrap() - 72.5).abs() < 0.1);
        assert_eq!(dev.fan_rpm().unwrap(), 3200);
        assert!((dev.power_watts().unwrap() - 320.0).abs() < 0.1);
    }

    #[test]
    fn test_device_unavailable_sensors() {
        let dev = DeviceMetrics::new("cpu0");
        assert!(dev.temperature().is_none());
        assert!(dev.fan_rpm().is_none());
        assert!(dev.power_watts().is_none());
    }

    #[test]
    fn test_pool_metrics() {
        let pool = PoolMetrics::new("sv2://pool:3336");
        pool.record_accepted();
        pool.record_accepted();
        pool.record_rejected();

        assert_eq!(pool.shares_accepted.load(Ordering::Relaxed), 2);
        assert!((pool.accept_rate() - 0.6667).abs() < 0.01);
    }

    #[test]
    fn test_registry_snapshot() {
        let reg = MetricsRegistry::new();
        let d0 = reg.register_device("gpu0");
        let p0 = reg.register_pool("sv2://pool:3336");

        {
            let devices = reg.devices.read().unwrap();
            devices[d0].set_hashrate(1e6);
            devices[d0].add_hashes(5_000_000);
        }
        {
            let pools = reg.pools.read().unwrap();
            pools[p0].record_accepted();
        }

        let snap = reg.snapshot();
        assert_eq!(snap.devices.len(), 1);
        assert_eq!(snap.pools.len(), 1);
        assert!((snap.total_hashrate - 1e6).abs() < 0.1);
        assert_eq!(snap.pools[0].accepted, 1);
    }

    #[test]
    fn test_concurrent_updates() {
        let dev = DeviceMetrics::new("test");

        // Simulate concurrent hash counting
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..10_000 {
                        dev.add_hashes(1);
                    }
                });
            }
        });

        assert_eq!(dev.hashes_total.load(Ordering::Relaxed), 40_000);
    }
}
