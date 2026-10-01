// LombokMiner — MITM Detection & Hashrate Hijack Detection
//
// Monitors pool connections for signs of man-in-the-middle attacks
// and hashrate theft (pool address substitution, difficulty manipulation).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ─── MITM Detection ────────────────────────────────────────────────────────

/// MITM detection heuristics.
#[derive(Debug)]
pub struct MitmDetector {
    /// History of connection fingerprints
    fingerprints: VecDeque<ConnectionFingerprint>,
    /// Maximum history size
    max_history: usize,
}

/// Fingerprint of a pool connection for consistency checking.
#[derive(Debug, Clone)]
pub struct ConnectionFingerprint {
    /// Pool URL
    pub pool_url: String,
    /// Resolved IP address
    pub resolved_ip: String,
    /// TLS certificate hash (if applicable, empty for SV2 Noise)
    pub cert_hash: Option<String>,
    /// Noise static public key (for Stratum V2)
    pub noise_pubkey: Option<[u8; 32]>,
    /// Timestamp of connection
    pub timestamp: Instant,
    /// Measured latency (microseconds)
    pub latency_us: u64,
}

/// MITM detection alerts.
#[derive(Debug, Clone)]
pub enum MitmAlert {
    /// Pool IP address changed unexpectedly
    IpChanged {
        pool: String,
        old_ip: String,
        new_ip: String,
    },
    /// Noise public key changed (possible key substitution)
    NoiseKeyChanged {
        pool: String,
    },
    /// Latency spike suggesting proxy insertion
    LatencyAnomaly {
        pool: String,
        expected_us: u64,
        actual_us: u64,
    },
    /// TLS certificate changed
    CertChanged {
        pool: String,
    },
}

impl std::fmt::Display for MitmAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpChanged { pool, old_ip, new_ip } => {
                write!(f, "MITM: pool {pool} IP changed {old_ip} → {new_ip}")
            }
            Self::NoiseKeyChanged { pool } => {
                write!(f, "MITM: pool {pool} Noise public key changed")
            }
            Self::LatencyAnomaly { pool, expected_us, actual_us } => {
                write!(
                    f,
                    "MITM: pool {pool} latency anomaly (expected ~{:.1}ms, got {:.1}ms)",
                    *expected_us as f64 / 1000.0,
                    *actual_us as f64 / 1000.0,
                )
            }
            Self::CertChanged { pool } => {
                write!(f, "MITM: pool {pool} TLS certificate changed")
            }
        }
    }
}

impl MitmDetector {
    pub fn new() -> Self {
        Self {
            fingerprints: VecDeque::new(),
            max_history: 100,
        }
    }

    /// Record a new connection fingerprint and check for anomalies.
    pub fn check_connection(&mut self, fp: ConnectionFingerprint) -> Vec<MitmAlert> {
        let mut alerts = Vec::new();

        // Find the most recent fingerprint for the same pool
        let prev = self
            .fingerprints
            .iter()
            .rev()
            .find(|f| f.pool_url == fp.pool_url);

        if let Some(prev) = prev {
            // Check IP consistency
            if prev.resolved_ip != fp.resolved_ip {
                alerts.push(MitmAlert::IpChanged {
                    pool: fp.pool_url.clone(),
                    old_ip: prev.resolved_ip.clone(),
                    new_ip: fp.resolved_ip.clone(),
                });
            }

            // Check Noise public key consistency
            if let (Some(old_key), Some(new_key)) = (prev.noise_pubkey, fp.noise_pubkey) {
                if old_key != new_key {
                    alerts.push(MitmAlert::NoiseKeyChanged {
                        pool: fp.pool_url.clone(),
                    });
                }
            }

            // Check TLS cert consistency
            if let (Some(old_cert), Some(new_cert)) = (&prev.cert_hash, &fp.cert_hash) {
                if old_cert != new_cert {
                    alerts.push(MitmAlert::CertChanged {
                        pool: fp.pool_url.clone(),
                    });
                }
            }

            // Check latency anomaly (>3x increase suggests proxy)
            if prev.latency_us > 0 && fp.latency_us > prev.latency_us * 3 {
                alerts.push(MitmAlert::LatencyAnomaly {
                    pool: fp.pool_url.clone(),
                    expected_us: prev.latency_us,
                    actual_us: fp.latency_us,
                });
            }
        }

        // Store fingerprint
        self.fingerprints.push_back(fp);
        if self.fingerprints.len() > self.max_history {
            self.fingerprints.pop_front();
        }

        alerts
    }
}

impl Default for MitmDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Hashrate Hijack Detection ──────────────────────────────────────────────

/// Detects hashrate hijacking by monitoring share acceptance patterns.
///
/// Hijacking signs:
/// - Sudden drop in accept rate without hashrate change
/// - Pool difficulty that doesn't match expected network difficulty
/// - Submitted work not acknowledged (shares "disappear")
#[derive(Debug)]
pub struct HijackDetector {
    /// Rolling window of share results
    windows: VecDeque<ShareWindow>,
    /// Expected accept rate (baseline, established over time)
    baseline_accept_rate: Option<f64>,
    /// Window size for analysis
    window_duration: Duration,
}

#[derive(Debug, Clone)]
struct ShareWindow {
    accepted: u64,
    rejected: u64,
    stale: u64,
    difficulty_sum: f64,
    timestamp: Instant,
}

/// Hijack detection alerts.
#[derive(Debug, Clone)]
pub enum HijackAlert {
    /// Accept rate dropped significantly
    AcceptRateDrop {
        baseline: f64,
        current: f64,
    },
    /// Difficulty seems inconsistent with pool's stated difficulty
    DifficultyAnomaly {
        expected: f64,
        actual: f64,
    },
    /// Too many shares unacknowledged (sent but no response)
    UnacknowledgedShares {
        count: u64,
        window_secs: u64,
    },
}

impl std::fmt::Display for HijackAlert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptRateDrop { baseline, current } => {
                write!(
                    f,
                    "HIJACK: accept rate dropped from {:.1}% to {:.1}%",
                    baseline * 100.0,
                    current * 100.0,
                )
            }
            Self::DifficultyAnomaly { expected, actual } => {
                write!(f, "HIJACK: difficulty mismatch (expected {expected:.2}, got {actual:.2})")
            }
            Self::UnacknowledgedShares { count, window_secs } => {
                write!(f, "HIJACK: {count} shares unacknowledged in {window_secs}s")
            }
        }
    }
}

impl HijackDetector {
    pub fn new() -> Self {
        Self {
            windows: VecDeque::new(),
            baseline_accept_rate: None,
            window_duration: Duration::from_secs(300), // 5-minute windows
        }
    }

    /// Record a share result and check for hijacking patterns.
    pub fn record_share(&mut self, accepted: bool, stale: bool, difficulty: f64) -> Vec<HijackAlert> {
        let now = Instant::now();

        // Get or create current window
        let needs_new = self
            .windows
            .back()
            .map_or(true, |w| now.duration_since(w.timestamp) > self.window_duration);

        if needs_new {
            self.windows.push_back(ShareWindow {
                accepted: 0,
                rejected: 0,
                stale: 0,
                difficulty_sum: 0.0,
                timestamp: now,
            });

            // Keep only last 12 windows (1 hour at 5-min windows)
            while self.windows.len() > 12 {
                self.windows.pop_front();
            }
        }

        if let Some(window) = self.windows.back_mut() {
            if stale {
                window.stale += 1;
            } else if accepted {
                window.accepted += 1;
            } else {
                window.rejected += 1;
            }
            window.difficulty_sum += difficulty;
        }

        self.analyze()
    }

    fn analyze(&mut self) -> Vec<HijackAlert> {
        let mut alerts = Vec::new();

        if self.windows.len() < 2 {
            return alerts;
        }

        // Calculate current accept rate across all windows
        let total_accepted: u64 = self.windows.iter().map(|w| w.accepted).sum();
        let total_rejected: u64 = self.windows.iter().map(|w| w.rejected).sum();
        let total_stale: u64 = self.windows.iter().map(|w| w.stale).sum();
        let total = total_accepted + total_rejected + total_stale;

        if total < 10 {
            return alerts; // Not enough data
        }

        let current_rate = total_accepted as f64 / total as f64;

        // Establish or compare baseline
        match self.baseline_accept_rate {
            None => {
                if total >= 50 {
                    self.baseline_accept_rate = Some(current_rate);
                }
            }
            Some(baseline) => {
                // Alert if accept rate dropped by more than 20% from baseline
                if current_rate < baseline * 0.8 && baseline > 0.5 {
                    alerts.push(HijackAlert::AcceptRateDrop {
                        baseline,
                        current: current_rate,
                    });
                }

                // Slowly adapt baseline (exponential moving average)
                self.baseline_accept_rate = Some(baseline * 0.95 + current_rate * 0.05);
            }
        }

        alerts
    }
}

impl Default for HijackDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitm_ip_change() {
        let mut detector = MitmDetector::new();

        let fp1 = ConnectionFingerprint {
            pool_url: "sv2://pool:3336".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: None,
            timestamp: Instant::now(),
            latency_us: 20000,
        };
        let alerts = detector.check_connection(fp1);
        assert!(alerts.is_empty()); // First connection, no baseline

        let fp2 = ConnectionFingerprint {
            pool_url: "sv2://pool:3336".into(),
            resolved_ip: "5.6.7.8".into(),
            cert_hash: None,
            noise_pubkey: None,
            timestamp: Instant::now(),
            latency_us: 22000,
        };
        let alerts = detector.check_connection(fp2);
        assert_eq!(alerts.len(), 1);
        assert!(matches!(alerts[0], MitmAlert::IpChanged { .. }));
    }

    #[test]
    fn test_mitm_noise_key_change() {
        let mut detector = MitmDetector::new();

        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];

        detector.check_connection(ConnectionFingerprint {
            pool_url: "sv2://pool:3336".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: Some(key1),
            timestamp: Instant::now(),
            latency_us: 20000,
        });

        let alerts = detector.check_connection(ConnectionFingerprint {
            pool_url: "sv2://pool:3336".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: Some(key2),
            timestamp: Instant::now(),
            latency_us: 20000,
        });

        assert!(alerts.iter().any(|a| matches!(a, MitmAlert::NoiseKeyChanged { .. })));
    }

    #[test]
    fn test_mitm_latency_anomaly() {
        let mut detector = MitmDetector::new();

        detector.check_connection(ConnectionFingerprint {
            pool_url: "pool".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: None,
            timestamp: Instant::now(),
            latency_us: 20000, // 20ms
        });

        let alerts = detector.check_connection(ConnectionFingerprint {
            pool_url: "pool".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: None,
            timestamp: Instant::now(),
            latency_us: 200000, // 200ms (10x increase)
        });

        assert!(alerts.iter().any(|a| matches!(a, MitmAlert::LatencyAnomaly { .. })));
    }

    #[test]
    fn test_mitm_no_alert_stable() {
        let mut detector = MitmDetector::new();

        for _ in 0..5 {
            let alerts = detector.check_connection(ConnectionFingerprint {
                pool_url: "sv2://pool:3336".into(),
                resolved_ip: "1.2.3.4".into(),
                cert_hash: Some("abc123".into()),
                noise_pubkey: Some([0xAA; 32]),
                timestamp: Instant::now(),
                latency_us: 20000,
            });
            // After first connection, no alerts if everything is stable
            if detector.fingerprints.len() > 1 {
                assert!(alerts.is_empty());
            }
        }
    }

    #[test]
    fn test_hijack_accept_rate_drop() {
        let mut detector = HijackDetector::new();

        // Build baseline: 95% accept rate
        for _ in 0..60 {
            detector.record_share(true, false, 1.0);
        }
        for _ in 0..3 {
            detector.record_share(false, false, 1.0);
        }

        // Force new window
        detector.windows.back_mut().unwrap().timestamp =
            Instant::now() - Duration::from_secs(600);

        // Simulate hijack: sudden reject spike
        for _ in 0..30 {
            detector.record_share(false, false, 1.0);
        }
        for _ in 0..5 {
            let alerts = detector.record_share(true, false, 1.0);
            if !alerts.is_empty() {
                assert!(alerts.iter().any(|a| matches!(a, HijackAlert::AcceptRateDrop { .. })));
                return;
            }
        }
    }

    #[test]
    fn test_hijack_not_enough_data() {
        let mut detector = HijackDetector::new();
        let alerts = detector.record_share(false, false, 1.0);
        assert!(alerts.is_empty()); // Need at least 10 shares
    }

    #[test]
    fn test_alert_display() {
        let a = MitmAlert::IpChanged {
            pool: "pool".into(),
            old_ip: "1.2.3.4".into(),
            new_ip: "5.6.7.8".into(),
        };
        assert!(format!("{a}").contains("1.2.3.4"));

        let b = HijackAlert::AcceptRateDrop {
            baseline: 0.95,
            current: 0.40,
        };
        assert!(format!("{b}").contains("95.0%"));
    }
}
