// LombokMiner — Pool Manager
//
// Manages connections to one or more mining pools with automatic failover.
// Tracks share statistics, connection health, and handles reconnection.

use std::time::{Duration, Instant};

/// Protocol type for a pool connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolProtocol {
    StratumV2,
    StratumV1,
}

impl std::fmt::Display for PoolProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StratumV2 => write!(f, "Stratum V2"),
            Self::StratumV1 => write!(f, "Stratum V1"),
        }
    }
}

/// Pool connection configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Pool URL (e.g., "sv2://pool.example.com:3336" or "stratum+tcp://pool:3333")
    pub url: String,
    /// Protocol to use
    pub protocol: PoolProtocol,
    /// Worker name / username
    pub user: String,
    /// Password (usually "x" for most pools)
    pub password: String,
    /// Priority (lower = higher priority, 0 = primary)
    pub priority: u32,
    /// Enable Stratum V2 Job Declaration (miner builds own block template)
    pub job_declaration: bool,
}

impl PoolConfig {
    /// Parse protocol from URL scheme.
    pub fn from_url(url: &str, user: &str, password: &str) -> Self {
        let protocol = if url.starts_with("sv2://") {
            PoolProtocol::StratumV2
        } else {
            PoolProtocol::StratumV1
        };

        Self {
            url: url.to_string(),
            protocol,
            user: user.to_string(),
            password: password.to_string(),
            priority: 0,
            job_declaration: false,
        }
    }

    /// Extract host and port from the URL.
    pub fn host_port(&self) -> (&str, u16) {
        let stripped = self.url
            .trim_start_matches("sv2://")
            .trim_start_matches("stratum+tcp://")
            .trim_start_matches("stratum+ssl://")
            .trim_start_matches("tcp://");

        if let Some((host, port_str)) = stripped.rsplit_once(':') {
            let port = port_str.parse().unwrap_or(3333);
            (host, port)
        } else {
            (stripped, 3333)
        }
    }
}

/// Connection state for a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not yet connected
    Disconnected,
    /// TCP connection established, performing handshake
    Connecting,
    /// Handshake complete, mining channel open
    Connected,
    /// Connection lost, will attempt reconnect
    Reconnecting,
    /// Permanently failed (e.g., auth error)
    Failed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "DISCONNECTED"),
            Self::Connecting => write!(f, "CONNECTING"),
            Self::Connected => write!(f, "CONNECTED"),
            Self::Reconnecting => write!(f, "RECONNECTING"),
            Self::Failed => write!(f, "FAILED"),
        }
    }
}

/// Share submission statistics for a pool.
#[derive(Debug, Clone, Default)]
pub struct ShareStats {
    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,
    /// Last share submission time
    pub last_share_time: Option<Instant>,
    /// Current pool-assigned difficulty
    pub difficulty: f64,
}

impl ShareStats {
    /// Acceptance rate (0.0 to 1.0).
    pub fn accept_rate(&self) -> f64 {
        let total = self.accepted + self.rejected + self.stale;
        if total == 0 {
            return 1.0;
        }
        self.accepted as f64 / total as f64
    }

    /// Stale rate (0.0 to 1.0).
    pub fn stale_rate(&self) -> f64 {
        let total = self.accepted + self.rejected + self.stale;
        if total == 0 {
            return 0.0;
        }
        self.stale as f64 / total as f64
    }

    /// Time since last share.
    pub fn time_since_last_share(&self) -> Option<Duration> {
        self.last_share_time.map(|t| t.elapsed())
    }
}

/// State of a single pool connection.
#[derive(Debug)]
pub struct PoolState {
    pub config: PoolConfig,
    pub state: ConnectionState,
    pub shares: ShareStats,
    /// When the connection was established
    pub connected_since: Option<Instant>,
    /// Number of reconnect attempts since last successful connection
    pub reconnect_attempts: u32,
    /// Network latency to this pool (ms)
    pub latency_ms: Option<u32>,
    /// Channel ID assigned by pool (SV2)
    pub channel_id: Option<u32>,
    /// Extranonce1 assigned by pool
    pub extranonce1: Option<Vec<u8>>,
    /// Extranonce2 size
    pub extranonce2_size: usize,
}

impl PoolState {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            state: ConnectionState::Disconnected,
            shares: ShareStats::default(),
            connected_since: None,
            reconnect_attempts: 0,
            latency_ms: None,
            channel_id: None,
            extranonce1: None,
            extranonce2_size: 4,
        }
    }

    /// Uptime since connection.
    pub fn uptime(&self) -> Option<Duration> {
        self.connected_since.map(|t| t.elapsed())
    }

    /// Record a share acceptance.
    pub fn record_accepted(&mut self) {
        self.shares.accepted += 1;
        self.shares.last_share_time = Some(Instant::now());
    }

    /// Record a share rejection.
    pub fn record_rejected(&mut self) {
        self.shares.rejected += 1;
    }

    /// Record a stale share.
    pub fn record_stale(&mut self) {
        self.shares.stale += 1;
    }

    /// Mark as connected.
    pub fn mark_connected(&mut self) {
        self.state = ConnectionState::Connected;
        self.connected_since = Some(Instant::now());
        self.reconnect_attempts = 0;
    }

    /// Mark as disconnected and schedule reconnect.
    pub fn mark_disconnected(&mut self) {
        self.state = ConnectionState::Reconnecting;
        self.connected_since = None;
        self.reconnect_attempts += 1;
    }
}

/// Pool manager — manages multiple pool connections with failover.
#[derive(Debug)]
pub struct PoolManager {
    pub pools: Vec<PoolState>,
    /// Index of the currently active pool
    pub active_pool: usize,
    /// Maximum reconnect attempts before moving to next pool
    pub max_reconnect_attempts: u32,
    /// Reconnect delay base (exponential backoff)
    pub reconnect_delay_base: Duration,
    /// Maximum reconnect delay
    pub reconnect_delay_max: Duration,
    /// Whether to sticky-reconnect to the primary pool when it comes back
    pub sticky_primary: bool,
}

impl PoolManager {
    /// Create a new pool manager from a list of pool configs.
    pub fn new(configs: Vec<PoolConfig>) -> Self {
        assert!(!configs.is_empty(), "at least one pool is required");

        let mut pools: Vec<PoolState> = configs.into_iter().map(PoolState::new).collect();
        // Sort by priority (lower = higher priority)
        pools.sort_by_key(|p| p.config.priority);

        Self {
            pools,
            active_pool: 0,
            max_reconnect_attempts: 5,
            reconnect_delay_base: Duration::from_secs(1),
            reconnect_delay_max: Duration::from_secs(60),
            sticky_primary: true,
        }
    }

    /// Get the currently active pool state.
    pub fn active(&self) -> &PoolState {
        &self.pools[self.active_pool]
    }

    /// Get the currently active pool state (mutable).
    pub fn active_mut(&mut self) -> &mut PoolState {
        &mut self.pools[self.active_pool]
    }

    /// Perform failover to the next available pool.
    /// Returns true if a new pool was selected, false if no pools are available.
    pub fn failover(&mut self) -> bool {
        let start = self.active_pool;
        let count = self.pools.len();

        for offset in 1..count {
            let idx = (start + offset) % count;
            if self.pools[idx].state != ConnectionState::Failed {
                tracing::warn!(
                    "Failover: {} → {}",
                    self.pools[start].config.url,
                    self.pools[idx].config.url,
                );
                self.active_pool = idx;
                self.pools[idx].state = ConnectionState::Connecting;
                return true;
            }
        }

        tracing::error!("No available pools for failover");
        false
    }

    /// Check if we should fail back to the primary pool.
    pub fn should_failback(&self) -> bool {
        self.sticky_primary
            && self.active_pool != 0
            && self.pools[0].state != ConnectionState::Failed
    }

    /// Fail back to the primary pool.
    pub fn failback(&mut self) {
        if self.active_pool != 0 {
            tracing::info!(
                "Failback: {} → {} (primary)",
                self.pools[self.active_pool].config.url,
                self.pools[0].config.url,
            );
            self.active_pool = 0;
            self.pools[0].state = ConnectionState::Connecting;
            self.pools[0].reconnect_attempts = 0;
        }
    }

    /// Calculate reconnect delay with exponential backoff.
    pub fn reconnect_delay(&self, attempts: u32) -> Duration {
        let delay = self.reconnect_delay_base * 2u32.pow(attempts.min(6));
        delay.min(self.reconnect_delay_max)
    }

    /// Get a summary of all pool states.
    pub fn summary(&self) -> Vec<PoolSummary> {
        self.pools
            .iter()
            .enumerate()
            .map(|(i, p)| PoolSummary {
                index: i,
                url: p.config.url.clone(),
                protocol: p.config.protocol,
                state: p.state,
                is_active: i == self.active_pool,
                accepted: p.shares.accepted,
                rejected: p.shares.rejected,
                stale: p.shares.stale,
                accept_rate: p.shares.accept_rate(),
                latency_ms: p.latency_ms,
            })
            .collect()
    }
}

/// Summary of a pool's state (for display/monitoring).
#[derive(Debug, Clone)]
pub struct PoolSummary {
    pub index: usize,
    pub url: String,
    pub protocol: PoolProtocol,
    pub state: ConnectionState,
    pub is_active: bool,
    pub accepted: u64,
    pub rejected: u64,
    pub stale: u64,
    pub accept_rate: f64,
    pub latency_ms: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_from_url() {
        let cfg = PoolConfig::from_url("sv2://braiins.com:3336", "worker1", "x");
        assert_eq!(cfg.protocol, PoolProtocol::StratumV2);
        assert_eq!(cfg.host_port(), ("braiins.com", 3336));

        let cfg2 = PoolConfig::from_url("stratum+tcp://pool.example.com:3333", "w", "x");
        assert_eq!(cfg2.protocol, PoolProtocol::StratumV1);
        assert_eq!(cfg2.host_port(), ("pool.example.com", 3333));
    }

    #[test]
    fn test_pool_manager_failover() {
        let pools = vec![
            PoolConfig::from_url("sv2://primary:3336", "w", "x"),
            PoolConfig::from_url("stratum+tcp://backup:3333", "w", "x"),
        ];
        let mut mgr = PoolManager::new(pools);
        assert_eq!(mgr.active_pool, 0);

        // Failover to backup
        assert!(mgr.failover());
        assert_eq!(mgr.active_pool, 1);

        // Failover wraps around
        assert!(mgr.failover());
        assert_eq!(mgr.active_pool, 0);
    }

    #[test]
    fn test_pool_manager_failback() {
        let pools = vec![
            PoolConfig::from_url("sv2://primary:3336", "w", "x"),
            PoolConfig::from_url("stratum+tcp://backup:3333", "w", "x"),
        ];
        let mut mgr = PoolManager::new(pools);

        mgr.failover(); // go to backup
        assert_eq!(mgr.active_pool, 1);
        assert!(mgr.should_failback());

        mgr.failback();
        assert_eq!(mgr.active_pool, 0);
    }

    #[test]
    fn test_reconnect_backoff() {
        let pools = vec![PoolConfig::from_url("sv2://p:3336", "w", "x")];
        let mgr = PoolManager::new(pools);

        assert_eq!(mgr.reconnect_delay(0), Duration::from_secs(1));
        assert_eq!(mgr.reconnect_delay(1), Duration::from_secs(2));
        assert_eq!(mgr.reconnect_delay(2), Duration::from_secs(4));
        assert_eq!(mgr.reconnect_delay(3), Duration::from_secs(8));
        // Capped at max
        assert_eq!(mgr.reconnect_delay(10), Duration::from_secs(60));
    }

    #[test]
    fn test_share_stats() {
        let mut pool = PoolState::new(PoolConfig::from_url("sv2://p:3336", "w", "x"));
        pool.record_accepted();
        pool.record_accepted();
        pool.record_rejected();

        assert_eq!(pool.shares.accepted, 2);
        assert_eq!(pool.shares.rejected, 1);
        assert!((pool.shares.accept_rate() - 0.6667).abs() < 0.01);
        assert!(pool.shares.time_since_last_share().is_some());
    }

    #[test]
    fn test_pool_summary() {
        let pools = vec![
            PoolConfig::from_url("sv2://primary:3336", "w", "x"),
            PoolConfig::from_url("stratum+tcp://backup:3333", "w", "x"),
        ];
        let mgr = PoolManager::new(pools);
        let summary = mgr.summary();

        assert_eq!(summary.len(), 2);
        assert!(summary[0].is_active);
        assert!(!summary[1].is_active);
    }
}
