// LombokMiner Monitor
//
// Zero-dependency metrics registry, Prometheus text export,
// and configurable alert engine.

pub mod metrics;
pub mod prometheus;
pub mod alerts;

pub use metrics::{MetricsRegistry, DeviceMetrics, PoolMetrics, MinerMetrics};
pub use alerts::{AlertEngine, AlertRule, AlertLevel, Alert};
