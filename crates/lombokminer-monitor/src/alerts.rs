// LombokMiner — Alert Engine
//
// Evaluates configurable rules against current metrics and fires alerts.
// Features: threshold-based checks, cooldown periods, severity levels,
// and hysteresis (alert clears only after value returns well past threshold).

use crate::metrics::MetricsSnapshot;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Alert severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Critical => write!(f, "CRIT"),
        }
    }
}

/// A fired alert.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub level: AlertLevel,
    pub rule_name: String,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
    #[serde(skip)]
    pub fired_at: Instant,
}

impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {} (value={:.2}, threshold={:.2})",
            self.level, self.rule_name, self.message, self.value, self.threshold)
    }
}

/// What metric to check.
#[derive(Debug, Clone)]
pub enum AlertMetric {
    /// Total hashrate (H/s)
    TotalHashrate,
    /// Per-device temperature (°C) — fires if ANY device exceeds threshold
    DeviceTemperature,
    /// Stale share ratio (0.0 to 1.0) for ANY pool
    StaleRatio,
    /// Accept rate (0.0 to 1.0) for ANY pool — fires if BELOW threshold
    AcceptRate,
    /// Pool latency (ms)
    PoolLatency,
}

/// Comparison direction.
#[derive(Debug, Clone, Copy)]
pub enum AlertCondition {
    /// Fire when value > threshold (e.g., temperature)
    Above,
    /// Fire when value < threshold (e.g., hashrate drop)
    Below,
}

/// A configurable alert rule.
#[derive(Debug, Clone)]
pub struct AlertRule {
    pub name: String,
    pub metric: AlertMetric,
    pub condition: AlertCondition,
    pub threshold: f64,
    pub level: AlertLevel,
    /// Minimum time between repeated firings of this rule
    pub cooldown: Duration,
    /// Human-readable description template
    pub message_template: String,
}

/// Alert engine state.
#[derive(Debug)]
pub struct AlertEngine {
    rules: Vec<AlertRule>,
    /// Last fire time per rule name (for cooldown)
    last_fired: HashMap<String, Instant>,
    /// Currently active (not yet cleared) alerts
    active: Vec<Alert>,
}

impl AlertEngine {
    /// Create with default mining alert rules.
    pub fn with_defaults() -> Self {
        let rules = vec![
            AlertRule {
                name: "hashrate_drop".into(),
                metric: AlertMetric::TotalHashrate,
                condition: AlertCondition::Below,
                threshold: 0.0, // will be set dynamically based on baseline
                level: AlertLevel::Warning,
                cooldown: Duration::from_secs(300),
                message_template: "Hashrate dropped below threshold".into(),
            },
            AlertRule {
                name: "temp_warning".into(),
                metric: AlertMetric::DeviceTemperature,
                condition: AlertCondition::Above,
                threshold: 80.0,
                level: AlertLevel::Warning,
                cooldown: Duration::from_secs(60),
                message_template: "Device temperature exceeds 80°C".into(),
            },
            AlertRule {
                name: "temp_critical".into(),
                metric: AlertMetric::DeviceTemperature,
                condition: AlertCondition::Above,
                threshold: 90.0,
                level: AlertLevel::Critical,
                cooldown: Duration::from_secs(30),
                message_template: "Device temperature exceeds 90°C — throttle recommended".into(),
            },
            AlertRule {
                name: "stale_shares".into(),
                metric: AlertMetric::StaleRatio,
                condition: AlertCondition::Above,
                threshold: 0.05,
                level: AlertLevel::Warning,
                cooldown: Duration::from_secs(300),
                message_template: "Stale share ratio exceeds 5%".into(),
            },
            AlertRule {
                name: "pool_latency".into(),
                metric: AlertMetric::PoolLatency,
                condition: AlertCondition::Above,
                threshold: 200.0,
                level: AlertLevel::Warning,
                cooldown: Duration::from_secs(120),
                message_template: "Pool latency exceeds 200ms".into(),
            },
        ];

        Self {
            rules,
            last_fired: HashMap::new(),
            active: Vec::new(),
        }
    }

    /// Create with custom rules.
    pub fn new(rules: Vec<AlertRule>) -> Self {
        Self {
            rules,
            last_fired: HashMap::new(),
            active: Vec::new(),
        }
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: AlertRule) {
        self.rules.push(rule);
    }

    /// Evaluate all rules against current metrics. Returns newly fired alerts.
    pub fn evaluate(&mut self, snap: &MetricsSnapshot) -> Vec<Alert> {
        let now = Instant::now();
        let mut new_alerts = Vec::new();

        for rule in &self.rules {
            // Check cooldown
            if let Some(last) = self.last_fired.get(&rule.name) {
                if now.duration_since(*last) < rule.cooldown {
                    continue;
                }
            }

            let values = extract_values(&rule.metric, snap);

            for (value, context) in values {
                let triggered = match rule.condition {
                    AlertCondition::Above => value > rule.threshold,
                    AlertCondition::Below => value < rule.threshold && rule.threshold > 0.0,
                };

                if triggered {
                    let message = if context.is_empty() {
                        rule.message_template.clone()
                    } else {
                        format!("{} ({})", rule.message_template, context)
                    };

                    let alert = Alert {
                        level: rule.level,
                        rule_name: rule.name.clone(),
                        message,
                        value,
                        threshold: rule.threshold,
                        fired_at: now,
                    };

                    tracing::warn!("{alert}");
                    new_alerts.push(alert.clone());
                    self.last_fired.insert(rule.name.clone(), now);
                    self.active.push(alert);
                    break; // One fire per rule per evaluation
                }
            }
        }

        // Clean up cleared alerts (value returned to safe range)
        self.active.retain(|a| {
            let values = extract_values(
                &self.rules.iter().find(|r| r.name == a.rule_name)
                    .map(|r| r.metric.clone())
                    .unwrap_or(AlertMetric::TotalHashrate),
                snap,
            );
            // Keep alert if any value still exceeds threshold
            values.iter().any(|(v, _)| match a.level {
                _ => {
                    let rule = self.rules.iter().find(|r| r.name == a.rule_name);
                    rule.map_or(false, |r| match r.condition {
                        AlertCondition::Above => *v > r.threshold * 0.95, // hysteresis
                        AlertCondition::Below => *v < r.threshold * 1.05,
                    })
                }
            })
        });

        new_alerts
    }

    /// Get currently active alerts.
    pub fn active_alerts(&self) -> &[Alert] {
        &self.active
    }

    /// Number of active alerts by severity.
    pub fn count_by_level(&self, level: AlertLevel) -> usize {
        self.active.iter().filter(|a| a.level == level).count()
    }
}

/// Extract metric values from a snapshot for a given AlertMetric.
/// Returns (value, context_string) pairs.
fn extract_values(metric: &AlertMetric, snap: &MetricsSnapshot) -> Vec<(f64, String)> {
    match metric {
        AlertMetric::TotalHashrate => {
            vec![(snap.total_hashrate, String::new())]
        }
        AlertMetric::DeviceTemperature => {
            snap.devices
                .iter()
                .filter_map(|d| d.temperature.map(|t| (t as f64, d.name.clone())))
                .collect()
        }
        AlertMetric::StaleRatio => {
            snap.pools
                .iter()
                .map(|p| {
                    let total = p.accepted + p.rejected + p.stale;
                    let ratio = if total == 0 { 0.0 } else { p.stale as f64 / total as f64 };
                    (ratio, p.url.clone())
                })
                .collect()
        }
        AlertMetric::AcceptRate => {
            snap.pools
                .iter()
                .map(|p| {
                    let total = p.accepted + p.rejected + p.stale;
                    let rate = if total == 0 { 1.0 } else { p.accepted as f64 / total as f64 };
                    (rate, p.url.clone())
                })
                .collect()
        }
        AlertMetric::PoolLatency => {
            snap.pools
                .iter()
                .filter_map(|p| p.latency_ms.map(|ms| (ms as f64, p.url.clone())))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::*;

    fn make_snap(temp: Option<f32>, stale_ratio: f64) -> MetricsSnapshot {
        let total = 1000u64;
        let stale = (total as f64 * stale_ratio) as u64;
        MetricsSnapshot {
            uptime_secs: 100.0,
            total_hashrate: 1_000_000.0,
            blocks_found: 0,
            devices: vec![DeviceSnapshot {
                name: "gpu0".into(),
                hashrate: 1_000_000.0,
                temperature: temp,
                fan_rpm: Some(3000),
                power_watts: Some(300.0),
                hashes_total: 100_000_000,
            }],
            pools: vec![PoolSnapshot {
                url: "sv2://pool:3336".into(),
                accepted: total - stale,
                rejected: 0,
                stale,
                latency_ms: Some(25.0),
            }],
        }
    }

    #[test]
    fn test_temp_warning() {
        let mut engine = AlertEngine::with_defaults();
        let snap = make_snap(Some(85.0), 0.0);
        let alerts = engine.evaluate(&snap);

        assert!(!alerts.is_empty());
        assert!(alerts.iter().any(|a| a.rule_name == "temp_warning"));
        assert!(alerts.iter().all(|a| a.rule_name != "temp_critical"));
    }

    #[test]
    fn test_temp_critical() {
        let mut engine = AlertEngine::with_defaults();
        let snap = make_snap(Some(95.0), 0.0);
        let alerts = engine.evaluate(&snap);

        assert!(alerts.iter().any(|a| a.rule_name == "temp_critical"));
    }

    #[test]
    fn test_no_alert_normal() {
        let mut engine = AlertEngine::with_defaults();
        let snap = make_snap(Some(65.0), 0.01);
        let alerts = engine.evaluate(&snap);

        assert!(alerts.is_empty());
    }

    #[test]
    fn test_stale_shares_alert() {
        let mut engine = AlertEngine::with_defaults();
        let snap = make_snap(Some(60.0), 0.10); // 10% stale
        let alerts = engine.evaluate(&snap);

        assert!(alerts.iter().any(|a| a.rule_name == "stale_shares"));
    }

    #[test]
    fn test_cooldown() {
        let mut engine = AlertEngine::new(vec![AlertRule {
            name: "test_rule".into(),
            metric: AlertMetric::DeviceTemperature,
            condition: AlertCondition::Above,
            threshold: 80.0,
            level: AlertLevel::Warning,
            cooldown: Duration::from_secs(3600), // 1 hour cooldown
            message_template: "test".into(),
        }]);

        let snap = make_snap(Some(85.0), 0.0);

        // First evaluation fires
        let alerts1 = engine.evaluate(&snap);
        assert_eq!(alerts1.len(), 1);

        // Second evaluation within cooldown does NOT fire
        let alerts2 = engine.evaluate(&snap);
        assert_eq!(alerts2.len(), 0);
    }

    #[test]
    fn test_custom_rule() {
        let mut engine = AlertEngine::new(vec![AlertRule {
            name: "high_latency".into(),
            metric: AlertMetric::PoolLatency,
            condition: AlertCondition::Above,
            threshold: 20.0, // 20ms
            level: AlertLevel::Info,
            cooldown: Duration::from_secs(0),
            message_template: "Pool latency high".into(),
        }]);

        let snap = make_snap(Some(60.0), 0.0); // latency = 25ms
        let alerts = engine.evaluate(&snap);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, AlertLevel::Info);
    }

    #[test]
    fn test_alert_display() {
        let alert = Alert {
            level: AlertLevel::Critical,
            rule_name: "temp_critical".into(),
            message: "Temperature exceeds 90°C".into(),
            value: 95.0,
            threshold: 90.0,
            fired_at: Instant::now(),
        };
        let s = format!("{alert}");
        assert!(s.contains("CRIT"));
        assert!(s.contains("temp_critical"));
    }
}
