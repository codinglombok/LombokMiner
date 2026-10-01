// LombokMiner — Prometheus Text Format Exporter
//
// Generates metrics in Prometheus exposition format (text/plain; version=0.0.4).
// No external dependencies — just string formatting.
//
// Endpoint: GET /metrics → text/plain
// Compatible with Prometheus, Grafana Agent, Victoria Metrics, etc.

use crate::metrics::MetricsSnapshot;
use std::fmt::Write;

/// Render a MetricsSnapshot as Prometheus text format.
pub fn render(snap: &MetricsSnapshot) -> String {
    let mut out = String::with_capacity(4096);

    // ─── Miner-level metrics ────────────────────────────────────────────

    write_help(&mut out, "lombokminer_uptime_seconds", "Process uptime in seconds");
    write_type(&mut out, "lombokminer_uptime_seconds", "gauge");
    writeln!(out, "lombokminer_uptime_seconds {:.1}", snap.uptime_secs).ok();
    out.push('\n');

    write_help(&mut out, "lombokminer_hashrate_hps", "Total hashrate in hashes per second");
    write_type(&mut out, "lombokminer_hashrate_hps", "gauge");
    writeln!(out, "lombokminer_hashrate_hps {:.2}", snap.total_hashrate).ok();
    out.push('\n');

    write_help(&mut out, "lombokminer_blocks_found_total", "Total blocks found (solo mining)");
    write_type(&mut out, "lombokminer_blocks_found_total", "counter");
    writeln!(out, "lombokminer_blocks_found_total {}", snap.blocks_found).ok();
    out.push('\n');

    // ─── Per-device metrics ─────────────────────────────────────────────

    if !snap.devices.is_empty() {
        write_help(&mut out, "lombokminer_device_hashrate_hps", "Hashrate per device in H/s");
        write_type(&mut out, "lombokminer_device_hashrate_hps", "gauge");
        for d in &snap.devices {
            writeln!(
                out,
                "lombokminer_device_hashrate_hps{{device=\"{}\"}} {:.2}",
                escape_label(&d.name),
                d.hashrate
            ).ok();
        }
        out.push('\n');

        write_help(&mut out, "lombokminer_device_hashes_total", "Total hashes computed per device");
        write_type(&mut out, "lombokminer_device_hashes_total", "counter");
        for d in &snap.devices {
            writeln!(
                out,
                "lombokminer_device_hashes_total{{device=\"{}\"}} {}",
                escape_label(&d.name),
                d.hashes_total
            ).ok();
        }
        out.push('\n');

        // Temperature (only emit if sensor is available)
        let has_temp = snap.devices.iter().any(|d| d.temperature.is_some());
        if has_temp {
            write_help(&mut out, "lombokminer_device_temp_celsius", "Device temperature in degrees Celsius");
            write_type(&mut out, "lombokminer_device_temp_celsius", "gauge");
            for d in &snap.devices {
                if let Some(t) = d.temperature {
                    writeln!(
                        out,
                        "lombokminer_device_temp_celsius{{device=\"{}\"}} {:.1}",
                        escape_label(&d.name),
                        t
                    ).ok();
                }
            }
            out.push('\n');
        }

        let has_fan = snap.devices.iter().any(|d| d.fan_rpm.is_some());
        if has_fan {
            write_help(&mut out, "lombokminer_device_fan_rpm", "Device fan speed in RPM");
            write_type(&mut out, "lombokminer_device_fan_rpm", "gauge");
            for d in &snap.devices {
                if let Some(rpm) = d.fan_rpm {
                    writeln!(
                        out,
                        "lombokminer_device_fan_rpm{{device=\"{}\"}} {}",
                        escape_label(&d.name),
                        rpm
                    ).ok();
                }
            }
            out.push('\n');
        }

        let has_power = snap.devices.iter().any(|d| d.power_watts.is_some());
        if has_power {
            write_help(&mut out, "lombokminer_device_power_watts", "Device power draw in watts");
            write_type(&mut out, "lombokminer_device_power_watts", "gauge");
            for d in &snap.devices {
                if let Some(w) = d.power_watts {
                    writeln!(
                        out,
                        "lombokminer_device_power_watts{{device=\"{}\"}} {:.1}",
                        escape_label(&d.name),
                        w
                    ).ok();
                }
            }
            out.push('\n');
        }
    }

    // ─── Per-pool metrics ───────────────────────────────────────────────

    if !snap.pools.is_empty() {
        write_help(&mut out, "lombokminer_shares_total", "Total shares submitted per pool and status");
        write_type(&mut out, "lombokminer_shares_total", "counter");
        for p in &snap.pools {
            let pool = escape_label(&p.url);
            writeln!(out, "lombokminer_shares_total{{pool=\"{pool}\",status=\"accepted\"}} {}", p.accepted).ok();
            writeln!(out, "lombokminer_shares_total{{pool=\"{pool}\",status=\"rejected\"}} {}", p.rejected).ok();
            writeln!(out, "lombokminer_shares_total{{pool=\"{pool}\",status=\"stale\"}} {}", p.stale).ok();
        }
        out.push('\n');

        let has_latency = snap.pools.iter().any(|p| p.latency_ms.is_some());
        if has_latency {
            write_help(&mut out, "lombokminer_pool_latency_ms", "Network latency to pool in milliseconds");
            write_type(&mut out, "lombokminer_pool_latency_ms", "gauge");
            for p in &snap.pools {
                if let Some(ms) = p.latency_ms {
                    writeln!(
                        out,
                        "lombokminer_pool_latency_ms{{pool=\"{}\"}} {:.1}",
                        escape_label(&p.url),
                        ms
                    ).ok();
                }
            }
            out.push('\n');
        }
    }

    out
}

/// Render as JSON (for the web dashboard API).
pub fn render_json(snap: &MetricsSnapshot) -> String {
    serde_json::to_string_pretty(snap).unwrap_or_else(|_| "{}".to_string())
}

fn write_help(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").ok();
}

fn write_type(out: &mut String, name: &str, metric_type: &str) {
    writeln!(out, "# TYPE {name} {metric_type}").ok();
}

/// Escape label values for Prometheus format.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::*;

    fn sample_snapshot() -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: 3661.5,
            total_hashrate: 374_500_000_000_000.0,
            blocks_found: 0,
            devices: vec![
                DeviceSnapshot {
                    name: "Antminer S21 #0".into(),
                    hashrate: 188_000_000_000_000.0,
                    temperature: Some(62.5),
                    fan_rpm: Some(3200),
                    power_watts: Some(3150.0),
                    hashes_total: 690_000_000_000_000_000,
                },
                DeviceSnapshot {
                    name: "RTX 4090".into(),
                    hashrate: 1_200_000_000.0,
                    temperature: Some(71.0),
                    fan_rpm: Some(2100),
                    power_watts: Some(320.0),
                    hashes_total: 4_400_000_000_000,
                },
            ],
            pools: vec![PoolSnapshot {
                url: "sv2://braiins.com:3336".into(),
                accepted: 14237,
                rejected: 12,
                stale: 3,
                latency_ms: Some(23.4),
            }],
        }
    }

    #[test]
    fn test_prometheus_render() {
        let snap = sample_snapshot();
        let text = render(&snap);

        assert!(text.contains("lombokminer_uptime_seconds 3661.5"));
        assert!(text.contains("lombokminer_hashrate_hps 374500000000000.00"));
        assert!(text.contains("lombokminer_blocks_found_total 0"));
        assert!(text.contains("lombokminer_device_hashrate_hps{device=\"Antminer S21 #0\"}"));
        assert!(text.contains("lombokminer_device_temp_celsius{device=\"RTX 4090\"} 71.0"));
        assert!(text.contains("lombokminer_shares_total{pool=\"sv2://braiins.com:3336\",status=\"accepted\"} 14237"));
        assert!(text.contains("lombokminer_pool_latency_ms{pool=\"sv2://braiins.com:3336\"} 23.4"));

        // Every metric has HELP and TYPE
        assert!(text.contains("# HELP lombokminer_uptime_seconds"));
        assert!(text.contains("# TYPE lombokminer_uptime_seconds gauge"));
        assert!(text.contains("# TYPE lombokminer_shares_total counter"));
    }

    #[test]
    fn test_json_render() {
        let snap = sample_snapshot();
        let json = render_json(&snap);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["blocks_found"], 0);
        assert_eq!(parsed["devices"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_empty_snapshot() {
        let snap = MetricsSnapshot {
            uptime_secs: 0.0,
            total_hashrate: 0.0,
            blocks_found: 0,
            devices: vec![],
            pools: vec![],
        };
        let text = render(&snap);
        assert!(text.contains("lombokminer_uptime_seconds 0.0"));
        // Should not contain device/pool sections
        assert!(!text.contains("lombokminer_device_hashrate_hps"));
        assert!(!text.contains("lombokminer_shares_total"));
    }

    #[test]
    fn test_escape_label() {
        assert_eq!(escape_label("simple"), "simple");
        assert_eq!(escape_label("has\"quote"), "has\\\"quote");
        assert_eq!(escape_label("has\\back"), "has\\\\back");
    }
}
