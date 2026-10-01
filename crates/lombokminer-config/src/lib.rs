// LombokMiner — Configuration
//
// Parses lombokminer.toml, validates all fields, applies defaults.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)] pub general: GeneralConfig,
    #[serde(default)] pub wallet: WalletConfig,
    #[serde(default)] pub solo: SoloConfig,
    #[serde(default)] pub pool: PoolsConfig,
    #[serde(default)] pub hardware: HardwareConfig,
    #[serde(default)] pub alerts: AlertsConfig,
    #[serde(default)] pub dashboard: DashboardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "d_mode")] pub mode: String,
    #[serde(default = "d_log_level")] pub log_level: String,
    #[serde(default = "d_log_format")] pub log_format: String,
    #[serde(default)] pub daemon: bool,
    #[serde(default = "d_api_bind")] pub api_bind: String,
    #[serde(default = "d_metrics_bind")] pub metrics_bind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig { #[serde(default)] pub address: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoloConfig {
    #[serde(default = "d_rpc")] pub bitcoind_rpc: String,
    #[serde(default)] pub bitcoind_user: String,
    #[serde(default)] pub bitcoind_pass: String,
    #[serde(default = "d_cb_msg")] pub coinbase_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolsConfig {
    #[serde(default)] pub primary: Option<PoolEntry>,
    #[serde(default)] pub backup: Option<PoolEntry>,
    #[serde(default)] pub extra: Vec<PoolEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolEntry {
    pub url: String,
    #[serde(default = "d_proto")] pub protocol: String,
    #[serde(default = "d_user")] pub user: String,
    #[serde(default = "d_pass")] pub password: String,
    #[serde(default)] pub job_declaration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareConfig {
    #[serde(default)] pub cpu: CpuHwConfig,
    #[serde(default)] pub gpu: GpuHwConfig,
    #[serde(default)] pub asic: AsicHwConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuHwConfig {
    #[serde(default = "d_true")] pub enabled: bool,
    #[serde(default)] pub threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuHwConfig {
    #[serde(default)] pub enabled: bool,
    #[serde(default = "d_gpu")] pub backend: String,
    #[serde(default)] pub devices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsicHwConfig {
    #[serde(default)] pub enabled: bool,
    #[serde(default = "d_true")] pub auto_detect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    #[serde(default = "d_hr_drop")] pub hashrate_drop_percent: f64,
    #[serde(default = "d_hr_win")] pub hashrate_drop_window: String,
    #[serde(default = "d_tw")] pub temp_warning: f32,
    #[serde(default = "d_tc")] pub temp_critical: f32,
    #[serde(default = "d_sw")] pub stale_ratio_warning: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    #[serde(default = "d_true")] pub enabled: bool,
    #[serde(default = "d_dash_bind")] pub bind: String,
    #[serde(default)] pub auth: bool,
    #[serde(default)] pub username: String,
    #[serde(default)] pub password_hash: String,
}

fn d_mode() -> String { "pool".into() }
fn d_log_level() -> String { "info".into() }
fn d_log_format() -> String { "human".into() }
fn d_api_bind() -> String { "127.0.0.1:4028".into() }
fn d_metrics_bind() -> String { "127.0.0.1:9100".into() }
fn d_rpc() -> String { "http://127.0.0.1:8332".into() }
fn d_cb_msg() -> String { "/LombokMiner/".into() }
fn d_proto() -> String { "stratum_v2".into() }
fn d_user() -> String { "worker1".into() }
fn d_pass() -> String { "x".into() }
fn d_true() -> bool { true }
fn d_gpu() -> String { "opencl".into() }
fn d_hr_drop() -> f64 { 10.0 }
fn d_hr_win() -> String { "5m".into() }
fn d_tw() -> f32 { 80.0 }
fn d_tc() -> f32 { 90.0 }
fn d_sw() -> f64 { 0.05 }
fn d_dash_bind() -> String { "0.0.0.0:8080".into() }

impl Default for GeneralConfig { fn default() -> Self { Self { mode: d_mode(), log_level: d_log_level(), log_format: d_log_format(), daemon: false, api_bind: d_api_bind(), metrics_bind: d_metrics_bind() } } }
impl Default for WalletConfig { fn default() -> Self { Self { address: String::new() } } }
impl Default for SoloConfig { fn default() -> Self { Self { bitcoind_rpc: d_rpc(), bitcoind_user: String::new(), bitcoind_pass: String::new(), coinbase_message: d_cb_msg() } } }
impl Default for PoolsConfig { fn default() -> Self { Self { primary: None, backup: None, extra: vec![] } } }
impl Default for HardwareConfig { fn default() -> Self { Self { cpu: CpuHwConfig::default(), gpu: GpuHwConfig::default(), asic: AsicHwConfig::default() } } }
impl Default for CpuHwConfig { fn default() -> Self { Self { enabled: true, threads: 0 } } }
impl Default for GpuHwConfig { fn default() -> Self { Self { enabled: false, backend: d_gpu(), devices: vec![] } } }
impl Default for AsicHwConfig { fn default() -> Self { Self { enabled: false, auto_detect: true } } }
impl Default for AlertsConfig { fn default() -> Self { Self { hashrate_drop_percent: d_hr_drop(), hashrate_drop_window: d_hr_win(), temp_warning: d_tw(), temp_critical: d_tc(), stale_ratio_warning: d_sw() } } }
impl Default for DashboardConfig { fn default() -> Self { Self { enabled: true, bind: d_dash_bind(), auth: false, username: String::new(), password_hash: String::new() } } }
impl Default for Config { fn default() -> Self { Self { general: GeneralConfig::default(), wallet: WalletConfig::default(), solo: SoloConfig::default(), pool: PoolsConfig::default(), hardware: HardwareConfig::default(), alerts: AlertsConfig::default(), dashboard: DashboardConfig::default() } } }

#[derive(Debug)]
pub enum ConfigError { ParseError(String), ValidationError(String), IoError(String) }
impl std::fmt::Display for ConfigError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { match self { Self::ParseError(e) => write!(f, "parse: {e}"), Self::ValidationError(e) => write!(f, "validation: {e}"), Self::IoError(e) => write!(f, "I/O: {e}") } } }
impl std::error::Error for ConfigError {}

pub fn parse_config(toml_str: &str) -> Result<Config, ConfigError> {
    let config: Config = toml::from_str(toml_str).map_err(|e| ConfigError::ParseError(e.to_string()))?;
    validate(&config)?;
    Ok(config)
}

pub fn load_config(path: &str) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;
    parse_config(&content)
}

pub fn load_or_default() -> Config {
    for path in &["lombokminer.toml", "config/lombokminer.toml", "/etc/lombokminer/lombokminer.toml"] {
        if let Ok(cfg) = load_config(path) { tracing::info!("Loaded config from {path}"); return cfg; }
    }
    tracing::info!("No config file found, using defaults");
    Config::default()
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    match config.general.mode.as_str() {
        "solo" | "pool" => {}
        o => return Err(ConfigError::ValidationError(format!("invalid mode '{o}'"))),
    }
    match config.general.log_level.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => {}
        o => return Err(ConfigError::ValidationError(format!("invalid log_level '{o}'"))),
    }
    if !config.wallet.address.is_empty() {
        lombokminer_security::validate_address(&config.wallet.address)
            .map_err(|e| ConfigError::ValidationError(format!("invalid wallet: {e}")))?;
    }
    if let Some(ref p) = config.pool.primary { validate_pool(p, "primary")?; }
    if let Some(ref p) = config.pool.backup { validate_pool(p, "backup")?; }
    if config.alerts.temp_warning >= config.alerts.temp_critical {
        return Err(ConfigError::ValidationError("temp_warning must be < temp_critical".into()));
    }
    Ok(())
}

fn validate_pool(e: &PoolEntry, name: &str) -> Result<(), ConfigError> {
    if e.url.is_empty() { return Err(ConfigError::ValidationError(format!("{name}.url empty"))); }
    match e.protocol.as_str() {
        "stratum_v2" | "stratum_v1" => Ok(()),
        o => Err(ConfigError::ValidationError(format!("{name}.protocol invalid: '{o}'"))),
    }
}

pub fn generate_default_toml() -> String {
    r#"# LombokMiner Configuration
# https://github.com/codinglombok/lombokminer

[general]
mode = "pool"
log_level = "info"
log_format = "human"
daemon = false
api_bind = "127.0.0.1:4028"
metrics_bind = "127.0.0.1:9100"

[wallet]
address = ""

[solo]
bitcoind_rpc = "http://127.0.0.1:8332"
bitcoind_user = "rpcuser"
bitcoind_pass = ""
coinbase_message = "/LombokMiner/"

[pool.primary]
url = "sv2://pool.example.com:3336"
protocol = "stratum_v2"
user = "worker1"
password = "x"
job_declaration = false

[hardware.cpu]
enabled = true
threads = 0

[hardware.gpu]
enabled = false
backend = "opencl"
devices = []

[hardware.asic]
enabled = false
auto_detect = true

[alerts]
hashrate_drop_percent = 10.0
hashrate_drop_window = "5m"
temp_warning = 80.0
temp_critical = 90.0
stale_ratio_warning = 0.05

[dashboard]
enabled = true
bind = "0.0.0.0:8080"
auth = false
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn test_parse_empty() { let c = parse_config("").unwrap(); assert_eq!(c.general.mode, "pool"); }
    #[test] fn test_parse_full() {
        let t = "[general]\nmode = \"solo\"\n\n[hardware.cpu]\nthreads = 4\n\n[pool.primary]\nurl = \"sv2://x:3336\"\n";
        let c = parse_config(t).unwrap();
        assert_eq!(c.general.mode, "solo");
        assert_eq!(c.hardware.cpu.threads, 4);
    }
    #[test] fn test_invalid_mode() { assert!(parse_config("[general]\nmode = \"x\"").is_err()); }
    #[test] fn test_invalid_wallet() { assert!(parse_config("[wallet]\naddress = \"bad\"").is_err()); }
    #[test] fn test_invalid_temp() { assert!(parse_config("[alerts]\ntemp_warning = 95.0\ntemp_critical = 90.0").is_err()); }
    #[test] fn test_generate_default() { let t = generate_default_toml(); assert!(t.contains("[general]")); parse_config(&t).unwrap(); }
    #[test] fn test_pool_empty_url() { assert!(parse_config("[pool.primary]\nurl = \"\"").is_err()); }
    #[test] fn test_defaults() { let c = Config::default(); assert!(c.hardware.cpu.enabled); assert!(!c.hardware.gpu.enabled); }
}
