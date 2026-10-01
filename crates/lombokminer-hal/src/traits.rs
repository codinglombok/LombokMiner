// LombokMiner — Hardware Abstraction Layer: Core Traits
//
// Every mining backend (CPU, GPU, ASIC) implements the MiningDevice trait.
// The mining engine dispatches work units to devices without knowing
// the underlying hardware.

use lombokminer_core::block::BlockHeader;
use lombokminer_core::mining::{Target, MineResult};

/// Hardware backend type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DeviceType {
    Cpu,
    Gpu,
    Asic,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cpu => write!(f, "CPU"),
            Self::Gpu => write!(f, "GPU"),
            Self::Asic => write!(f, "ASIC"),
        }
    }
}

/// Hardware sensor readings (snapshot).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DeviceSensors {
    /// Temperature in °C
    pub temperature: Option<f32>,
    /// Fan speed in RPM
    pub fan_rpm: Option<u32>,
    /// Power draw in watts
    pub power_watts: Option<f32>,
    /// Clock frequency in MHz
    pub clock_mhz: Option<u32>,
    /// Voltage in mV
    pub voltage_mv: Option<u32>,
}

/// Information about a mining device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceInfo {
    /// Human-readable device name
    pub name: String,
    /// Device type
    pub device_type: DeviceType,
    /// Unique device identifier (serial number, PCI bus ID, etc.)
    pub id: String,
    /// Device vendor (e.g., "AMD", "NVIDIA", "Bitmain")
    pub vendor: String,
    /// Maximum theoretical hashrate (H/s)
    pub max_hashrate: Option<f64>,
}

/// Result of submitting a work unit to a device.
#[derive(Debug, Clone)]
pub struct DeviceWorkResult {
    /// Mining result (found or exhausted)
    pub result: MineResult,
    /// Number of hashes computed
    pub hashes: u64,
    /// Time taken in nanoseconds
    pub duration_ns: u64,
    /// Current hashrate (H/s)
    pub hashrate: f64,
}

/// Error from a device operation.
#[derive(Debug)]
pub enum DeviceError {
    /// Device not found or disconnected
    NotFound(String),
    /// Device initialization failed
    InitFailed(String),
    /// Work submission failed
    WorkFailed(String),
    /// Temperature limit exceeded
    Overheated(f32),
    /// Device communication error
    IoError(String),
    /// Feature not supported
    Unsupported(String),
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(s) => write!(f, "device not found: {s}"),
            Self::InitFailed(s) => write!(f, "init failed: {s}"),
            Self::WorkFailed(s) => write!(f, "work failed: {s}"),
            Self::Overheated(t) => write!(f, "overheated: {t}°C"),
            Self::IoError(s) => write!(f, "I/O error: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl std::error::Error for DeviceError {}

/// The core trait for all mining hardware.
///
/// Implementors: CpuMiner, GpuMiner, AsicDevice
pub trait MiningDevice: Send + Sync {
    /// Get device information.
    fn info(&self) -> &DeviceInfo;

    /// Read current sensor values.
    fn sensors(&self) -> DeviceSensors;

    /// Current hashrate in H/s.
    fn hashrate(&self) -> f64;

    /// Submit a work unit for mining.
    /// The device will iterate nonces in [nonce_start, nonce_end) and return
    /// when a valid hash is found or the range is exhausted.
    fn submit_work(
        &self,
        header: &BlockHeader,
        target: &Target,
        nonce_start: u32,
        nonce_end: u32,
    ) -> Result<DeviceWorkResult, DeviceError>;

    /// Set the device clock frequency (MHz). Not all devices support this.
    fn set_clock(&self, _mhz: u32) -> Result<(), DeviceError> {
        Err(DeviceError::Unsupported("clock control".into()))
    }

    /// Set the device voltage (mV). Not all devices support this.
    fn set_voltage(&self, _mv: u32) -> Result<(), DeviceError> {
        Err(DeviceError::Unsupported("voltage control".into()))
    }

    /// Shutdown / release the device.
    fn shutdown(&self) -> Result<(), DeviceError> {
        Ok(())
    }
}

/// Enumerate all available mining devices on this system.
pub fn enumerate_devices() -> Vec<DeviceInfo> {
    let mut devices = Vec::new();

    // CPU is always available
    let cpu_name = format!("CPU ({} cores)", num_cpus());
    devices.push(DeviceInfo {
        name: cpu_name,
        device_type: DeviceType::Cpu,
        id: "cpu0".into(),
        vendor: cpu_vendor(),
        max_hashrate: None,
    });

    // GPU detection would go here (OpenCL/Vulkan enumeration)
    // ASIC detection would go here (USB enumeration)

    devices
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
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
    fn test_enumerate_devices() {
        let devs = enumerate_devices();
        assert!(!devs.is_empty());
        assert_eq!(devs[0].device_type, DeviceType::Cpu);
        assert!(devs[0].name.contains("CPU"));
    }

    #[test]
    fn test_device_info_display() {
        assert_eq!(format!("{}", DeviceType::Cpu), "CPU");
        assert_eq!(format!("{}", DeviceType::Gpu), "GPU");
        assert_eq!(format!("{}", DeviceType::Asic), "ASIC");
    }

    #[test]
    fn test_device_error_display() {
        let e = DeviceError::Overheated(95.0);
        assert!(format!("{e}").contains("95"));
    }

    #[test]
    fn test_device_sensors_default() {
        let s = DeviceSensors::default();
        assert!(s.temperature.is_none());
        assert!(s.fan_rpm.is_none());
    }
}
