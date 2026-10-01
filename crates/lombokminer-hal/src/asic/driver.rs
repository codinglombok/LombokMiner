// LombokMiner — ASIC Driver Framework
//
// Abstraction for USB-connected ASIC mining devices.
// Implements a cgminer-compatible protocol for communication with
// Antminer, Whatsminer, Avalon, and other SHA-256 ASICs.
//
// Architecture:
//   1. USB hotplug detection (libusb or platform-specific)
//   2. Serial/UART communication (USB-CDC or FTDI)
//   3. Per-vendor driver for chip initialization, work submission, result reading
//   4. MiningDevice trait implementation for each supported ASIC

use crate::traits::{DeviceError, DeviceInfo, DeviceSensors, DeviceType};

/// ASIC vendor/model identification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum AsicModel {
    /// Bitmain Antminer series
    Antminer { model: String },
    /// MicroBT Whatsminer series
    Whatsminer { model: String },
    /// Canaan Avalon series
    Avalon { model: String },
    /// Generic cgminer-compatible ASIC
    Generic { vendor: String, model: String },
}

impl std::fmt::Display for AsicModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Antminer { model } => write!(f, "Antminer {model}"),
            Self::Whatsminer { model } => write!(f, "Whatsminer {model}"),
            Self::Avalon { model } => write!(f, "Avalon {model}"),
            Self::Generic { vendor, model } => write!(f, "{vendor} {model}"),
        }
    }
}

/// ASIC connection interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsicInterface {
    /// USB with vendor/product ID
    Usb { vendor_id: u16, product_id: u16 },
    /// Network (Ethernet-connected ASICs)
    Network { host: String, port: u16 },
    /// Serial port (UART/RS-232)
    Serial { path: String, baud_rate: u32 },
}

/// ASIC driver configuration.
#[derive(Debug, Clone)]
pub struct AsicConfig {
    /// Auto-detect USB ASIC devices
    pub auto_detect: bool,
    /// Manually specified ASIC connections
    pub manual_devices: Vec<AsicInterface>,
    /// Default chip frequency (MHz), 0 = use device default
    pub default_frequency: u32,
    /// Default chip voltage (mV), 0 = use device default
    pub default_voltage: u32,
}

impl Default for AsicConfig {
    fn default() -> Self {
        Self {
            auto_detect: true,
            manual_devices: vec![],
            default_frequency: 0,
            default_voltage: 0,
        }
    }
}

/// Known USB vendor/product IDs for mining ASICs.
pub const KNOWN_ASIC_USB_IDS: &[(u16, u16, &str)] = &[
    // Bitmain (various controllers)
    (0x1a86, 0x7523, "CH341 (Bitmain USB)"),
    // FTDI (common ASIC UART bridge)
    (0x0403, 0x6001, "FTDI FT232R"),
    (0x0403, 0x6014, "FTDI FT232H"),
    // CP2102 (Silicon Labs, used by various miners)
    (0x10c4, 0xea60, "CP2102 USB-UART"),
    // Canaan Avalon
    (0x1fc9, 0x0083, "Avalon USB"),
    // GekkoScience
    (0x2100, 0x0001, "GekkoScience Compac"),
];

/// Work unit for ASIC submission.
/// ASICs receive a compact work descriptor, not the full block.
#[derive(Debug, Clone)]
pub struct AsicWorkUnit {
    /// Midstate (SHA-256 state after first 64 bytes of header)
    pub midstate: [u32; 8],
    /// Last 12 bytes of the header (timestamp, bits, nonce_start)
    /// Note: ASICs handle nonce iteration internally on-chip
    pub tail: [u8; 12],
    /// Target difficulty (compact)
    pub nbits: u32,
    /// Job identifier
    pub job_id: u32,
}

/// Result from an ASIC after processing a work unit.
#[derive(Debug, Clone)]
pub struct AsicResult {
    /// The winning nonce (if found)
    pub nonce: u32,
    /// Job ID this result belongs to
    pub job_id: u32,
    /// Which chip on the ASIC board found it
    pub chip_id: Option<u8>,
}

/// Trait for ASIC-specific driver implementations.
///
/// Each ASIC vendor requires a different initialization sequence,
/// work format, and result parsing. This trait abstracts those differences.
pub trait AsicDriver: Send + Sync {
    /// Initialize the ASIC device (reset, set frequency/voltage, etc.)
    fn init(&mut self) -> Result<(), DeviceError>;

    /// Get device info (model, serial, hashrate)
    fn device_info(&self) -> DeviceInfo;

    /// Read sensor data (temperature, fan, power)
    fn read_sensors(&self) -> DeviceSensors;

    /// Submit a work unit to the ASIC
    fn submit_work(&self, work: &AsicWorkUnit) -> Result<(), DeviceError>;

    /// Poll for results (non-blocking)
    fn poll_results(&self) -> Vec<AsicResult>;

    /// Set chip frequency in MHz
    fn set_frequency(&mut self, mhz: u32) -> Result<(), DeviceError>;

    /// Set chip voltage in mV
    fn set_voltage(&mut self, mv: u32) -> Result<(), DeviceError>;

    /// Perform hardware reset
    fn reset(&mut self) -> Result<(), DeviceError>;
}

/// Scan for connected ASIC devices.
///
/// This is a stub — actual implementation requires USB enumeration
/// (libusb or platform-specific APIs).
pub fn scan_asic_devices() -> Vec<DeviceInfo> {
    tracing::debug!("ASIC scan: no USB library linked (stub)");

    // In production:
    // 1. Enumerate USB devices
    // 2. Match against KNOWN_ASIC_USB_IDS
    // 3. Open device, send identification command
    // 4. Return DeviceInfo for each recognized ASIC

    vec![]
}

/// Create the appropriate driver for a detected ASIC model.
pub fn create_driver(model: &AsicModel, interface: &AsicInterface) -> Result<Box<dyn AsicDriver>, DeviceError> {
    match model {
        AsicModel::Antminer { .. } => {
            Err(DeviceError::Unsupported(format!(
                "Antminer driver not yet implemented (interface: {interface:?})"
            )))
        }
        AsicModel::Whatsminer { .. } => {
            Err(DeviceError::Unsupported("Whatsminer driver not yet implemented".into()))
        }
        AsicModel::Avalon { .. } => {
            Err(DeviceError::Unsupported("Avalon driver not yet implemented".into()))
        }
        AsicModel::Generic { vendor, model: m } => {
            Err(DeviceError::Unsupported(format!(
                "No driver for {vendor} {m}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asic_model_display() {
        let m = AsicModel::Antminer { model: "S21".into() };
        assert_eq!(format!("{m}"), "Antminer S21");

        let m = AsicModel::Generic { vendor: "Innosilicon".into(), model: "T3+".into() };
        assert_eq!(format!("{m}"), "Innosilicon T3+");
    }

    #[test]
    fn test_scan_empty() {
        let devices = scan_asic_devices();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_known_usb_ids() {
        assert!(!KNOWN_ASIC_USB_IDS.is_empty());
        // Verify FTDI is in the list
        assert!(KNOWN_ASIC_USB_IDS.iter().any(|(v, _, _)| *v == 0x0403));
    }

    #[test]
    fn test_create_driver_unsupported() {
        let model = AsicModel::Antminer { model: "S21".into() };
        let iface = AsicInterface::Usb { vendor_id: 0x1a86, product_id: 0x7523 };
        let result = create_driver(&model, &iface);
        assert!(result.is_err());
    }

    #[test]
    fn test_asic_config_default() {
        let cfg = AsicConfig::default();
        assert!(cfg.auto_detect);
        assert!(cfg.manual_devices.is_empty());
    }

    #[test]
    fn test_asic_work_unit() {
        let work = AsicWorkUnit {
            midstate: [0u32; 8],
            tail: [0u8; 12],
            nbits: 0x17034219,
            job_id: 42,
        };
        assert_eq!(work.job_id, 42);
    }
}
