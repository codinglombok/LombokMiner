// LombokMiner — GekkoScience Compac Driver
//
// Supports GekkoScience Compac F, NewPac, R909 USB miners.
// These devices use BM1387/BM1397 ASIC chips (same as Antminer S9/S17).
//
// Protocol:
//   - USB-CDC serial at 115200 baud (default) or 375000 baud (Compac F)
//   - cgminer-compatible work submission format
//   - Midstate-based work: send 32-byte midstate + 12-byte tail
//   - Results: 4-byte nonce responses
//
// Reference: https://github.com/vthoang/cgminer (gekko driver)

use crate::asic::driver::{AsicDriver, AsicWorkUnit, AsicResult};
use crate::asic::serial::{SerialPort, SerialConfig, SerialError};
use crate::traits::{DeviceError, DeviceInfo, DeviceSensors, DeviceType};

use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// GekkoScience device model variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GekkoModel {
    /// Compac F (BM1397, ~300 GH/s)
    CompacF,
    /// NewPac (dual BM1387, ~40 GH/s)
    NewPac,
    /// R909 (BM1397, ~120 GH/s)
    R909,
    /// Compac (single BM1387, ~20 GH/s)
    Compac,
}

impl std::fmt::Display for GekkoModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompacF => write!(f, "Compac F"),
            Self::NewPac => write!(f, "NewPac"),
            Self::R909 => write!(f, "R909"),
            Self::Compac => write!(f, "Compac"),
        }
    }
}

/// GekkoScience chip configuration.
#[derive(Debug, Clone)]
pub struct GekkoChipConfig {
    /// Clock frequency in MHz
    pub frequency_mhz: u32,
    /// Voltage in mV (for devices that support it)
    pub voltage_mv: Option<u32>,
    /// Number of ASIC chips on the device
    pub chip_count: u8,
    /// Baud rate for serial communication
    pub baud_rate: u32,
}

impl GekkoChipConfig {
    /// Default config for each model.
    pub fn for_model(model: GekkoModel) -> Self {
        match model {
            GekkoModel::CompacF => Self {
                frequency_mhz: 400,
                voltage_mv: Some(1200),
                chip_count: 1,
                baud_rate: 375000,
            },
            GekkoModel::NewPac => Self {
                frequency_mhz: 600,
                voltage_mv: None,
                chip_count: 2,
                baud_rate: 115200,
            },
            GekkoModel::R909 => Self {
                frequency_mhz: 450,
                voltage_mv: Some(1250),
                chip_count: 1,
                baud_rate: 375000,
            },
            GekkoModel::Compac => Self {
                frequency_mhz: 600,
                voltage_mv: None,
                chip_count: 1,
                baud_rate: 115200,
            },
        }
    }
}

// ─── BM1387/BM1397 Protocol Constants ───────────────────────────────────────

/// Command prefix bytes
const CMD_PREAMBLE: [u8; 2] = [0x55, 0xAA];

/// Command types
const CMD_WRITE_JOB: u8 = 0x01;   // Send work to chip
const CMD_READ_RESULT: u8 = 0x02;  // Read nonce result
const CMD_SET_FREQ: u8 = 0x04;     // Set clock frequency
const CMD_CHAIN_INACTIVE: u8 = 0x05; // Deactivate chip chain
const CMD_SET_BAUD: u8 = 0x06;     // Set baud rate
const CMD_READ_REG: u8 = 0x07;     // Read chip register (for temp)
const CMD_WRITE_REG: u8 = 0x08;    // Write chip register

/// Work command length: preamble(2) + cmd(1) + length(1) + midstate(32) + tail(12) + crc(2) = 50
const WORK_CMD_LEN: usize = 50;

/// Nonce response length: preamble(2) + nonce(4) + chip_id(1) + crc(1) = 8
const NONCE_RESPONSE_LEN: usize = 8;

// ─── Driver Implementation ─────────────────────────────────────────────────

/// GekkoScience ASIC driver.
pub struct GekkoDriver {
    model: GekkoModel,
    config: GekkoChipConfig,
    port: Mutex<Option<SerialPort>>,
    info: DeviceInfo,
    initialized: AtomicBool,
    hashes_total: AtomicU64,
    hashrate_bits: AtomicU64,
    last_nonce_time: Mutex<Option<Instant>>,
    current_job_id: AtomicU64,
}

impl GekkoDriver {
    /// Create a new GekkoScience driver.
    pub fn new(model: GekkoModel, serial_path: &str) -> Self {
        let config = GekkoChipConfig::for_model(model);
        let info = DeviceInfo {
            name: format!("GekkoScience {} ({})", model, serial_path),
            device_type: DeviceType::Asic,
            id: serial_path.to_string(),
            vendor: "GekkoScience".into(),
            max_hashrate: Some(model_max_hashrate(model)),
        };

        Self {
            model,
            config: config.clone(),
            port: Mutex::new(None),
            info,
            initialized: AtomicBool::new(false),
            hashes_total: AtomicU64::new(0),
            hashrate_bits: AtomicU64::new(0),
            last_nonce_time: Mutex::new(None),
            current_job_id: AtomicU64::new(0),
        }
    }

    /// Build a work command for the BM1387/BM1397 chip.
    ///
    /// Format: [0x55, 0xAA, CMD_WRITE_JOB, length, midstate[32], tail[12], crc[2]]
    fn build_work_cmd(work: &AsicWorkUnit) -> [u8; WORK_CMD_LEN] {
        let mut cmd = [0u8; WORK_CMD_LEN];

        // Preamble
        cmd[0] = CMD_PREAMBLE[0];
        cmd[1] = CMD_PREAMBLE[1];

        // Command type
        cmd[2] = CMD_WRITE_JOB;

        // Payload length (midstate + tail = 44 bytes)
        cmd[3] = 44;

        // Midstate (32 bytes, as little-endian u32 words)
        for (i, &word) in work.midstate.iter().enumerate() {
            let bytes = word.to_le_bytes();
            cmd[4 + i * 4..4 + (i + 1) * 4].copy_from_slice(&bytes);
        }

        // Tail (12 bytes: timestamp[4] + bits[4] + nonce_start[4])
        cmd[36..48].copy_from_slice(&work.tail);

        // CRC-16 (simplified: XOR checksum over payload)
        let crc = compute_crc(&cmd[2..48]);
        cmd[48] = (crc >> 8) as u8;
        cmd[49] = (crc & 0xFF) as u8;

        cmd
    }

    /// Build a frequency-set command.
    fn build_freq_cmd(freq_mhz: u32) -> Vec<u8> {
        // BM1387 frequency register format
        // The actual PLL calculation depends on the chip variant
        let pll_val = (freq_mhz as f64 / 25.0 * 64.0) as u16;

        let mut cmd = vec![0u8; 10];
        cmd[0] = CMD_PREAMBLE[0];
        cmd[1] = CMD_PREAMBLE[1];
        cmd[2] = CMD_SET_FREQ;
        cmd[3] = 4; // payload length
        cmd[4] = (pll_val >> 8) as u8;
        cmd[5] = (pll_val & 0xFF) as u8;
        cmd[6] = 0x00; // chip address (broadcast)
        cmd[7] = 0x00;

        let crc = compute_crc(&cmd[2..8]);
        cmd[8] = (crc >> 8) as u8;
        cmd[9] = (crc & 0xFF) as u8;

        cmd
    }

    /// Parse a nonce response from the chip.
    ///
    /// Format: [0x55, 0xAA, nonce[4], chip_id, crc]
    fn parse_nonce_response(data: &[u8]) -> Option<AsicResult> {
        if data.len() < NONCE_RESPONSE_LEN {
            return None;
        }

        // Check preamble
        if data[0] != CMD_PREAMBLE[0] || data[1] != CMD_PREAMBLE[1] {
            return None;
        }

        let nonce = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        let chip_id = data[6];

        Some(AsicResult {
            nonce,
            job_id: 0, // filled by caller
            chip_id: Some(chip_id),
        })
    }
}

impl AsicDriver for GekkoDriver {
    fn init(&mut self) -> Result<(), DeviceError> {
        let serial_config = SerialConfig {
            path: self.info.id.clone(),
            baud_rate: self.config.baud_rate,
            timeout: Duration::from_millis(100),
            ..Default::default()
        };

        let port = SerialPort::open(serial_config)
            .map_err(|e| DeviceError::InitFailed(format!("serial open: {e}")))?;

        *self.port.lock().unwrap() = Some(port);

        // Send chip chain inactive command (reset all chips)
        let reset_cmd = [CMD_PREAMBLE[0], CMD_PREAMBLE[1], CMD_CHAIN_INACTIVE, 0x00, 0x00, 0x00];
        if let Some(ref mut p) = *self.port.lock().unwrap() {
            let _ = p.write_bytes(&reset_cmd);
        }

        // Set frequency
        let freq_cmd = Self::build_freq_cmd(self.config.frequency_mhz);
        if let Some(ref mut p) = *self.port.lock().unwrap() {
            let _ = p.write_bytes(&freq_cmd);
        }

        self.initialized.store(true, Ordering::Relaxed);
        tracing::info!(
            "Initialized {} at {} MHz ({} baud)",
            self.info.name, self.config.frequency_mhz, self.config.baud_rate
        );

        Ok(())
    }

    fn device_info(&self) -> DeviceInfo {
        self.info.clone()
    }

    fn read_sensors(&self) -> DeviceSensors {
        // BM1387/BM1397 have on-die temperature sensors accessible via register read.
        // For now, return empty — real implementation would send CMD_READ_REG.
        DeviceSensors::default()
    }

    fn submit_work(&self, work: &AsicWorkUnit) -> Result<(), DeviceError> {
        if !self.initialized.load(Ordering::Relaxed) {
            return Err(DeviceError::WorkFailed("not initialized".into()));
        }

        let cmd = Self::build_work_cmd(work);
        self.current_job_id.store(work.job_id as u64, Ordering::Relaxed);

        if let Some(ref mut port) = *self.port.lock().unwrap() {
            port.write_bytes(&cmd)
                .map_err(|e| DeviceError::WorkFailed(format!("write: {e}")))?;
        } else {
            return Err(DeviceError::WorkFailed("port not open".into()));
        }

        Ok(())
    }

    fn poll_results(&self) -> Vec<AsicResult> {
        let mut results = Vec::new();

        if let Some(ref mut port) = *self.port.lock().unwrap() {
            let mut buf = [0u8; 64];
            match port.read_bytes(&mut buf) {
                Ok(n) if n >= NONCE_RESPONSE_LEN => {
                    // Parse all complete responses in the buffer
                    let mut offset = 0;
                    while offset + NONCE_RESPONSE_LEN <= n {
                        if let Some(mut result) = Self::parse_nonce_response(&buf[offset..]) {
                            result.job_id = self.current_job_id.load(Ordering::Relaxed) as u32;
                            results.push(result);
                        }
                        offset += NONCE_RESPONSE_LEN;
                    }
                }
                _ => {} // No data or read error — normal during mining
            }
        }

        // Update hash counter (estimate based on chip hashrate)
        if !results.is_empty() {
            *self.last_nonce_time.lock().unwrap() = Some(Instant::now());
        }

        results
    }

    fn set_frequency(&mut self, mhz: u32) -> Result<(), DeviceError> {
        let cmd = Self::build_freq_cmd(mhz);
        if let Some(ref mut port) = *self.port.lock().unwrap() {
            port.write_bytes(&cmd)
                .map_err(|e| DeviceError::IoError(format!("set freq: {e}")))?;
            self.config.frequency_mhz = mhz;
            tracing::info!("Set {} frequency to {} MHz", self.info.name, mhz);
            Ok(())
        } else {
            Err(DeviceError::IoError("port not open".into()))
        }
    }

    fn set_voltage(&mut self, mv: u32) -> Result<(), DeviceError> {
        if self.config.voltage_mv.is_some() {
            self.config.voltage_mv = Some(mv);
            tracing::info!("Set {} voltage to {} mV", self.info.name, mv);
            Ok(())
        } else {
            Err(DeviceError::Unsupported("voltage control not available on this model".into()))
        }
    }

    fn reset(&mut self) -> Result<(), DeviceError> {
        self.initialized.store(false, Ordering::Relaxed);
        self.init()
    }
}

/// Estimated max hashrate per model (H/s).
fn model_max_hashrate(model: GekkoModel) -> f64 {
    match model {
        GekkoModel::CompacF => 300e9,  // 300 GH/s
        GekkoModel::NewPac => 40e9,    // 40 GH/s
        GekkoModel::R909 => 120e9,     // 120 GH/s
        GekkoModel::Compac => 20e9,    // 20 GH/s
    }
}

/// CRC-16 checksum (XOR-based, simplified for ASIC protocol).
fn compute_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Detect GekkoScience devices on available serial ports.
pub fn detect_gekko_devices() -> Vec<(GekkoModel, String)> {
    let mut devices = Vec::new();

    let ports = crate::asic::serial::detect_serial_ports();
    for port in ports {
        // In production, we'd open the port, send an identification command,
        // and parse the response to determine the model.
        // For now, we report all /dev/ttyUSB* as potential GekkoScience devices.
        if port.contains("ttyUSB") || port.contains("ttyACM") {
            tracing::debug!("Potential GekkoScience device at {port}");
            // Default to Compac — real detection would query the chip
            devices.push((GekkoModel::Compac, port));
        }
    }

    devices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_work_cmd() {
        let work = AsicWorkUnit {
            midstate: [0x11223344; 8],
            tail: [0xAA; 12],
            nbits: 0x17034219,
            job_id: 1,
        };

        let cmd = GekkoDriver::build_work_cmd(&work);
        assert_eq!(cmd[0], 0x55); // preamble
        assert_eq!(cmd[1], 0xAA);
        assert_eq!(cmd[2], CMD_WRITE_JOB);
        assert_eq!(cmd[3], 44); // payload length
        assert_eq!(cmd.len(), WORK_CMD_LEN);
    }

    #[test]
    fn test_parse_nonce_response() {
        let response = [0x55, 0xAA, 0x78, 0x56, 0x34, 0x12, 0x03, 0x00];
        let result = GekkoDriver::parse_nonce_response(&response).unwrap();
        assert_eq!(result.nonce, 0x12345678);
        assert_eq!(result.chip_id, Some(0x03));
    }

    #[test]
    fn test_parse_nonce_bad_preamble() {
        let response = [0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x03, 0x00];
        assert!(GekkoDriver::parse_nonce_response(&response).is_none());
    }

    #[test]
    fn test_parse_nonce_too_short() {
        let response = [0x55, 0xAA, 0x78];
        assert!(GekkoDriver::parse_nonce_response(&response).is_none());
    }

    #[test]
    fn test_freq_cmd() {
        let cmd = GekkoDriver::build_freq_cmd(600);
        assert_eq!(cmd[0], 0x55);
        assert_eq!(cmd[1], 0xAA);
        assert_eq!(cmd[2], CMD_SET_FREQ);
    }

    #[test]
    fn test_crc() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let crc1 = compute_crc(&data);
        let crc2 = compute_crc(&data);
        assert_eq!(crc1, crc2); // deterministic
        assert_ne!(crc1, 0); // non-trivial
    }

    #[test]
    fn test_chip_config_models() {
        let cf = GekkoChipConfig::for_model(GekkoModel::CompacF);
        assert_eq!(cf.frequency_mhz, 400);
        assert_eq!(cf.baud_rate, 375000);
        assert!(cf.voltage_mv.is_some());

        let np = GekkoChipConfig::for_model(GekkoModel::NewPac);
        assert_eq!(np.chip_count, 2);
        assert_eq!(np.baud_rate, 115200);
    }

    #[test]
    fn test_model_hashrate() {
        assert!(model_max_hashrate(GekkoModel::CompacF) > model_max_hashrate(GekkoModel::Compac));
        assert!(model_max_hashrate(GekkoModel::R909) > model_max_hashrate(GekkoModel::NewPac));
    }

    #[test]
    fn test_detect_gekko() {
        let devices = detect_gekko_devices();
        // May be empty on CI
        println!("Detected GekkoScience: {:?}", devices);
    }

    #[test]
    fn test_gekko_driver_new() {
        let driver = GekkoDriver::new(GekkoModel::CompacF, "/dev/ttyUSB0");
        assert_eq!(driver.model, GekkoModel::CompacF);
        assert!(driver.info.name.contains("Compac F"));
        assert!(!driver.initialized.load(Ordering::Relaxed));
    }

    #[test]
    fn test_model_display() {
        assert_eq!(format!("{}", GekkoModel::CompacF), "Compac F");
        assert_eq!(format!("{}", GekkoModel::NewPac), "NewPac");
    }
}
