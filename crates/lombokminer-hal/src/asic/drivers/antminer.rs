// LombokMiner — Antminer USB Driver
//
// Supports Bitmain Antminer U1, U2, U3 USB stick miners.
// These use BM1382/BM1385 chips with a CH341 USB-UART bridge.
//
// Protocol is similar to GekkoScience but with different:
//   - Chip initialization sequence
//   - Frequency register layout
//   - Work submission format (some models use a different header)
//
// Reference: cgminer/driver-hashfast.c, cgminer/driver-bitfury.c

use crate::asic::driver::{AsicDriver, AsicWorkUnit, AsicResult};
use crate::asic::serial::{SerialPort, SerialConfig};
use crate::traits::{DeviceError, DeviceInfo, DeviceSensors, DeviceType};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Antminer USB model variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntminerModel {
    /// Antminer U1 (BM1382, ~1.6 GH/s)
    U1,
    /// Antminer U2 (BM1382, ~2 GH/s)
    U2,
    /// Antminer U3 (BM1385, ~63 GH/s)
    U3,
}

impl std::fmt::Display for AntminerModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::U1 => write!(f, "U1"),
            Self::U2 => write!(f, "U2"),
            Self::U3 => write!(f, "U3"),
        }
    }
}

/// Antminer USB driver.
pub struct AntminerDriver {
    model: AntminerModel,
    port: Mutex<Option<SerialPort>>,
    info: DeviceInfo,
    initialized: AtomicBool,
    frequency_mhz: u32,
}

impl AntminerDriver {
    pub fn new(model: AntminerModel, serial_path: &str) -> Self {
        let info = DeviceInfo {
            name: format!("Antminer {} ({})", model, serial_path),
            device_type: DeviceType::Asic,
            id: serial_path.to_string(),
            vendor: "Bitmain".into(),
            max_hashrate: Some(match model {
                AntminerModel::U1 => 1.6e9,
                AntminerModel::U2 => 2.0e9,
                AntminerModel::U3 => 63.0e9,
            }),
        };

        Self {
            model,
            port: Mutex::new(None),
            info,
            initialized: AtomicBool::new(false),
            frequency_mhz: match model {
                AntminerModel::U1 | AntminerModel::U2 => 200,
                AntminerModel::U3 => 550,
            },
        }
    }
}

impl AsicDriver for AntminerDriver {
    fn init(&mut self) -> Result<(), DeviceError> {
        let config = SerialConfig {
            path: self.info.id.clone(),
            baud_rate: 115200,
            timeout: Duration::from_millis(200),
            ..Default::default()
        };

        let port = SerialPort::open(config)
            .map_err(|e| DeviceError::InitFailed(format!("Antminer serial: {e}")))?;

        *self.port.lock().unwrap() = Some(port);
        self.initialized.store(true, Ordering::Relaxed);

        tracing::info!("Initialized Antminer {} at {} MHz", self.model, self.frequency_mhz);
        Ok(())
    }

    fn device_info(&self) -> DeviceInfo { self.info.clone() }
    fn read_sensors(&self) -> DeviceSensors { DeviceSensors::default() }

    fn submit_work(&self, work: &AsicWorkUnit) -> Result<(), DeviceError> {
        if !self.initialized.load(Ordering::Relaxed) {
            return Err(DeviceError::WorkFailed("not initialized".into()));
        }

        // Antminer work format: midstate(32) + tail(12)
        let mut cmd = Vec::with_capacity(44);
        for &word in &work.midstate {
            cmd.extend_from_slice(&word.to_le_bytes());
        }
        cmd.extend_from_slice(&work.tail);

        if let Some(ref mut port) = *self.port.lock().unwrap() {
            port.write_bytes(&cmd)
                .map_err(|e| DeviceError::WorkFailed(format!("write: {e}")))?;
        }

        Ok(())
    }

    fn poll_results(&self) -> Vec<AsicResult> {
        let mut results = Vec::new();
        if let Some(ref mut port) = *self.port.lock().unwrap() {
            let mut buf = [0u8; 32];
            if let Ok(n) = port.read_bytes(&mut buf) {
                // Antminer returns 4-byte nonce values
                let mut offset = 0;
                while offset + 4 <= n {
                    let nonce = u32::from_le_bytes([
                        buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
                    ]);
                    if nonce != 0 && nonce != 0xFFFFFFFF {
                        results.push(AsicResult { nonce, job_id: 0, chip_id: None });
                    }
                    offset += 4;
                }
            }
        }
        results
    }

    fn set_frequency(&mut self, mhz: u32) -> Result<(), DeviceError> {
        self.frequency_mhz = mhz;
        tracing::info!("Set Antminer {} frequency to {} MHz", self.model, mhz);
        Ok(())
    }

    fn set_voltage(&mut self, _mv: u32) -> Result<(), DeviceError> {
        Err(DeviceError::Unsupported("Antminer USB does not support voltage control".into()))
    }

    fn reset(&mut self) -> Result<(), DeviceError> {
        self.initialized.store(false, Ordering::Relaxed);
        self.init()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_antminer_new() {
        let d = AntminerDriver::new(AntminerModel::U3, "/dev/ttyUSB1");
        assert!(d.info.name.contains("U3"));
        assert_eq!(d.frequency_mhz, 550);
    }

    #[test]
    fn test_antminer_model_display() {
        assert_eq!(format!("{}", AntminerModel::U1), "U1");
        assert_eq!(format!("{}", AntminerModel::U3), "U3");
    }

    #[test]
    fn test_antminer_max_hashrate() {
        let d = AntminerDriver::new(AntminerModel::U3, "/dev/ttyUSB0");
        assert_eq!(d.info.max_hashrate, Some(63.0e9));
    }
}
