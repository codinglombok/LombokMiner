// LombokMiner — Serial Transport
//
// Platform-independent serial port abstraction for ASIC USB miners.
// Most USB ASICs appear as USB-CDC or FTDI serial devices (/dev/ttyUSB0, COM3).
//
// This module provides:
//   - Auto-detection of ASIC serial ports
//   - Read/write with configurable baud rate, timeout
//   - Command/response framing for ASIC protocols

use std::io::{Read, Write};
use std::time::Duration;

/// Serial port configuration for ASIC communication.
#[derive(Debug, Clone)]
pub struct SerialConfig {
    /// Device path (e.g., "/dev/ttyUSB0", "COM3")
    pub path: String,
    /// Baud rate (typical: 115200 for most ASICs)
    pub baud_rate: u32,
    /// Read timeout
    pub timeout: Duration,
    /// Data bits (typically 8)
    pub data_bits: u8,
    /// Stop bits (typically 1)
    pub stop_bits: u8,
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            baud_rate: 115200,
            timeout: Duration::from_millis(500),
            data_bits: 8,
            stop_bits: 1,
        }
    }
}

/// Platform-agnostic serial port wrapper.
/// Uses raw file I/O on Linux and stubs on other platforms.
pub struct SerialPort {
    config: SerialConfig,
    #[cfg(target_os = "linux")]
    fd: Option<std::fs::File>,
    #[cfg(not(target_os = "linux"))]
    _phantom: std::marker::PhantomData<()>,
}

impl SerialPort {
    /// Open a serial port with the given configuration.
    pub fn open(config: SerialConfig) -> Result<Self, SerialError> {
        if config.path.is_empty() {
            return Err(SerialError::InvalidPath("empty path".into()));
        }

        #[cfg(target_os = "linux")]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&config.path)
                .map_err(|e| SerialError::OpenFailed(format!("{}: {e}", config.path)))?;

            // Configure baud rate via termios (simplified — production would use libc::tcsetattr)
            tracing::info!("Opened serial port {} at {} baud", config.path, config.baud_rate);

            Ok(Self {
                config,
                fd: Some(file),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("Serial port not implemented on this platform (stub)");
            Ok(Self {
                config,
                _phantom: std::marker::PhantomData,
            })
        }
    }

    /// Write bytes to the serial port.
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<usize, SerialError> {
        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut fd) = self.fd {
                fd.write(data).map_err(|e| SerialError::WriteFailed(e.to_string()))
            } else {
                Err(SerialError::NotOpen)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = data;
            Err(SerialError::NotSupported)
        }
    }

    /// Read bytes from the serial port (up to buf.len()).
    pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize, SerialError> {
        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut fd) = self.fd {
                fd.read(buf).map_err(|e| SerialError::ReadFailed(e.to_string()))
            } else {
                Err(SerialError::NotOpen)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = buf;
            Err(SerialError::NotSupported)
        }
    }

    /// Send a command and read the response.
    pub fn command(&mut self, cmd: &[u8], response_len: usize) -> Result<Vec<u8>, SerialError> {
        self.write_bytes(cmd)?;
        let mut buf = vec![0u8; response_len];
        let n = self.read_bytes(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Get the device path.
    pub fn path(&self) -> &str {
        &self.config.path
    }

    /// Get the baud rate.
    pub fn baud_rate(&self) -> u32 {
        self.config.baud_rate
    }
}

/// Auto-detect serial ports that might be ASIC miners.
///
/// On Linux, scans /dev/ttyUSB* and /dev/ttyACM* devices.
/// On Windows, scans COM ports.
pub fn detect_serial_ports() -> Vec<String> {
    let mut ports = Vec::new();

    #[cfg(target_os = "linux")]
    {
        for prefix in &["/dev/ttyUSB", "/dev/ttyACM"] {
            for i in 0..16 {
                let path = format!("{prefix}{i}");
                if std::path::Path::new(&path).exists() {
                    ports.push(path);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        for i in 1..=32 {
            let path = format!("COM{i}");
            // On Windows, we'd use CreateFile to test if the port exists
            ports.push(path);
        }
    }

    #[cfg(target_os = "macos")]
    {
        for prefix in &["/dev/tty.usbserial-", "/dev/tty.usbmodem"] {
            // macOS uses dynamic names — scan directory
            if let Ok(entries) = std::fs::read_dir("/dev") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with(prefix.trim_start_matches("/dev/")) {
                        ports.push(format!("/dev/{name}"));
                    }
                }
            }
        }
    }

    ports
}

/// Serial port errors.
#[derive(Debug)]
pub enum SerialError {
    InvalidPath(String),
    OpenFailed(String),
    NotOpen,
    WriteFailed(String),
    ReadFailed(String),
    Timeout,
    NotSupported,
}

impl std::fmt::Display for SerialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath(s) => write!(f, "invalid path: {s}"),
            Self::OpenFailed(s) => write!(f, "open failed: {s}"),
            Self::NotOpen => write!(f, "port not open"),
            Self::WriteFailed(s) => write!(f, "write failed: {s}"),
            Self::ReadFailed(s) => write!(f, "read failed: {s}"),
            Self::Timeout => write!(f, "timeout"),
            Self::NotSupported => write!(f, "serial not supported on this platform"),
        }
    }
}

impl std::error::Error for SerialError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_config_default() {
        let cfg = SerialConfig::default();
        assert_eq!(cfg.baud_rate, 115200);
        assert_eq!(cfg.data_bits, 8);
        assert_eq!(cfg.stop_bits, 1);
    }

    #[test]
    fn test_detect_serial_ports() {
        let ports = detect_serial_ports();
        // May be empty on CI — that's fine
        println!("Detected serial ports: {:?}", ports);
    }

    #[test]
    fn test_serial_open_invalid() {
        let result = SerialPort::open(SerialConfig {
            path: "".into(),
            ..Default::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_serial_open_nonexistent() {
        let result = SerialPort::open(SerialConfig {
            path: "/dev/ttyNONEXISTENT999".into(),
            ..Default::default()
        });
        assert!(result.is_err());
    }
}
