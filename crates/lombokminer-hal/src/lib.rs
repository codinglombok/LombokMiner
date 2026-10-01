// LombokMiner Hardware Abstraction Layer
//
// Unified interface for CPU, GPU, and ASIC mining hardware.
// Every backend implements the MiningDevice trait.

pub mod traits;
pub mod cpu;
pub mod gpu;
pub mod asic;

pub use traits::{MiningDevice, DeviceType, DeviceInfo, DeviceSensors, DeviceWorkResult, DeviceError};
pub use traits::enumerate_devices;
pub use cpu::{CpuMiner, CpuConfig};
pub use gpu::{GpuBackend, GpuConfig};
pub use asic::{AsicConfig, AsicModel};
