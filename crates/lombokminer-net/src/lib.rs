// LombokMiner Network Layer
//
// Stratum V2 (primary), Stratum V1 (compat), getblocktemplate RPC,
// and pool connection management with failover.

pub mod stratum_v2;
pub mod stratum_v1;
pub mod rpc;
pub mod pool;

pub use pool::{PoolConfig, PoolProtocol, PoolManager, ConnectionState};
