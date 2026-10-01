// LombokMiner Core
//
// Zero-dependency Bitcoin mining engine.
// Provides SHA-256d hashing, block construction, merkle trees,
// difficulty calculation, and nonce iteration.
//
// Apache-2.0 — github.com/codinglombok/lombokminer

pub mod hash;
pub mod block;
pub mod mining;

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name.
pub const NAME: &str = "LombokMiner";

/// Full version string.
pub fn version_string() -> String {
    format!("{NAME} v{VERSION}")
}
