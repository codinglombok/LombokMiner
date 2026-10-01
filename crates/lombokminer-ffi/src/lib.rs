// LombokMiner — C FFI
//
// Exposes core mining functions as C-compatible symbols.
// Used by: Python (via ctypes/cffi), PHP (via FFI), Go (via cgo), etc.
//
// ABI: C (extern "C"), all pointers are caller-owned unless noted.
// Error handling: functions return 0 on success, negative on error.
// Thread safety: all functions are thread-safe (no global mutable state).
//
// Build outputs:
//   liblombokminer.so     (Linux)
//   liblombokminer.dylib  (macOS)
//   lombokminer.dll        (Windows)
//   liblombokminer.a       (static, all platforms)

use std::slice;

// ─── Version ────────────────────────────────────────────────────────────────

/// Get the library version string. Returns a pointer to a static null-terminated string.
/// The pointer is valid for the lifetime of the library. Do NOT free it.
#[no_mangle]
pub extern "C" fn lombokminer_version() -> *const std::ffi::c_char {
    static VERSION: &[u8] = b"1.0.0\0";
    VERSION.as_ptr() as *const std::ffi::c_char
}

// ─── SHA-256d Hashing ───────────────────────────────────────────────────────

/// Compute SHA-256d (double SHA-256) of input data.
///
/// # Parameters
/// - `data`: pointer to input bytes
/// - `data_len`: length of input in bytes
/// - `out`: pointer to a 32-byte output buffer (caller-allocated)
///
/// # Returns
/// 0 on success, -1 on null pointer.
#[no_mangle]
pub extern "C" fn lombokminer_sha256d(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
) -> i32 {
    if data.is_null() || out.is_null() {
        return -1;
    }

    let input = unsafe { slice::from_raw_parts(data, data_len) };
    let hash = lombokminer_core::hash::sha256d(input);

    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32);
    }
    0
}

/// Compute SHA-256 midstate of the first 64 bytes of a block header.
///
/// # Parameters
/// - `first_64`: pointer to exactly 64 bytes
/// - `out`: pointer to 32-byte output buffer (midstate as 8 × u32 LE)
///
/// # Returns
/// 0 on success, -1 on null pointer.
#[no_mangle]
pub extern "C" fn lombokminer_sha256_midstate(
    first_64: *const u8,
    out: *mut u32,
) -> i32 {
    if first_64.is_null() || out.is_null() {
        return -1;
    }

    let input: [u8; 64] = unsafe {
        let s = slice::from_raw_parts(first_64, 64);
        s.try_into().unwrap()
    };

    let midstate = lombokminer_core::hash::sha256_midstate(&input);

    unsafe {
        std::ptr::copy_nonoverlapping(midstate.as_ptr(), out, 8);
    }
    0
}

/// Compute SHA-256d from a precomputed midstate and the last 16 bytes.
///
/// # Parameters
/// - `midstate`: pointer to 8 × u32 (32 bytes) midstate
/// - `last_16`: pointer to 16 bytes (tail of 80-byte header)
/// - `out`: pointer to 32-byte output buffer
///
/// # Returns
/// 0 on success, -1 on null pointer.
#[no_mangle]
pub extern "C" fn lombokminer_sha256d_from_midstate(
    midstate: *const u32,
    last_16: *const u8,
    out: *mut u8,
) -> i32 {
    if midstate.is_null() || last_16.is_null() || out.is_null() {
        return -1;
    }

    let ms: [u32; 8] = unsafe {
        let s = slice::from_raw_parts(midstate, 8);
        s.try_into().unwrap()
    };
    let tail: [u8; 16] = unsafe {
        let s = slice::from_raw_parts(last_16, 16);
        s.try_into().unwrap()
    };

    let hash = lombokminer_core::hash::sha256_from_midstate(&ms, &tail);

    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32);
    }
    0
}

// ─── Block Header ───────────────────────────────────────────────────────────

/// Compute the block hash of an 80-byte serialized header.
///
/// # Parameters
/// - `header_80`: pointer to exactly 80 bytes (serialized block header)
/// - `out`: pointer to 32-byte output buffer (hash in internal byte order)
///
/// # Returns
/// 0 on success, -1 on null pointer.
#[no_mangle]
pub extern "C" fn lombokminer_block_hash(
    header_80: *const u8,
    out: *mut u8,
) -> i32 {
    if header_80.is_null() || out.is_null() {
        return -1;
    }

    let header = unsafe { slice::from_raw_parts(header_80, 80) };
    let hash = lombokminer_core::hash::sha256d(header);

    unsafe {
        std::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32);
    }
    0
}

// ─── Difficulty ─────────────────────────────────────────────────────────────

/// Compute difficulty from compact target (nBits).
///
/// # Parameters
/// - `nbits`: compact target encoding (e.g., 0x1d00ffff for difficulty 1)
///
/// # Returns
/// The difficulty as a double.
#[no_mangle]
pub extern "C" fn lombokminer_difficulty(nbits: u32) -> f64 {
    lombokminer_core::mining::difficulty_from_nbits(nbits)
}

/// Check if a hash (32 bytes, internal byte order) meets a target.
///
/// # Parameters
/// - `hash`: pointer to 32-byte hash
/// - `nbits`: compact target
///
/// # Returns
/// 1 if hash meets target, 0 if not, -1 on null pointer.
#[no_mangle]
pub extern "C" fn lombokminer_check_target(
    hash: *const u8,
    nbits: u32,
) -> i32 {
    if hash.is_null() {
        return -1;
    }

    let h: [u8; 32] = unsafe {
        slice::from_raw_parts(hash, 32).try_into().unwrap()
    };

    let target = lombokminer_core::mining::Target::from_nbits(nbits);
    if target.check_hash(&h) { 1 } else { 0 }
}

// ─── Mining ─────────────────────────────────────────────────────────────────

/// Mine a nonce range on CPU. Returns the winning nonce or -1 if exhausted.
///
/// # Parameters
/// - `header_80`: pointer to 80-byte block header (nonce field will be used as template)
/// - `nbits`: compact target
/// - `nonce_start`: first nonce to try
/// - `nonce_end`: last nonce (exclusive)
/// - `threads`: number of CPU threads (0 = auto)
/// - `out_hash`: pointer to 32-byte buffer for the winning hash (filled on success)
///
/// # Returns
/// The winning nonce (>= 0), or -1 if not found, -2 on error.
#[no_mangle]
pub extern "C" fn lombokminer_mine_cpu(
    header_80: *const u8,
    nbits: u32,
    nonce_start: u32,
    nonce_end: u32,
    threads: u32,
    out_hash: *mut u8,
) -> i64 {
    if header_80.is_null() || out_hash.is_null() {
        return -2;
    }

    let header_bytes: [u8; 80] = unsafe {
        slice::from_raw_parts(header_80, 80).try_into().unwrap()
    };

    let header = lombokminer_core::block::BlockHeader::deserialize(&header_bytes);
    let target = lombokminer_core::mining::Target::from_nbits(nbits);

    let t = if threads == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        threads as usize
    };

    let miner = lombokminer_hal::CpuMiner::new(lombokminer_hal::CpuConfig {
        threads: t,
        core_affinity: false,
    });

    use lombokminer_hal::MiningDevice;
    match miner.submit_work(&header, &target, nonce_start, nonce_end) {
        Ok(result) => match result.result {
            lombokminer_core::mining::MineResult::Found { nonce, hash } => {
                unsafe {
                    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
                }
                nonce as i64
            }
            lombokminer_core::mining::MineResult::Exhausted => -1,
        },
        Err(_) => -2,
    }
}

// ─── Wallet Validation ──────────────────────────────────────────────────────

/// Validate a Bitcoin address.
///
/// # Parameters
/// - `address`: pointer to null-terminated UTF-8 string
///
/// # Returns
/// 0 = valid mainnet, 1 = valid testnet, 2 = valid regtest, -1 = invalid, -2 = null pointer.
#[no_mangle]
pub extern "C" fn lombokminer_validate_address(address: *const std::ffi::c_char) -> i32 {
    if address.is_null() {
        return -2;
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(address) };
    let addr = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match lombokminer_security::validate_address(addr) {
        Ok(v) => match v.network {
            lombokminer_security::Network::Mainnet => 0,
            lombokminer_security::Network::Testnet => 1,
            lombokminer_security::Network::Regtest => 2,
        },
        Err(_) => -1,
    }
}

// ─── Self-test ──────────────────────────────────────────────────────────────

/// Run the SHA-256d self-test (genesis block hash verification).
///
/// # Returns
/// 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn lombokminer_selftest() -> i32 {
    match lombokminer_core::hash::self_test() {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_version() {
        let ptr = lombokminer_version();
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert_eq!(s.to_str().unwrap(), "1.0.0");
    }

    #[test]
    fn test_ffi_sha256d() {
        let data = b"hello";
        let mut out = [0u8; 32];
        let ret = lombokminer_sha256d(data.as_ptr(), data.len(), out.as_mut_ptr());
        assert_eq!(ret, 0);
        assert_ne!(out, [0u8; 32]);

        // Verify against Rust API
        let expected = lombokminer_core::hash::sha256d(b"hello");
        assert_eq!(out, expected);
    }

    #[test]
    fn test_ffi_sha256d_null() {
        let mut out = [0u8; 32];
        assert_eq!(lombokminer_sha256d(std::ptr::null(), 0, out.as_mut_ptr()), -1);
        assert_eq!(lombokminer_sha256d(b"x".as_ptr(), 1, std::ptr::null_mut()), -1);
    }

    #[test]
    fn test_ffi_midstate_roundtrip() {
        let mut header = [0u8; 80];
        for (i, b) in header.iter_mut().enumerate() { *b = i as u8; }

        let mut midstate = [0u32; 8];
        let ret = lombokminer_sha256_midstate(header[..64].as_ptr(), midstate.as_mut_ptr());
        assert_eq!(ret, 0);

        let mut hash_ffi = [0u8; 32];
        let ret = lombokminer_sha256d_from_midstate(
            midstate.as_ptr(), header[64..].as_ptr(), hash_ffi.as_mut_ptr()
        );
        assert_eq!(ret, 0);

        let hash_rust = lombokminer_core::hash::sha256d(&header);
        assert_eq!(hash_ffi, hash_rust);
    }

    #[test]
    fn test_ffi_block_hash() {
        // Genesis block
        let header = hex::decode(concat!(
            "01000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49", "ffff001d", "1dac2b7c"
        )).unwrap();

        let mut out = [0u8; 32];
        let ret = lombokminer_block_hash(header.as_ptr(), out.as_mut_ptr());
        assert_eq!(ret, 0);

        let mut display = out;
        display.reverse();
        assert_eq!(
            hex::encode(display),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn test_ffi_difficulty() {
        let diff = lombokminer_difficulty(0x1d00ffff);
        assert!((diff - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_ffi_check_target() {
        let zero = [0u8; 32];
        assert_eq!(lombokminer_check_target(zero.as_ptr(), 0x1d00ffff), 1);

        let max = [0xFFu8; 32];
        assert_eq!(lombokminer_check_target(max.as_ptr(), 0x1d00ffff), 0);
    }

    #[test]
    fn test_ffi_mine_cpu() {
        let header = lombokminer_core::block::BlockHeader {
            version: 0x20000000, prev_block: [0xAB; 32], merkle_root: [0xCD; 32],
            timestamp: 1700000000, bits: 0x207fffff, nonce: 0,
        };
        let serialized = header.serialize();
        let mut out_hash = [0u8; 32];

        let nonce = lombokminer_mine_cpu(
            serialized.as_ptr(), 0x207fffff, 0, 100_000, 1, out_hash.as_mut_ptr()
        );

        assert!(nonce >= 0, "Should find nonce with easy target");
        assert_ne!(out_hash, [0u8; 32]);
    }

    #[test]
    fn test_ffi_validate_address() {
        let addr = std::ffi::CString::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(lombokminer_validate_address(addr.as_ptr()), 0); // mainnet

        let bad = std::ffi::CString::new("not_valid").unwrap();
        assert_eq!(lombokminer_validate_address(bad.as_ptr()), -1);

        assert_eq!(lombokminer_validate_address(std::ptr::null()), -2);
    }

    #[test]
    fn test_ffi_selftest() {
        assert_eq!(lombokminer_selftest(), 0);
    }
}
