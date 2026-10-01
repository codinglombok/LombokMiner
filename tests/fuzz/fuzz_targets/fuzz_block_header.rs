//! Fuzz block header: deserialize + hash must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 80 {
        let header_bytes: [u8; 80] = data[..80].try_into().unwrap();
        let header = lombokminer_core::block::BlockHeader::deserialize(&header_bytes);
        let _ = header.hash();
        let _ = header.serialize();
    }
});
