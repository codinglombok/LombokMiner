//! Fuzz SHA-256d: must never panic on any input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lombokminer_core::hash::sha256d(data);
});
