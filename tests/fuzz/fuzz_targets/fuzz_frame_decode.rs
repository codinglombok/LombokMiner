//! Fuzz SV2 frame decoder: must never panic on arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut decoder = lombokminer_net::stratum_v2::FrameDecoder::new();
    decoder.feed(data);
    let _ = decoder.decode_all();
});
