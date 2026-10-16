#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_core::device::{DeviceType, parse};

fuzz_target!(|data: &[u8]| {
    // TUN frame parsing runs on the hot path over untrusted tunnel traffic;
    // it must never panic on arbitrary bytes.
    let _ = parse(&DeviceType::Tun, data);
});
