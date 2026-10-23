#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Handshake messages arrive unauthenticated from the network; the parser
    // must never panic on arbitrary bytes.
    let _ = vault_core::protocol::parse_handshake(data);
});
