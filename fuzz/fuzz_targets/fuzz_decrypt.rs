#![no_main]

use std::io::Write as _;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use vault_core::{AlgorithmType, Buffer, CryptoCore, Role, create_ecdh_keypair};

// A fixed session receiver; decrypt must reject arbitrary ciphertext with an
// error, never a panic.
static RECEIVER: LazyLock<CryptoCore> = LazyLock::new(|| {
    let (_sender_priv, sender_pub) = create_ecdh_keypair().unwrap();
    let (receiver_priv, _receiver_pub) = create_ecdh_keypair().unwrap();
    CryptoCore::new(
        receiver_priv,
        &AlgorithmType::Aes128Gcm,
        sender_pub.bytes(),
        Role::Responder,
        b"fuzz-pake-key",
    )
    .unwrap()
});

fuzz_target!(|data: &[u8]| {
    let mut buf = Buffer::new(0);
    if buf.write_all(data).is_ok() {
        let _ = RECEIVER.decrypt(&mut buf);
    }
});
