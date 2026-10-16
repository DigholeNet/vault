// SPDX-License-Identifier: MIT
// Vault - Peer-to-Peer VPN

fn main() {
    prost_build::compile_protos(&["proto/protocol.proto"], &["proto/"]).unwrap();
}
