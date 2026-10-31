// SPDX-License-Identifier: MIT
// Vault - shared VPN protocol core

fn main() {
    prost_build::compile_protos(&["proto/protocol.proto"], &["proto/"]).unwrap();
}
