//
//  GlueTests.swift
//  VaultCore
//
//
//  Tests for the platform glue layer. The VPN core itself (vault-core)
//  is covered by its own Rust tests.
//

import Testing
import Darwin

@testable import VaultCore

@Test func hexDecoding() {
    #expect([UInt8](hex: "00ff10") == [0x00, 0xFF, 0x10])
    #expect([UInt8](hex: "0x00ff") == [0x00, 0xFF])
    #expect([UInt8](hex: "a") == [0x0A])
    #expect([UInt8](hex: "zz") == nil)
    #expect([UInt8](hex: "") == [])
}

@Test func edgeConfig() {
    let config = EdgeConfig(password: "pw", host: "example.com", port: 9527)
    #expect(config.port == 9527)
}

@Test func formatBytes() {
    #expect(PacketStats.formatBytes(0) == "0.00 B")
    #expect(PacketStats.formatBytes(1024) == "1.00 KB")
    #expect(PacketStats.formatBytes(1536) == "1.50 KB")
}
