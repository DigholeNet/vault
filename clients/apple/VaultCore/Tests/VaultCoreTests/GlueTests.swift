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

@Test func unreachableErrorsFailStartImmediately() {
    for code in [ENETDOWN, ENETUNREACH, EHOSTDOWN, EHOSTUNREACH] {
        #expect(Edge.isNetworkUnreachable("IO error: unreachable (os error \(code))"))
    }
    #expect(!Edge.isNetworkUnreachable("IO error: timeout (os error \(ETIMEDOUT))"))
    #expect(!Edge.isNetworkUnreachable("Handshake failed: timeout"))
    #expect(!Edge.isNetworkUnreachable("IO error: connection refused (os error \(ECONNREFUSED))"))
    #expect(!Edge.isNetworkUnreachable("Internal error: unreachable (os error \(EHOSTUNREACH))"))
}

@Test func handshakeFailuresFailStartImmediately() {
    #expect(Edge.isHandshakeFailure("Handshake failed: handshake response timeout"))
    #expect(Edge.isHandshakeFailure("Handshake failed: response not bound to this handshake request"))
    #expect(!Edge.isHandshakeFailure("IO error: unreachable (os error \(ENETUNREACH))"))
    #expect(!Edge.isHandshakeFailure("heartbeat timeout"))
    #expect(!Edge.isHandshakeFailure("session rejected by server"))
}

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
