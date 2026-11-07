//
//  GlueTests.swift
//  VaultCore
//
//
//  Tests for the platform glue layer. The VPN core itself (vault-core)
//  is covered by its own Rust tests.
//

import Darwin
import Foundation
import Testing
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

struct TunnelPacketWriterTests {
    @Test func mixedBatch() throws {
        let metrics = TunnelWriteMetrics(startedAt: 0)
        let ipv6 = Data([0xFF, 0x60, 0x12, 0x34]).dropFirst()
        #expect(ipv6.startIndex != 0)
        let packets = [Data([0x45, 0x01]), ipv6, Data(), Data([0x10, 0x02])]
        var callbackCalls = 0
        var writeCalls = 0
        let callbacks = Edge.Callbacks(
            onPackets: { batch in
                callbackCalls += 1
                TunnelPacketWriter.write(batch, metrics: metrics) { written, protocols in
                    writeCalls += 1
                    #expect(written == packets)
                    #expect(protocols.map(\.int32Value) == [AF_INET, AF_INET6, AF_INET, AF_INET])
                    return true
                }
            },
            onIpAssigned: { _, _, _, _ in }
        )

        callbacks.onDataBatch(packets: packets)
        // Delivery and the system write finish before the core callback returns.
        #expect(callbackCalls == 1 && writeCalls == 1)
        let report = try #require(metrics.takeReport(at: 5_000_000_000))
        #expect(report.calls == 1 && report.submittedPackets == 4)
        #expect(report.submittedBytes == 7)
        #expect(report.failedCalls == 0 && report.failedPackets == 0)
    }

    @Test func immediateWrite() throws {
        let metrics = TunnelWriteMetrics(startedAt: 0)
        let packet = Data([0x45, 0xAB, 0xCD])
        var writes: [[Data]] = []
        let callbacks = Edge.Callbacks(
            onPackets: { batch in
                TunnelPacketWriter.write(batch, metrics: metrics) { packets, protocols in
                    #expect(protocols.map(\.int32Value) == [AF_INET])
                    writes.append(packets)
                    return true
                }
            },
            onIpAssigned: { _, _, _, _ in }
        )

        callbacks.onDataBatch(packets: [])
        #expect(writes.isEmpty)
        #expect(metrics.takeReport(at: 0, force: true) == nil)

        callbacks.onDataBatch(packets: [packet])
        #expect(writes == [[packet]])
        let report = try #require(metrics.takeReport(at: 0, force: true))
        #expect(report.calls == 1 && report.submittedPackets == 1)
        #expect(report.submittedBytes == 3)
    }

    @Test func failedBatch() throws {
        let metrics = TunnelWriteMetrics(startedAt: 0)
        let packets = [Data([0x45, 0x01]), Data([0x60, 0x02, 0x03])]
        var writeCalls = 0
        TunnelPacketWriter.write(packets, metrics: metrics) { written, protocols in
            writeCalls += 1
            #expect(written == packets)
            #expect(protocols.map(\.int32Value) == [AF_INET, AF_INET6])
            return false
        }

        // A failed submission is not retried as individual packets.
        #expect(writeCalls == 1)
        let report = try #require(metrics.takeReport(at: 5_000_000_000))
        #expect(report.calls == 1 && report.submittedPackets == 2)
        #expect(report.submittedBytes == 5)
        #expect(report.failedCalls == 1 && report.failedPackets == 2)
    }
}
