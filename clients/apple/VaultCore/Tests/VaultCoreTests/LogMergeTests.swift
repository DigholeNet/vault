//
//  LogMergeTests.swift
//  VaultCore
//
//

import Foundation
import Testing
@testable import VaultCore

@Test func mergeByTimestamp() {
    let app = """
    [2026-10-23 13:26:22.702Z] [NOTICE] [app] connect() starting
    [2026-10-23 13:26:25.790Z] [NOTICE] [app] VPN status: connecting -> on
    """
    let ne = """
    [2026-10-23 13:26:23.000Z] [NOTICE] [ne] startTunnel #1
    [2026-10-23 13:26:44.660Z] [NOTICE] [ne] [probe] tcp ok
    """
    let merged = FileLogger.mergeChronologically([app, ne])
    #expect(
        merged == """
        [2026-10-23 13:26:22.702Z] [NOTICE] [app] connect() starting
        [2026-10-23 13:26:23.000Z] [NOTICE] [ne] startTunnel #1
        [2026-10-23 13:26:25.790Z] [NOTICE] [app] VPN status: connecting -> on
        [2026-10-23 13:26:44.660Z] [NOTICE] [ne] [probe] tcp ok
        """
    )
}

@Test func mergeDropsEmptyLines() {
    let merged = FileLogger.mergeChronologically(["[2026-10-23 13:00:00.000Z] a\n\n", ""])
    #expect(merged == "[2026-10-23 13:00:00.000Z] a")
}

@Test func clearQueuedLogs() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let logger = try FileLogger(logDirectory: directory)
    logger.logSync("previous session")
    logger.rotateForNewSession()
    logger.log("queued before clear")
    try logger.clearLogs()
    for name in ["vault.log", "vault.prev.log"] {
        let bytes = try Data(contentsOf: directory.appendingPathComponent(name))
        #expect(bytes.isEmpty)
    }
    #expect(logger.readLog() == "")
    logger.logSync("new event")
    #expect(logger.readLog()?.contains("new event") == true)
    #expect(logger.readLog()?.contains("queued before clear") == false)
}

@Test func providerTraceMetadata() throws {
    let request = ProviderCommandEnvelope(.clearLogs, token: "clear-test")
    let traced = try request.encoded(requestID: "request-test", trace: true)
    let envelope = try ProviderCommandEnvelope.decode(traced)
    #expect(envelope.command == .clearLogs)
    #expect(envelope.token == "clear-test")
    #expect(envelope.requestID == "request-test")
    #expect(envelope.trace == true)
    let status = try ProviderCommandEnvelope(.status).encoded(requestID: "unused", trace: true)
    #expect(status.isEmpty)
    #expect(try ProviderCommandEnvelope.decode(status).command == .status)
}

@Test func providerEnvelopeCompatibility() throws {
    let old = try ProviderCommandEnvelope.decode(Data(#"{"command":"logs","futureOption":7}"#.utf8))
    #expect(old.requestID == nil && old.trace == nil && old.token == nil)
    let data = try ProviderCommandEnvelope(.logs).encoded(requestID: "poll-test", trace: false)
    let new = try ProviderCommandEnvelope.decode(data)
    #expect(new.command == .logs && new.trace == false && new.requestID == "poll-test")
    #expect(throws: (any Error).self) { try ProviderCommandEnvelope.decode(Data([0xff])) }
    #expect(throws: (any Error).self) {
        try ProviderCommandEnvelope.decode(Data(#"{"command":"unknown"}"#.utf8))
    }
}

@Test func providerProbeCompatibility() throws {
    let probe = Data(#"{"run":"probe-test","id":42}"#.utf8)
    let encoded = try ProviderCommandEnvelope(.diagnosticProbe, payload: probe)
        .encoded(requestID: "request-test", trace: false)
    let fields = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    #expect(fields["command"] as? String == "diagnosticProbe")
    #expect(fields["payload"] as? String == probe.base64EncodedString())
    #expect(try ProviderCommandEnvelope.decode(encoded).payload == probe)
}
