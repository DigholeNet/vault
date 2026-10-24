//
//  LogMergeTests.swift
//  VaultCore
//
//

import Foundation
import Testing

@testable import VaultCore

@Test func mergeChronologicallyInterleavesByTimestamp() {
    let app = """
        [2026-10-23 13:26:22.702] [NOTICE] [app] connect() starting
        [2026-10-23 13:26:25.790] [NOTICE] [app] VPN status: connecting -> on
        """
    let ne = """
        [2026-10-23 13:26:23.000] [NOTICE] [ne] startTunnel #1
        [2026-10-23 13:26:44.660] [NOTICE] [ne] [probe] tcp ok
        """
    let merged = FileLogger.mergeChronologically([app, ne])
    #expect(
        merged == """
            [2026-10-23 13:26:22.702] [NOTICE] [app] connect() starting
            [2026-10-23 13:26:23.000] [NOTICE] [ne] startTunnel #1
            [2026-10-23 13:26:25.790] [NOTICE] [app] VPN status: connecting -> on
            [2026-10-23 13:26:44.660] [NOTICE] [ne] [probe] tcp ok
            """
    )
}

@Test func mergeChronologicallyDropsEmptyLines() {
    let merged = FileLogger.mergeChronologically(["[2026-10-23 13:00:00.000] a\n\n", ""])
    #expect(merged == "[2026-10-23 13:00:00.000] a")
}

@Test func mergeConvertsLegacyLocalTimeAndKeepsEqualTimestampOrder() throws {
    let shanghai = try #require(TimeZone(secondsFromGMT: 8 * 3600))
    let app = """
        [2026-10-24 16:00:00.000] [NOTICE] [app] z-first
        [2026-10-24 16:00:00.000] [ERROR] [app] a-second
        [2026-10-24 08:00:02.000Z] [NOTICE] [app] new UTC format
        """
    let rust = "[2026-10-24 08:00:01.000Z] [rust] handshake"
    let merged = FileLogger.mergeChronologically([app, rust], legacyTimeZone: shanghai)
    #expect(merged.split(separator: "\n").map(String.init) == [
        "[2026-10-24 16:00:00.000] [NOTICE] [app] z-first",
        "[2026-10-24 16:00:00.000] [ERROR] [app] a-second",
        rust,
        "[2026-10-24 08:00:02.000Z] [NOTICE] [app] new UTC format"
    ])
}

@Test func mergeRepairsDuplicatedTimestampBracketsInsteadOfPinningOldRecordsLast() {
    let text = """
        [2026-10-24 11:08:08.000Z] [DEBUG] [ne] alive
        [[2026-10-24 10:58:28.234Z] [NOTICE] [ne] [session:first] Init edge successfully
        [[2026-10-24 10:58:38.306Z] [NOTICE] [ne] [session:second] Init edge successfully
        """
    let lines = FileLogger.mergeChronologically([text]).split(separator: "\n")
    #expect(lines.count == 3)
    #expect(lines[0].hasPrefix("[2026-10-24 10:58:28.234Z]"))
    #expect(lines[1].hasPrefix("[2026-10-24 10:58:38.306Z]"))
    #expect(lines[2].hasSuffix("alive"))
}

@Test func mergeNormalizesLegacyRustSeverityWithoutChangingMessage() {
    let log = "[2026-10-24 11:07:49.001Z] [rust]  INFO Heartbeat ping sent"
    #expect(FileLogger.mergeChronologically([log]) ==
        "[2026-10-24 11:07:49.001Z] [INFO] [rust] Heartbeat ping sent")
    let warning = "[2026-10-24 11:07:49.001Z] [rust]  WARN No route to host"
    #expect(FileLogger.mergeChronologically([warning]).contains("[WARNING] [rust] No route to host"))
}

@Test func swiftRecordsUseUTCAndPrefixEveryMessageLine() {
    let record = FileLogger.formattedRecord("first\nsecond", level: "WARN", source: "ne",
        timestamp: Date(timeIntervalSince1970: 0))
    #expect(record == "[1970-01-01 00:00:00.000Z] [WARNING] [ne] first\n" +
        "[1970-01-01 00:00:00.000Z] [WARNING] [ne] second\n")
}

@Test func clearingLogsTruncatesBothFilesAndDrainsQueuedWrites() throws {
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
