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
