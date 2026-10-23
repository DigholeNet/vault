//
//  LogMergeTests.swift
//  VaultCore
//
//

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
