@testable import Vault
import VaultCore
import XCTest

final class DiagnosticsPresentationTests: XCTestCase {
    private func snapshot() -> DiagnosticSnapshot {
        let request = DiagnosticRequest(
            id: 42,
            sessionId: 7,
            stage: .https,
            scope: .tunnel,
            domain: "example.com",
            deadlineMs: 1000,
            operation: .https(address: "192.0.2.1", port: 443)
        )
        let probe = DiagnosticProbe(
            request: request,
            durationMs: 12,
            succeeded: true,
            errorKind: nil,
            detail: "HTTP/1.1 200 OK",
            tlsDurationMs: 0
        )
        let check = DiagnosticCheck(
            stage: .https,
            passed: 1,
            attempted: 1,
            state: .passed,
            durationMs: 12,
            sampleCount: 1
        )
        return DiagnosticSnapshot(
            sessionId: 7,
            domains: ["example.com"],
            running: false,
            cancelled: false,
            activeStage: nil,
            state: .passed,
            durationMs: 12,
            plannedChecks: [.https],
            checks: [check],
            probes: [probe],
            routeIssues: [],
            routeUnavailable: [],
            domainStates: [DiagnosticDomainState(
                domain: "example.com",
                state: .passed
            )]
        )
    }

    func testNativeSnapshotPresentation() throws {
        let native = snapshot()
        let result = DiagnosticsResult(snapshot: native)
        XCTAssertTrue(DiagnosticsPresentation.passed(result))
        XCTAssertEqual(result.summary, "OK")
        XCTAssertEqual(DiagnosticsPresentation.domainState(result, domain: "example.com"), .passed)
        XCTAssertEqual(result.checks, native.checks)
        XCTAssertEqual(DiagnosticsPresentation.visibleChecks(result), ["https"])
        let probe = try XCTUnwrap(result.probes?.first)
        XCTAssertEqual(probe.id, 42)
        XCTAssertEqual(probe.stage, "https")
        XCTAssertEqual(probe.domain, "example.com")
        XCTAssertEqual(probe.displayDetail, "192.0.2.1:443 · HTTP/1.1 200 OK")
        XCTAssertEqual(probe.tlsDurationMs, 0)
        XCTAssertTrue(result.lines.contains { $0.contains("duration=12ms") })
    }

    func testInvalidatedVerdictRetainsRustObservations() {
        let native = snapshot()
        var result = DiagnosticsResult(snapshot: native)
        result.message = "INCOMPLETE - tunnel session changed; run diagnostics again"
        XCTAssertTrue(DiagnosticsPresentation.incomplete(result))
        XCTAssertFalse(DiagnosticsPresentation.passed(result))
        XCTAssertEqual(result.snapshot, native)
        XCTAssertEqual(result.checks, native.checks)
        XCTAssertEqual(result.probes, native.probes)
        XCTAssertFalse(result.lines.isEmpty)
    }

    func testEngineErrorPresentationWithoutSnapshot() {
        let result = DiagnosticsResult(message: "INCOMPLETE - Rust diagnostics: unavailable")
        XCTAssertTrue(DiagnosticsPresentation.incomplete(result))
        XCTAssertNil(result.snapshot)
        XCTAssertTrue(result.lines.isEmpty)
        XCTAssertTrue(result.summary.contains("unavailable"))
    }

    func testRunningCancelledAndRouteIssueSummaries() {
        var native = snapshot()
        native.running = true
        XCTAssertEqual(DiagnosticsResult(snapshot: native).summary, "RUNNING")
        native.cancelled = true
        XCTAssertEqual(DiagnosticsResult(snapshot: native).summary, "INCOMPLETE - diagnostics cancelled or tunnel session changed")
        native.running = false
        native.cancelled = false
        native.state = .failed
        native.routeIssues = ["wrong route"]
        let result = DiagnosticsResult(snapshot: native)
        XCTAssertEqual(result.summary, "PROBLEMS FOUND - wrong route")
        XCTAssertTrue(result.lines.contains("[probe] route: wrong route"))
    }

    func testSessionClockBounds() {
        XCTAssertEqual(DiagnosticsPresentation.connectionDuration(-5), "00:00:00")
        XCTAssertEqual(DiagnosticsPresentation.connectionDuration(1476.9), "00:24:36")
        XCTAssertEqual(DiagnosticsPresentation.connectionDuration(90061), "25:01:01")
    }

    func testLogSearchFilters() {
        let text = "[app] HTTPS ready\n[ne] DNS ready\n[ne] HTTPS failed"
        XCTAssertEqual(DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "https"), "[ne] HTTPS failed")
        XCTAssertEqual(
            DiagnosticsPresentation.filteredLogs(text, source: "all", search: "ready"),
            "[app] HTTPS ready\n[ne] DNS ready"
        )
        XCTAssertTrue(DiagnosticsPresentation.filteredLogs(text, source: "app", search: "DNS").isEmpty)
    }

    func testTunnelLogFilterIncludesCoreFailures() {
        let text = "[app] ready\n[ne] start\n[rust] handshake failed\n[rust] PANIC"
        XCTAssertEqual(
            DiagnosticsPresentation.filteredLogs(text, source: "ne", search: ""),
            "[ne] start\n[rust] handshake failed\n[rust] PANIC"
        )
        XCTAssertEqual(DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "HANDSHAKE"), "[rust] handshake failed")
        XCTAssertEqual(DiagnosticsPresentation.filteredLogs(text, source: "app", search: ""), "[app] ready")
    }
}

extension DiagnosticsPresentationTests {
    func testFormatBytes() {
        XCTAssertEqual(PacketStats.formatBytes(0), "0.00 B")
        XCTAssertEqual(PacketStats.formatBytes(1024), "1.00 KB")
        XCTAssertEqual(PacketStats.formatBytes(1536), "1.50 KB")
    }
}
