// SPDX-License-Identifier: MIT
import Foundation
import Testing
@testable import VaultCore

struct TunnelWriteMetricsTests {
    @Test func windowStats() throws {
        let metrics = TunnelWriteMetrics(startedAt: 0)
        metrics.record(packets: 1, bytes: 100, succeeded: true, durationNanoseconds: 1_000_000)
        metrics.record(packets: 2, bytes: 300, succeeded: false, durationNanoseconds: 3_000_000)
        #expect(metrics.takeReport(at: 4_999_999_999) == nil)

        // A busy main queue or sleep must retain the true report interval.
        let report = try #require(metrics.takeReport(at: 8_000_000_000))
        #expect(report.elapsedSeconds == 8)
        #expect(report.calls == 2)
        #expect(report.submittedPackets == 3)
        #expect(report.submittedBytes == 400)
        #expect(report.meanPacketsPerCall == 1.5 && report.maxPacketsPerCall == 2)
        #expect(report.failedCalls == 1)
        #expect(report.failedPackets == 2)
        #expect(report.meanDurationMilliseconds == 2)
        #expect(report.maxDurationMilliseconds == 3)
        #expect(metrics.takeReport(at: 13_000_000_000) == nil)

        // Drained failures and the old maximum must not leak into a new window.
        metrics.record(packets: 1, bytes: 50, succeeded: true, durationNanoseconds: 500_000)
        let next = try #require(metrics.takeReport(at: 18_000_000_000))
        #expect(next.elapsedSeconds == 5)
        #expect(next.calls == 1)
        #expect(next.meanPacketsPerCall == 1 && next.maxPacketsPerCall == 1)
        #expect(next.failedCalls == 0 && next.failedPackets == 0)
        #expect(next.meanDurationMilliseconds == 0.5 && next.maxDurationMilliseconds == 0.5)
    }

    @Test func sessionIsolation() throws {
        let oldSession = TunnelWriteMetrics(startedAt: 0)
        oldSession.record(packets: 1, bytes: 100, succeeded: true, durationNanoseconds: 25)
        let final = try #require(oldSession.takeReport(at: 1_000_000_000, force: true))
        #expect(final.calls == 1 && final.elapsedSeconds == 1)
        #expect(oldSession.takeReport(at: 1_000_000_000, force: true) == nil)

        let replacement = TunnelWriteMetrics(startedAt: 1_000_000_000)
        // The old Edge callback retains the old metrics object after stop.
        oldSession.record(packets: 1, bytes: 100, succeeded: false, durationNanoseconds: 25)
        replacement.record(packets: 1, bytes: 200, succeeded: true, durationNanoseconds: 50)
        let report = try #require(replacement.takeReport(at: 6_000_000_000))
        #expect(report.calls == 1 && report.submittedBytes == 200 && report.failedCalls == 0)
    }

    @Test func concurrentUpdates() throws {
        let metrics = TunnelWriteMetrics(startedAt: 0)
        let reports = CollectedWriteReports()
        DispatchQueue.concurrentPerform(iterations: 4_000) { index in
            if index.isMultiple(of: 4) {
                if let report = metrics.takeReport(at: 1_000_000_000, force: true) {
                    reports.append(report)
                }
            } else {
                metrics.record(packets: 1, bytes: 100, succeeded: index.isMultiple(of: 2), durationNanoseconds: 20)
            }
        }
        if let final = metrics.takeReport(at: 2_000_000_000, force: true) { reports.append(final) }
        let all = reports.values
        #expect(all.reduce(0) { $0 + $1.calls } == 3_000)
        #expect(all.reduce(0) { $0 + $1.submittedPackets } == 3_000)
        #expect(all.reduce(0) { $0 + $1.submittedBytes } == 300_000)
        #expect(all.reduce(0) { $0 + $1.failedCalls } == 2_000)
        #expect(all.reduce(0) { $0 + $1.failedPackets } == 2_000)
        #expect(all.reduce(0) { $0 + $1.durationNanoseconds } == 60_000)
    }
}

private final class CollectedWriteReports: @unchecked Sendable {
    private let lock = NSLock()
    private var reports: [TunnelWriteMetrics.Report] = []

    func append(_ report: TunnelWriteMetrics.Report) {
        lock.lock()
        defer { lock.unlock() }
        reports.append(report)
    }

    var values: [TunnelWriteMetrics.Report] {
        lock.lock()
        defer { lock.unlock() }
        return reports
    }
}
