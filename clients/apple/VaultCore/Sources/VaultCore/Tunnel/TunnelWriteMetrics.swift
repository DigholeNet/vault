// SPDX-License-Identifier: MIT
import Foundation

/// One provider session's TUN write measurements. Rust callbacks record on
/// worker threads; the provider's existing timer drains a window on main.
/// No formatting, logging or allocation occurs while recording a write.
public final class TunnelWriteMetrics: @unchecked Sendable {
    public struct Report: Sendable {
        public let elapsedSeconds: Double
        public let calls: UInt64
        public let submittedPackets: UInt64
        public let submittedBytes: UInt64
        public let maxPacketsPerCall: UInt64
        public let failedCalls: UInt64
        /// Packets submitted in calls that returned false; not a measured
        /// end-to-end packet loss count.
        public let failedPackets: UInt64
        public let durationNanoseconds: UInt64
        public let maxDurationNanoseconds: UInt64

        public var meanPacketsPerCall: Double {
            calls == 0 ? 0 : Double(submittedPackets) / Double(calls)
        }

        public var meanDurationMilliseconds: Double {
            calls == 0 ? 0 : Double(durationNanoseconds) / Double(calls) / 1_000_000
        }

        public var maxDurationMilliseconds: Double {
            Double(maxDurationNanoseconds) / 1_000_000
        }
    }

    private struct Window {
        var calls: UInt64 = 0
        var submittedPackets: UInt64 = 0
        var submittedBytes: UInt64 = 0
        var maxPacketsPerCall: UInt64 = 0
        var failedCalls: UInt64 = 0
        var failedPackets: UInt64 = 0
        var durationNanoseconds: UInt64 = 0
        var maxDurationNanoseconds: UInt64 = 0
    }

    private let lock = NSLock()
    private var window = Window()
    private var startedAt: UInt64
    private static let healthyReportIntervalNanoseconds: UInt64 = 30_000_000_000
    private static let failureReportIntervalNanoseconds: UInt64 = 5_000_000_000

    public init(startedAt: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        self.startedAt = startedAt
    }

    /// Counts submitted packets separately from failed calls. A successful
    /// system API return is not an acknowledgement from the receiving app.
    public func record(packets: Int, bytes: Int, succeeded: Bool, durationNanoseconds: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        window.calls += 1
        let packetCount = UInt64(max(0, packets))
        window.submittedPackets += packetCount
        window.maxPacketsPerCall = max(window.maxPacketsPerCall, packetCount)
        window.submittedBytes += UInt64(max(0, bytes))
        if !succeeded {
            window.failedCalls += 1
            window.failedPackets += packetCount
        }
        window.durationNanoseconds += durationNanoseconds
        window.maxDurationNanoseconds = max(window.maxDurationNanoseconds, durationNanoseconds)
    }

    /// Healthy traffic is summarized every thirty seconds; failed writes
    /// use a five-second minimum reporting interval. Counters remain intact
    /// between reports, including traffic preceding a failure.
    /// Empty windows produce no log record; force flushes a final window.
    public func takeReport(at now: UInt64 = DispatchTime.now().uptimeNanoseconds, force: Bool = false) -> Report? {
        lock.lock()
        defer { lock.unlock() }
        let elapsed = now >= startedAt ? now - startedAt : 0
        let interval = window.failedCalls > 0
            ? Self.failureReportIntervalNanoseconds : Self.healthyReportIntervalNanoseconds
        guard force || elapsed >= interval else { return nil }
        defer {
            window = Window()
            startedAt = now
        }
        guard window.calls > 0 else { return nil }
        return Report(
            elapsedSeconds: Double(elapsed) / 1_000_000_000,
            calls: window.calls,
            submittedPackets: window.submittedPackets,
            submittedBytes: window.submittedBytes,
            maxPacketsPerCall: window.maxPacketsPerCall,
            failedCalls: window.failedCalls,
            failedPackets: window.failedPackets,
            durationNanoseconds: window.durationNanoseconds,
            maxDurationNanoseconds: window.maxDurationNanoseconds
        )
    }
}
