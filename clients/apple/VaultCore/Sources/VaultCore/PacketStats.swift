// SPDX-License-Identifier: MIT
import Foundation

/// In-memory provider snapshots. Both apps read them through provider status IPC.
public enum PacketStats {
    public struct Stats: Codable, Sendable {
        public var packetsSent: UInt64 = 0
        public var packetsReceived: UInt64 = 0
        public var bytesSent: UInt64 = 0
        public var bytesReceived: UInt64 = 0
        public var bytesSentPerSecond: UInt64 = 0
        public var bytesReceivedPerSecond: UInt64 = 0

        public static var zero: Stats { Stats() }
        public init() {}

        public init(_ core: TrafficStats) {
            packetsSent = UInt64(max(0, core.packetsSent))
            packetsReceived = UInt64(max(0, core.packetsReceived))
            bytesSent = UInt64(max(0, core.bytesSent))
            bytesReceived = UInt64(max(0, core.bytesReceived))
            bytesSentPerSecond = UInt64(max(0, core.sendSpeed))
            bytesReceivedPerSecond = UInt64(max(0, core.receiveSpeed))
        }
    }

    /// Owns the identity and counters together. Ending a session invalidates
    /// queued status reads; cancellation tokens never identify traffic totals.
    public struct Session {
        private var id: String?
        private var stats: Stats = .zero

        public init() {}

        public mutating func begin() {
            id = UUID().uuidString
            stats = .zero
        }

        public mutating func end() {
            id = nil
            stats = .zero
        }

        public mutating func update(_ stats: Stats) {
            guard id != nil else { return }
            self.stats = stats
        }

        public func status(ip: String) -> ProviderStatus? {
            guard let id else { return nil }
            return ProviderStatus(ip: ip, stats: stats, session: id)
        }
    }

    public static func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var unitIndex = 0

        while value >= 1024 && unitIndex < units.count - 1 {
            value /= 1024
            unitIndex += 1
        }

        return String(format: "%.2f %@", value, units[unitIndex])
    }
}
