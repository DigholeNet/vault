//
//  PacketStats.swift
//  VaultCore
//
//

import Foundation

/// Bridges traffic statistics from the Rust core (vault-core owns the
/// counters, living in the Network Extension process) to the main app via
/// App Group UserDefaults.
///
/// The Network Extension polls `Edge.getTrafficStats()` once per second and
/// calls `update(from:)`. The main app is a read-only consumer through
/// `currentStats`. Thread-safe: all mutable state is protected by an
/// internal serial dispatch queue.
public final class PacketStats: @unchecked Sendable {
    public static let shared = PacketStats()

    private let statsKey = "packetStats"
    private let appGroupIdentifier: String
    private let defaults: UserDefaults
    private let queue = DispatchQueue(label: "net.dighole.vault.packetstats")
    private var _stats = Stats.zero

    public struct Stats: Codable, Sendable {
        public var packetsSent: UInt64
        public var packetsReceived: UInt64
        public var bytesSent: UInt64
        public var bytesReceived: UInt64
        public var bytesSentPerSecond: UInt64
        public var bytesReceivedPerSecond: UInt64
        public var lastUpdated: Date

        public static var zero: Stats {
            Stats(
                packetsSent: 0, packetsReceived: 0, bytesSent: 0, bytesReceived: 0,
                bytesSentPerSecond: 0, bytesReceivedPerSecond: 0, lastUpdated: Date()
            )
        }

        public init(
            packetsSent: UInt64, packetsReceived: UInt64, bytesSent: UInt64,
            bytesReceived: UInt64, bytesSentPerSecond: UInt64,
            bytesReceivedPerSecond: UInt64, lastUpdated: Date
        ) {
            self.packetsSent = packetsSent
            self.packetsReceived = packetsReceived
            self.bytesSent = bytesSent
            self.bytesReceived = bytesReceived
            self.bytesSentPerSecond = bytesSentPerSecond
            self.bytesReceivedPerSecond = bytesReceivedPerSecond
            self.lastUpdated = lastUpdated
        }
    }

    private init() {
        self.appGroupIdentifier = kAppGroupIdentifier
        self.defaults = UserDefaults(suiteName: appGroupIdentifier) ?? .standard
        loadPersisted()
    }

    /// Initialize with custom app group identifier (for testing)
    public init(appGroupIdentifier: String) {
        self.appGroupIdentifier = appGroupIdentifier
        self.defaults = UserDefaults(suiteName: appGroupIdentifier) ?? .standard
        loadPersisted()
    }

    private func loadPersisted() {
        if let data = defaults.data(forKey: statsKey),
           let persisted = try? JSONDecoder().decode(Stats.self, from: data) {
            self._stats = persisted
        }
    }

    /// Get current stats.
    /// In the Network Extension process this returns the in-memory value.
    /// In the main app process this merges the latest persisted data from
    /// UserDefaults (written by the Network Extension) if it is newer.
    public var currentStats: Stats {
        queue.sync {
            if let data = defaults.data(forKey: statsKey),
               let persisted = try? JSONDecoder().decode(Stats.self, from: data),
               persisted.lastUpdated > _stats.lastUpdated {
                _stats = persisted
            }
            return _stats
        }
    }

    /// Store a fresh snapshot from the Rust core. Called by the Network
    /// Extension's poll timer; negative core values are clamped to zero.
    public func update(from core: TrafficStats) {
        let snapshot = Stats(
            packetsSent: UInt64(max(0, core.packetsSent)),
            packetsReceived: UInt64(max(0, core.packetsReceived)),
            bytesSent: UInt64(max(0, core.bytesSent)),
            bytesReceived: UInt64(max(0, core.bytesReceived)),
            bytesSentPerSecond: UInt64(max(0, core.sendSpeed)),
            bytesReceivedPerSecond: UInt64(max(0, core.receiveSpeed)),
            lastUpdated: Date()
        )
        queue.async { [weak self] in
            guard let self = self else { return }
            self._stats = snapshot
            self.persist()
        }
    }

    /// Reset all stats (called by the Network Extension on tunnel start)
    public func reset() {
        queue.sync {
            self._stats = .zero
            self.persist()
        }
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(_stats) else { return }
        defaults.set(data, forKey: statsKey)
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

    public static func formatPacketsPerSecond(_ packets: UInt64, over timeInterval: TimeInterval) -> String {
        let pps = timeInterval > 0 ? Double(packets) / timeInterval : 0
        return String(format: "%.1f pkt/s", pps)
    }
}
