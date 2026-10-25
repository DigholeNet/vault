// SPDX-License-Identifier: MIT
import Foundation

/// Platform configuration that has either been requested or applied to the TUN.
public struct TunnelConfiguration: Equatable, Sendable {
    public let ipv4: String
    public let mask: String
    public let ipv6: String
    public let prefix: Int32
    public let mtu: Int

    public init(ipv4: String, mask: String, ipv6: String, prefix: Int32, mtu: Int) {
        self.ipv4 = ipv4
        self.mask = mask
        self.ipv6 = ipv6
        self.prefix = prefix
        self.mtu = mtu
    }

    public var addresses: String { ipv6.isEmpty ? ipv4 : "\(ipv4)/\(ipv6)" }
}

/// Main-queue-owned serialization of asynchronous OS settings applications.
/// Only a successful completion changes the configuration visible to readers.
public struct TunnelSettingsState {
    public struct Update: Equatable, Sendable {
        public let revision: UInt64
        public let configuration: TunnelConfiguration
    }

    public private(set) var applied: TunnelConfiguration?
    public private(set) var generation: UInt64 = 0
    private var sequence: UInt64 = 0
    private var applying: Update?
    private var invalidatedThrough: UInt64 = 0
    private var pending: TunnelConfiguration?
    public var isApplying: Bool { applying != nil || pending != nil }
    /// The OS call still in progress, including one invalidated by cleanup.
    public var outstanding: Update? { applying }

    public init() {}

    public mutating func enqueue(_ configuration: TunnelConfiguration) -> Update? {
        if let applying {
            // Only the latest request needs to follow the in-flight update.
            let current = applying.revision > invalidatedThrough
            pending = current && configuration == applying.configuration ? nil : configuration
            return nil
        }
        guard configuration != applied else { return nil }
        sequence &+= 1
        let update = Update(revision: sequence, configuration: configuration)
        applying = update
        return update
    }

    /// Always release the OS request slot, even for a discarded session.
    /// False means callers must not publish the result or handle its error;
    /// they may drain next() for a waiting replacement session.
    public mutating func complete(_ update: Update, succeeded: Bool) -> Bool {
        guard applying == update else { return false }
        applying = nil
        guard update.revision > invalidatedThrough else { return false }
        if succeeded {
            applied = update.configuration
            generation = update.revision
        }
        return true
    }

    public mutating func next() -> Update? {
        guard applying == nil, let configuration = pending else { return nil }
        pending = nil
        return enqueue(configuration)
    }

    public mutating func reset() {
        // Reset logical state without pretending the outstanding OS call was
        // cancelled. A replacement must wait for its completion before starting.
        invalidatedThrough = sequence
        pending = nil
        applied = nil
        generation = 0
    }
}
