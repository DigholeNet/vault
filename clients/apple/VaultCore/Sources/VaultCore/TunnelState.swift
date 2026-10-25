// SPDX-License-Identifier: MIT
import Foundation

// MARK: - Network settings application

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

// MARK: - Startup completion ownership

/// Owns the completions for one (possibly repeated) tunnel start. Access only on the provider's main queue.
public final class PendingStart {
    private var completions: [(Error?) -> Void]

    public init(completion: @escaping (Error?) -> Void) {
        self.completions = [completion]
    }

    public var isPending: Bool { !completions.isEmpty }

    @discardableResult
    public func appendCompletion(_ completion: @escaping (Error?) -> Void) -> Bool {
        guard isPending else { return false }
        completions.append(completion)
        return true
    }

    /// Claim completion before performing any success or failure side effects.
    public func takeCompletion() -> ((Error?) -> Void)? {
        guard isPending else { return nil }
        let callbacks = completions
        completions.removeAll()
        return { error in callbacks.forEach { $0(error) } }
    }
}

// MARK: - Traffic session ownership

extension PacketStats {
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
}
