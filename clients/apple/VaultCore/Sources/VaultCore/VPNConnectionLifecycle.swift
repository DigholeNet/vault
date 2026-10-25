import Foundation

/// Main-queue-owned serial operation gate. Preparation always settles before
/// teardown starts; user actions only change the final connection intent.
public struct VPNConnectionLifecycle {
    public enum Phase {
        case connecting
        case connected
        case disconnected
        case disconnecting
    }

    public private(set) var phase: Phase = .disconnected
    public private(set) var generation: UInt64 = 0
    public private(set) var wantsConnection = false
    public private(set) var stopFailed = false
    private var preparation: UInt64?
    private var stopInFlight = false
    public private(set) var isStopping = false
    private var startIssued = false
    public var isPreparing: Bool { preparation != nil }
    public init() {}

    public mutating func beginConnect() -> UInt64? {
        wantsConnection = true
        guard phase == .disconnected, !isPreparing else { return nil }
        generation &+= 1
        phase = .connecting
        startIssued = false
        preparation = generation
        return generation
    }
    public func canStart(_ token: UInt64) -> Bool {
        token == generation && wantsConnection && !isStopping
    }
    public mutating func finishPreparation(_ token: UInt64) {
        if preparation == token { preparation = nil }
    }
    public mutating func markStarted(_ token: UInt64) -> Bool {
        guard canStart(token) else { return false }
        startIssued = true
        return true
    }
    public mutating func failConnect(_ token: UInt64) -> Bool {
        guard canStart(token) else { return false }
        finishPreparation(token)
        wantsConnection = false
        phase = .disconnected
        startIssued = false
        return true
    }
    public mutating func beginDisconnect() -> UInt64? {
        wantsConnection = false
        guard !isStopping else { return nil }
        generation &+= 1
        phase = .disconnecting
        isStopping = true
        stopFailed = false
        return generation
    }
    public func acceptsStop(_ token: UInt64) -> Bool { token == generation && isStopping }
    public mutating func beginTeardown(_ token: UInt64) -> Bool {
        guard acceptsStop(token), !isPreparing, !stopInFlight else { return false }
        stopInFlight = true
        return true
    }
    public mutating func finishTeardown(_ token: UInt64, succeeded: Bool = true) {
        guard acceptsStop(token), stopInFlight else { return }
        stopInFlight = false
        if !succeeded { stopFailed = true }
    }
    public mutating func failStop(_ token: UInt64) {
        guard acceptsStop(token), !stopInFlight else { return }
        stopFailed = true
    }
    public mutating func completeStopIfReady(tunnelDown: Bool) -> Bool {
        guard isStopping, !isPreparing, !stopInFlight, tunnelDown || stopFailed else { return false }
        isStopping = false
        phase = tunnelDown ? .disconnected : (startIssued ? .connected : .connecting)
        startIssued = false
        // A failed cleanup must be explicitly retried, never auto-started.
        if stopFailed { wantsConnection = false }
        return true
    }
    /// Observe OS state only after preparation/teardown releases ownership.
    /// A failed stop updates the displayed phase without restoring connect intent.
    @discardableResult
    public mutating func observe(_ status: Phase, updateIntent: Bool = true) -> Bool {
        guard !isStopping, !isPreparing else { return false }
        let unexpected = updateIntent && status == .disconnected && wantsConnection && startIssued
        phase = status
        if updateIntent {
            if status == .connected {
                wantsConnection = true
                startIssued = true
            } else if status == .disconnected {
                wantsConnection = false
                startIssued = false
            }
        }
        return unexpected
    }
}
