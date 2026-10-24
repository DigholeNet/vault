import Foundation

/// Main-queue-owned intent and async-operation gate. A cancelled preparation must
/// finish cleaning up its saved profile before another connection can begin.
public struct VPNConnectionLifecycle {
    public private(set) var generation: UInt64 = 0
    public private(set) var wantsConnection = false
    public private(set) var isStopping = false
    public private(set) var pendingStopJobs = 0
    public private(set) var stopFailed = false
    private var preparation: UInt64?
    private var startIssued = false
    public var isPreparing: Bool { preparation != nil }
    public init() {}

    public mutating func beginConnect() -> UInt64? {
        guard !isPreparing, !isStopping, !wantsConnection else { return nil }
        generation &+= 1
        wantsConnection = true
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
        startIssued = false
        return true
    }
    public mutating func beginDisconnect() -> UInt64? {
        guard !isStopping else { return nil }
        generation &+= 1
        wantsConnection = false
        isStopping = true
        stopFailed = false
        return generation
    }
    public func acceptsStop(_ token: UInt64) -> Bool { token == generation && isStopping }
    public mutating func beginStopJob(_ token: UInt64) -> Bool {
        guard acceptsStop(token) else { return false }
        pendingStopJobs += 1
        return true
    }
    public mutating func finishStopJob(_ token: UInt64, succeeded: Bool = true) {
        guard acceptsStop(token), pendingStopJobs > 0 else { return }
        pendingStopJobs -= 1
        if !succeeded { stopFailed = true }
    }
    /// A failed stop releases the operation gate after cleanup settles, without
    /// claiming the tunnel is down. The caller reports failure and permits retry.
    public mutating func completeStopIfReady(tunnelDown: Bool) -> Bool {
        guard isStopping, !isPreparing, pendingStopJobs == 0, tunnelDown || stopFailed else { return false }
        isStopping = false
        startIssued = false
        return true
    }
    public mutating func observedConnected() {
        guard !isStopping else { return }
        wantsConnection = true
        startIssued = true
    }
    /// True only for a connection that the user still wanted to keep alive.
    public mutating func observedDisconnected() -> Bool {
        guard !isStopping, !isPreparing else { return false }
        let unexpected = wantsConnection && startIssued
        wantsConnection = false
        startIssued = false
        return unexpected
    }
}
