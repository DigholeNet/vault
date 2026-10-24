import Testing
@testable import VaultCore

@Test func rapidToggleWaitsForStopCallbacks() throws {
    var state = VPNConnectionLifecycle()
    for _ in 0..<1000 {
        let connect = try #require({ state.beginConnect() }())
        #expect({ state.beginConnect() == nil }())
        state.finishPreparation(connect)
        #expect({ state.markStarted(connect) }())
        state.observedConnected()
        let stop = try #require({ state.beginDisconnect() }())
        #expect({ state.beginDisconnect() == nil }())
        #expect({ state.beginTeardown(stop) }())
        #expect({ !state.completeStopIfReady(tunnelDown: true) }())
        #expect({ state.beginConnect() == nil }())
        #expect({ !state.observedDisconnected() }())
        state.finishTeardown(stop)
        #expect({ !state.completeStopIfReady(tunnelDown: false) }())
        #expect({ state.completeStopIfReady(tunnelDown: true) }())
        #expect({ !state.observedDisconnected() }())
        #expect({ !state.failConnect(connect) }())
        #expect({ !state.markStarted(connect) }())
    }
}

@Test func cancellationWaitsForPreparationAndSavedProfileCleanup() throws {
    var state = VPNConnectionLifecycle()
    let connect = try #require({ state.beginConnect() }())
    let stop = try #require({ state.beginDisconnect() }())
    #expect({ !state.beginTeardown(stop) }())
    #expect({ !state.completeStopIfReady(tunnelDown: true) }())
    #expect({ !state.canStart(connect) }())
    #expect({ !state.failConnect(connect) }())
    state.finishPreparation(connect)
    // The cancelled save returned a profile: disable its on-demand rule too.
    #expect({ state.beginTeardown(stop) }())
    #expect({ state.beginConnect() == nil }())
    #expect({ !state.completeStopIfReady(tunnelDown: true) }())
    state.finishTeardown(stop)
    #expect({ state.completeStopIfReady(tunnelDown: true) }())
    let next = try #require({ state.beginConnect() }())
    state.finishTeardown(stop)
    state.finishPreparation(connect)
    #expect({ state.isPreparing }())
    #expect({ state.canStart(next) }())
    #expect({ !state.markStarted(connect) }())
}

@Test func realDisconnectStillReportsUnexpectedOnce() throws {
    var state = VPNConnectionLifecycle()
    #expect({ !state.observedDisconnected() }())
    let token = try #require({ state.beginConnect() }())
    #expect({ !state.observedDisconnected() }())
    state.finishPreparation(token)
    #expect({ state.markStarted(token) }())
    #expect({ state.observedDisconnected() }())
    #expect({ !state.observedDisconnected() }())
    // Existing system-managed connections are also tracked.
    state.observedConnected()
    #expect({ state.observedDisconnected() }())
}

@Test func connectionFailureAllowsRetryButStaleFailureDoesNot() throws {
    var state = VPNConnectionLifecycle()
    let first = try #require({ state.beginConnect() }())
    #expect({ state.failConnect(first) }())
    let second = try #require({ state.beginConnect() }())
    #expect({ !state.failConnect(first) }())
    #expect({ state.canStart(second) }())
    #expect({ state.isPreparing }())
}

@Test func failedDisconnectRestoresRetryAfterAllCleanupJobsFinish() throws {
    var state = VPNConnectionLifecycle()
    let connect = try #require({ state.beginConnect() }())
    let stop = try #require({ state.beginDisconnect() }())
    #expect({ !state.beginTeardown(stop) }())
    // Preparation must settle before any profile cleanup can begin.
    #expect({ !state.completeStopIfReady(tunnelDown: true) }())
    state.finishPreparation(connect)
    #expect({ state.beginTeardown(stop) }())
    #expect({ !state.completeStopIfReady(tunnelDown: false) }())
    state.finishTeardown(stop, succeeded: false)
    #expect(state.stopFailed)
    #expect({ state.completeStopIfReady(tunnelDown: false) }())
    #expect(!state.isStopping)
    state.observedConnected()
    let retry = try #require({ state.beginDisconnect() }())
    #expect(!state.stopFailed)
    #expect({ state.beginTeardown(retry) }())
    // Late errors from the failed attempt must not poison the retry.
    state.finishTeardown(stop, succeeded: false)
    #expect(!state.stopFailed)
    state.finishTeardown(retry)
    #expect({ !state.completeStopIfReady(tunnelDown: false) }())
    #expect({ state.completeStopIfReady(tunnelDown: true) }())
}

@Test func failedDisconnectOfIdleProfileAllowsAnotherAttempt() throws {
    var state = VPNConnectionLifecycle()
    let stop = try #require({ state.beginDisconnect() }())
    #expect({ state.beginTeardown(stop) }())
    state.finishTeardown(stop, succeeded: false)
    #expect({ state.completeStopIfReady(tunnelDown: true) }())
    let retry = try #require({ state.beginDisconnect() }())
    #expect(!state.stopFailed)
    #expect(state.acceptsStop(retry))
}

@Test func latestIntentWaitsForSerialTeardown() throws {
    var state = VPNConnectionLifecycle()
    let start = try #require({ state.beginConnect() }())
    let stop = try #require({ state.beginDisconnect() }())
    #expect(state.phase == .disconnecting)
    #expect({ state.beginConnect() == nil }())
    #expect(state.wantsConnection)
    #expect(!state.canStart(start))
    state.finishPreparation(start)
    #expect({ state.beginTeardown(stop) }())
    #expect({ !state.beginTeardown(stop) }())
    #expect({ !state.completeStopIfReady(tunnelDown: true) }())
    state.finishTeardown(stop)
    #expect({ state.completeStopIfReady(tunnelDown: true) }())
    #expect(state.phase == .disconnected)
    #expect(state.wantsConnection)
    #expect({ state.beginConnect() != nil }())
}

@Test func subsequentDisconnectClearsQueuedReconnect() throws {
    var state = VPNConnectionLifecycle()
    let stop = try #require({ state.beginDisconnect() }())
    #expect({ state.beginConnect() == nil }())
    #expect({ state.beginDisconnect() == nil }())
    #expect(!state.wantsConnection)
    #expect({ state.beginTeardown(stop) }())
    state.finishTeardown(stop)
    #expect({ state.completeStopIfReady(tunnelDown: true) }())
    #expect(!state.wantsConnection)
}

@Test func stopTimeoutReleasesOperationWithoutClaimingDisconnected() throws {
    var state = VPNConnectionLifecycle()
    state.observedConnected()
    let stop = try #require({ state.beginDisconnect() }())
    #expect({ state.beginTeardown(stop) }())
    state.failStop(stop)
    #expect(!state.stopFailed) // A preferences write must settle first.
    state.finishTeardown(stop)
    state.failStop(stop)
    #expect({ state.completeStopIfReady(tunnelDown: false) }())
    #expect(state.phase != .disconnected)
    #expect(!state.wantsConnection)
    #expect({ state.beginDisconnect() != nil }())
}

@Test func onDemandNotificationsCannotFinishPreparation() throws {
    var state = VPNConnectionLifecycle()
    let token = try #require({ state.beginConnect() }())
    state.observedConnected()
    #expect(state.phase == .connecting)
    #expect(state.isPreparing)
    #expect(state.canStart(token))
    #expect({ !state.observedDisconnected() }())
    #expect(state.canStart(token))
    state.finishPreparation(token)
    #expect({ state.markStarted(token) }())
    state.observedConnected()
    #expect(state.phase == .connected)
}

@Test func cancellationOverridesOnDemandNotificationsDuringPreparation() throws {
    var state = VPNConnectionLifecycle()
    let token = try #require({ state.beginConnect() }())
    state.observedConnected()
    let stop = try #require({ state.beginDisconnect() }())
    state.observedConnected()
    #expect(!state.canStart(token))
    #expect(state.phase == .disconnecting)
    state.finishPreparation(token)
    #expect({ state.beginTeardown(stop) }())
    state.finishTeardown(stop)
    #expect({ state.completeStopIfReady(tunnelDown: true) }())
    #expect(!state.wantsConnection)
}
