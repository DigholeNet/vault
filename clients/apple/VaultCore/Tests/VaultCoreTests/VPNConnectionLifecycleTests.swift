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
        #expect({ state.beginStopJob(stop) }())
        #expect({ !state.completeStopIfReady(tunnelDown: true) }())
        #expect({ state.beginConnect() == nil }())
        #expect({ !state.observedDisconnected() }())
        state.finishStopJob(stop)
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
    #expect({ state.beginStopJob(stop) }())
    state.finishStopJob(stop)
    #expect({ !state.completeStopIfReady(tunnelDown: true) }())
    #expect({ !state.canStart(connect) }())
    #expect({ !state.failConnect(connect) }())
    state.finishPreparation(connect)
    // The cancelled save returned a profile: disable its on-demand rule too.
    #expect({ state.beginStopJob(stop) }())
    #expect({ state.beginConnect() == nil }())
    #expect({ !state.completeStopIfReady(tunnelDown: true) }())
    state.finishStopJob(stop)
    #expect({ state.completeStopIfReady(tunnelDown: true) }())
    let next = try #require({ state.beginConnect() }())
    state.finishStopJob(stop)
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
