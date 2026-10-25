// SPDX-License-Identifier: MIT
import Testing
@testable import VaultCore

private func configuration(_ ip: String) -> TunnelConfiguration {
    TunnelConfiguration(ipv4: ip, mask: "255.255.255.0", ipv6: "fd00::2", prefix: 64, mtu: 1427)
}

@Test func settingsCommit() throws {
    var state = TunnelSettingsState()
    let initial = configuration("10.0.0.2")
    let updateRequest = state.enqueue(initial)
    let update = try #require(updateRequest)
    #expect(state.applied == nil)
    #expect(state.isApplying)
    #expect(state.complete(update, succeeded: true) == true)
    #expect(state.applied == initial)
    #expect(state.generation == update.revision)
    #expect(!state.isApplying)
    #expect(state.enqueue(initial) == nil)
}

@Test func settingsFailure() throws {
    var state = TunnelSettingsState()
    let initial = configuration("10.0.0.2")
    let firstRequest = state.enqueue(initial)
    let first = try #require(firstRequest)
    #expect(state.complete(first, succeeded: true) == true)
    let changedRequest = state.enqueue(configuration("10.0.0.3"))
    let changed = try #require(changedRequest)
    #expect(state.complete(changed, succeeded: false) == true)
    #expect(state.applied == initial)
    #expect(state.generation == first.revision)
}

@Test func settingsOrder() throws {
    var state = TunnelSettingsState()
    let firstRequest = state.enqueue(configuration("10.0.0.2"))
    let first = try #require(firstRequest)
    #expect(state.enqueue(configuration("10.0.0.3")) == nil)
    let latest = configuration("10.0.0.4")
    #expect(state.enqueue(latest) == nil)
    #expect(state.next() == nil)
    #expect(state.complete(first, succeeded: true) == true)
    let nextRequest = state.next()
    let next = try #require(nextRequest)
    #expect(next.configuration == latest)
    #expect(state.complete(next, succeeded: true) == true)
    #expect(!state.isApplying)
    #expect(state.applied == latest)
}

@Test func settingsRestart() throws {
    // Both success and failure from the discarded OS request must release
    // the slot without publishing old state or failing the replacement.
    for succeeded in [true, false] {
        var state = TunnelSettingsState()
        let firstRequest = state.enqueue(configuration("10.0.0.2"))
        let first = try #require(firstRequest)
        state.reset()
        #expect(state.isApplying)
        #expect(state.enqueue(configuration("10.0.0.3")) == nil)
        #expect(state.next() == nil)
        #expect(state.complete(first, succeeded: succeeded) == false)
        #expect(state.applied == nil)
        #expect(state.generation == 0)
        let replacementRequest = state.next()
        let replacement = try #require(replacementRequest)
        #expect(replacement.configuration.ipv4 == "10.0.0.3")
        // Duplicate old completions cannot release the replacement's slot.
        #expect(state.complete(first, succeeded: true) == false)
        #expect(state.next() == nil)
        #expect(state.complete(replacement, succeeded: true) == true)
        #expect(state.applied == replacement.configuration)
    }
}

@Test func settingsStoppedReply() throws {
    var state = TunnelSettingsState()
    let firstRequest = state.enqueue(configuration("10.0.0.2"))
    let first = try #require(firstRequest)
    state.reset()
    #expect(state.complete(first, succeeded: true) == false)
    #expect(state.applied == nil)
    #expect(state.next() == nil)
    #expect(!state.isApplying)
}

@Test func settingsSameIpRestart() throws {
    var state = TunnelSettingsState()
    let initial = configuration("10.0.0.2")
    let firstRequest = state.enqueue(initial)
    let first = try #require(firstRequest)
    state.reset()
    // Same IP must still be applied for the new logical session.
    #expect(state.enqueue(initial) == nil)
    #expect(state.complete(first, succeeded: true) == false)
    let nextRequest = state.next()
    let next = try #require(nextRequest)
    #expect(next.revision > first.revision)
    #expect(state.complete(next, succeeded: true) == true)
    #expect(state.applied == initial)
}

@Test func settingsRepeatedReset() throws {
    var state = TunnelSettingsState()
    let firstRequest = state.enqueue(configuration("10.0.0.2"))
    let first = try #require(firstRequest)
    state.reset()
    #expect(state.enqueue(configuration("10.0.0.3")) == nil)
    state.reset()
    #expect(state.enqueue(configuration("10.0.0.4")) == nil)
    #expect(state.complete(first, succeeded: true) == false)
    let nextRequest = state.next()
    let next = try #require(nextRequest)
    #expect(next.configuration.ipv4 == "10.0.0.4")
    #expect(state.complete(next, succeeded: true) == true)
    #expect(state.applied == next.configuration)
}

@Test func settingsHang() throws {
    var state = TunnelSettingsState()
    let request = state.enqueue(configuration("10.0.0.2"))
    let outstanding = try #require(request)
    // Cleanup/retry cannot cancel the OS call. This remains observable so
    // the provider can recycle the process instead of retrying forever.
    for _ in 0..<3 {
        state.reset()
        #expect(state.outstanding == outstanding)
        #expect(state.enqueue(configuration("10.0.0.3")) == nil)
        #expect(state.next() == nil)
    }
    // A late completion removes the reason to recycle the process.
    #expect(state.complete(outstanding, succeeded: false) == false)
    #expect(state.outstanding == nil)
    let replacementRequest = state.next()
    let replacement = try #require(replacementRequest)
    #expect(state.complete(replacement, succeeded: true) == true)
}

@Test func settingsErrorWithPending() throws {
    var state = TunnelSettingsState()
    let request = state.enqueue(configuration("10.0.0.2"))
    let outstanding = try #require(request)
    #expect(state.enqueue(configuration("10.0.0.3")) == nil)
    #expect(state.complete(outstanding, succeeded: false) == true)
    // Queued work alone must not trigger process recycling after an ordinary
    // settings error: there is no unresponsive OS request anymore.
    #expect(state.isApplying)
    #expect(state.outstanding == nil)
}
