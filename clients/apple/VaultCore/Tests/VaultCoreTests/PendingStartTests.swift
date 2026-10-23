// SPDX-License-Identifier: MIT
import Testing
@testable import VaultCore

@Test func failureOnce() {
    let start = PendingStart { _ in }
    #expect(start.scheduleFailure())
    #expect(!start.scheduleFailure())
    #expect(!start.scheduleFailure())
}

@Test func finishOnce() {
    var completions = 0
    let start = PendingStart { _ in completions += 1 }
    start.takeCompletion()?(nil)
    #expect(completions == 1)
    #expect(!start.isPending)
    #expect(start.takeCompletion() == nil)
    #expect(!start.scheduleFailure())
}

@Test func lateFailure() {
    var closed = false
    let start = PendingStart { _ in }
    #expect(start.scheduleFailure())
    start.takeCompletion()?(nil)
    // The delayed error must claim completion before closing the live Edge.
    if let completion = start.takeCompletion() {
        closed = true
        completion(nil)
    }
    #expect(!closed)
}
