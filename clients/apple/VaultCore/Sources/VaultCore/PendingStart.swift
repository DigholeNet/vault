// SPDX-License-Identifier: MIT
import Foundation

/// Owns one tunnel start completion. Access only on the provider's main queue.
public final class PendingStart {
    private var completion: ((Error?) -> Void)?
    private var failureScheduled = false

    public init(completion: @escaping (Error?) -> Void) {
        self.completion = completion
    }

    public var isPending: Bool { completion != nil }

    public func scheduleFailure() -> Bool {
        guard isPending, !failureScheduled else { return false }
        failureScheduled = true
        return true
    }

    /// Claim completion before performing any success or failure side effects.
    public func takeCompletion() -> ((Error?) -> Void)? {
        let result = completion
        completion = nil
        return result
    }
}
