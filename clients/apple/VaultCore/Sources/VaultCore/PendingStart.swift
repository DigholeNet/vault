// SPDX-License-Identifier: MIT
import Foundation

/// Owns the completions for one (possibly repeated) tunnel start. Access only on the provider's main queue.
public final class PendingStart {
    private var completions: [(Error?) -> Void]
    private var failureScheduled = false

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

    public func scheduleFailure() -> Bool {
        guard isPending, !failureScheduled else { return false }
        failureScheduled = true
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
