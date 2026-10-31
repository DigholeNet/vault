// SPDX-License-Identifier: MIT
import Foundation
import VaultCore

/// Owns provider-side probe cancellation; plans and network execution stay in Rust.
final class ProviderDiagnostics {
    private var cancellation: DiagnosticsCancellation?
    private var runID: String?

    func cancel(run: String? = nil) {
        guard run == nil || run == runID else { return }
        cancellation?.cancel()
        cancellation = nil
        runID = nil
    }

    /// Executes one Rust-selected probe. The app owns the engine and performs
    /// application-route requests itself; the provider never owns a second plan.
    func run(
        _ request: AppleProbeRequest,
        context: @escaping () -> AppleDiagnosticContext?,
        completionHandler: ((Data?) -> Void)?
    ) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard let current = context(), current.provider == request.provider,
              current.generation == request.generation, current.connectionGeneration == request.connectionGeneration,
              request.timeout.isFinite, request.timeout > 0, request.timeout <= 6,
              self.cancellation == nil || self.cancellation?.isCancelled == true
        else { completionHandler?(nil)
            return
        }
        switch request.operation {
        case .route: completionHandler?(nil)
            return
        case .dns, .tcp, .https:
            guard request.tunnel else { completionHandler?(nil)
                return
            }
        case .ping:
            guard !request.tunnel else { completionHandler?(nil)
                return
            }
        }
        let cancellation = DiagnosticsCancellation()
        self.cancellation = cancellation
        self.runID = request.run
        let address = current.ipv4.isEmpty ? current.ipv6 : current.ipv4
        DispatchQueue.global(qos: .utility).async {
            let response = RustDiagnostics.execute(request, tunnelAddress: address, cancellation: cancellation)
            DispatchQueue.main.async {
                let valid = self.cancellation === cancellation && !cancellation.isCancelled
                    && context()?.isSameSession(as: current) == true
                if self.cancellation === cancellation {
                    self.cancellation = nil
                    self.runID = nil
                }
                completionHandler?(valid ? try? JSONEncoder().encode(AppleProbeReply(request: request, response: response)) : nil)
            }
        }
    }
}
