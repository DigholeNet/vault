// SPDX-License-Identifier: MIT
import NetworkExtension
import os.log
import VaultCore

struct VpnDiagnosticState {
    var generation: UInt64 = 0
    var cancellation: DiagnosticsCancellation?
    var cancelledByUser = false
    var runID: String?
}

extension VpnManager {
    /// The Rust engine lives in the app. Tunnel/host-default operations use
    /// provider IPC; application operations execute here with default routing.
    /// Progress and completion callbacks run on main.
    func requestDiagnostics(onProgress: ((DiagnosticsResult) -> Void)? = nil, completion: @escaping (DiagnosticsResult?) -> Void) {
        guard Thread.isMainThread else {
            DispatchQueue.main.async { self.requestDiagnostics(onProgress: onProgress, completion: completion) }
            return
        }
        guard diagnosticState.cancellation == nil, vpnStatus == .connected else {
            completion(DiagnosticsResult(message: "INCOMPLETE - diagnostics unavailable or already running"))
            return
        }
        let cancellation = DiagnosticsCancellation()
        let run = UUID().uuidString
        let generation = diagnosticState.generation
        let connection = activeVPN?.connection
        let connectedDate = connection?.connectedDate
        diagnosticState.cancellation = cancellation
        diagnosticState.runID = run
        diagnosticState.cancelledByUser = false
        sendProviderCommand(.init(.diagnosticContext), timeout: 3) { data in
            guard !cancellation.isCancelled, self.diagnosticState.generation == generation,
                  self.vpnStatus == .connected, let data,
                  let context = try? JSONDecoder().decode(AppleDiagnosticContext.self, from: data) else {
                if self.diagnosticState.cancellation === cancellation {
                    self.diagnosticState.cancellation = nil
                    self.diagnosticState.runID = nil
                }
                completion(DiagnosticsResult(message: "INCOMPLETE - live diagnostic context unavailable"))
                return
            }
            DispatchQueue.global(qos: .utility).async {
                var result: DiagnosticsResult
                do {
                    let snapshot = try RustDiagnostics.run(
                        context: context,
                        cancellation: cancellation,
                        execute: { request, remaining in
                            let native = AppleProbeRequest(
                                request: request,
                                context: context,
                                run: run,
                                remainingMs: remaining
                            )
                            if request.scope == .application {
                                return RustDiagnostics.execute(
                                    native,
                                    tunnelAddress: nil,
                                    cancellation: cancellation
                                ).rust
                            }
                            guard let body = try? JSONEncoder().encode(native),
                                  let reply = self.diagnosticCommand(
                                      .init(.diagnosticProbe, payload: body),
                                      timeout: native.replyTimeout,
                                      cancellation: cancellation
                                  ),
                                  let decoded = try? JSONDecoder().decode(
                                      AppleProbeReply.self,
                                      from: reply
                                  ),
                                  decoded.run == run, decoded.id == request.id else { return nil }
                            return decoded.response.rust
                        },
                        onProgress: { progress in
                            DispatchQueue.main.async {
                                if self.diagnosticState.cancellation === cancellation,
                                   !cancellation.isCancelled {
                                    onProgress?(DiagnosticsResult(snapshot: progress))
                                }
                            }
                        }
                    )
                    result = DiagnosticsResult(snapshot: snapshot)
                } catch {
                    result = DiagnosticsResult(message: "INCOMPLETE - Rust diagnostics: \(error)")
                }
                // Reconfirm the provider instance/configuration, even when an
                // entire reconnect happened between two app-route samples.
                let finalData = self.diagnosticCommand(.init(.diagnosticContext), timeout: 3, cancellation: cancellation)
                let finalContext = finalData.flatMap { try? JSONDecoder().decode(AppleDiagnosticContext.self, from: $0) }
                DispatchQueue.main.async {
                    let changed = cancellation.isCancelled || self.diagnosticState.generation != generation
                        || self.vpnStatus != .connected || self.activeVPN?.connection !== connection
                        || self.activeVPN?.connection.connectedDate != connectedDate
                        || finalContext?.isSameSession(as: context) != true
                    if changed {
                        result.message = "INCOMPLETE - tunnel session changed; run diagnostics again"
                        self.sendProviderCommand(.init(.cancelDiagnostics, token: run), timeout: 3) { _ in }
                    }
                    if self.diagnosticState.cancelledByUser { result.message = "INCOMPLETE - diagnostics cancelled" }
                    if self.diagnosticState.cancellation === cancellation {
                        self.diagnosticState.cancellation = nil
                        self.diagnosticState.runID = nil
                    }
                    FileLogger.shared.log("[probe] final summary: \(result.summary) duration=\(result.durationMs ?? 0)ms")
                    completion(result)
                }
            }
        }
    }

    /// Wait only on a worker queue; reply and cancellation remain responsive on
    /// main. No native/provider callback runs while holding a Rust engine lock.
    private func diagnosticCommand(
        _ request: ProviderCommandEnvelope,
        timeout: TimeInterval,
        cancellation: DiagnosticsCancellation
    ) -> Data? {
        precondition(!Thread.isMainThread)
        let lock = NSLock()
        let semaphore = DispatchSemaphore(value: 0)
        var response: Data?
        sendProviderCommand(request, timeout: timeout) { data in
            lock.lock()
            response = data
            lock.unlock()
            semaphore.signal()
        }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while !cancellation.isCancelled, ProcessInfo.processInfo.systemUptime < deadline {
            if semaphore.wait(timeout: .now() + min(0.05, max(0, deadline - ProcessInfo.processInfo.systemUptime))) == .success {
                lock.lock()
                let data = response
                lock.unlock()
                return data
            }
        }
        return nil
    }

    func cancelDiagnostics() {
        guard let cancellation = diagnosticState.cancellation, let run = diagnosticState.runID else { return }
        diagnosticState.cancelledByUser = true
        cancellation.cancel()
        sendProviderCommand(.init(.cancelDiagnostics, token: run), timeout: 3) { _ in }
    }
}
