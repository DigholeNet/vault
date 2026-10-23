import Foundation
import Combine
import VaultCore

/// Both apps use the same request, progress and log refresh lifecycle.
@MainActor
final class DiagnosticsViewModel: ObservableObject {
    @Published private(set) var result: DiagnosticsResult?
    @Published private(set) var running = false
    @Published private(set) var cancelRequested = false
    @Published private(set) var startedAt: TimeInterval?
    @Published private(set) var progressReceived = ProcessInfo.processInfo.systemUptime
    @Published private(set) var completedAt: Date?
    @Published private(set) var logText = ""
    @Published private(set) var loadingLogs = false

    private var generation: UInt64 = 0

    var passed: Bool { DiagnosticsPresentation.passed(result) }
    var incomplete: Bool { DiagnosticsPresentation.incomplete(result) }
    var diagnosticText: String { ([result?.summary ?? ""] + (result?.lines ?? [])).joined(separator: "\n") }

    func run(using manager: VpnManager, connected: Bool) {
        guard !running, connected else { return }
        generation &+= 1
        let token = generation
        running = true
        cancelRequested = false
        let now = ProcessInfo.processInfo.systemUptime
        startedAt = now
        progressReceived = now
        completedAt = nil
        result = DiagnosticsResult(summary: "RUNNING", lines: [], checks: [], activeCheck: "dns")
        manager.requestDiagnostics(onProgress: { [weak self] progress in
            DispatchQueue.main.async {
                guard let self, self.running, self.generation == token else { return }
                if self.result?.activeCheck != progress.activeCheck {
                    self.progressReceived = ProcessInfo.processInfo.systemUptime
                }
                self.result = progress
            }
        }) { [weak self] reply in
            DispatchQueue.main.async {
                guard let self, self.generation == token else { return }
                self.result = reply ?? DiagnosticsResult(summary: "INCOMPLETE - provider returned no usable response", lines: [])
                self.running = false
                self.completedAt = Date()
            }
        }
    }

    func cancel(using manager: VpnManager) {
        guard running, !cancelRequested else { return }
        cancelRequested = true
        manager.cancelDiagnostics()
    }

    func refreshLogs(using manager: VpnManager) async {
        loadingLogs = logText.isEmpty
        defer { loadingLogs = false }
        while !Task.isCancelled {
            let text = await manager.collectLogs()
            guard !Task.isCancelled else { return }
            logText = text
            loadingLogs = false
            do { try await Task.sleep(for: .seconds(2)) }
            catch { return }
        }
    }
}
