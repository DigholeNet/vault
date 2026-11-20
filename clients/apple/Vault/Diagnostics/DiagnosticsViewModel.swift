import Combine
import Foundation
import VaultCore

protocol RuntimeLogStore {
    @MainActor func collectLogs() async -> String
    @MainActor func clearLogs() async throws -> Bool
}

extension VpnManager: RuntimeLogStore {}

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
    @Published private(set) var filteredLogText = ""
    @Published var logFilter = "all" {
        didSet { if logFilter != oldValue { filterLogs() } }
    }
    @Published var logSearch = "" {
        didSet { if logSearch != oldValue { filterLogs() } }
    }
    @Published private(set) var loadingLogs = false

    @Published private(set) var clearingLogs = false
    @Published private(set) var logMessage: String?
    private var logGeneration: UInt64 = 0
    private var refreshGeneration: UInt64 = 0
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
        result = DiagnosticsResult(message: "RUNNING")
        manager.requestDiagnostics(onProgress: { [weak self] progress in
            guard let self, self.running, self.generation == token else { return }
            if self.result?.activeCheck != progress.activeCheck {
                self.progressReceived = ProcessInfo.processInfo.systemUptime
            }
            self.result = progress
        }, completion: { [weak self] reply in
            guard let self, self.generation == token else { return }
            self.result = reply ?? DiagnosticsResult(message: "INCOMPLETE - provider returned no usable response")
            self.running = false
            self.completedAt = Date()
        })
    }

    func cancel(using manager: VpnManager) {
        guard running, !cancelRequested else { return }
        cancelRequested = true
        manager.cancelDiagnostics()
    }

    func clearLogs(using manager: any RuntimeLogStore) async {
        guard !clearingLogs else { return }
        clearingLogs = true
        logGeneration &+= 1
        updateLogs("")
        setLoadingLogs(false)
        logMessage = nil
        defer { clearingLogs = false }
        do {
            let complete = try await manager.clearLogs()
            if !complete { logMessage = "Local logs cleared. Provider logs will be cleared on the next connection." }
        } catch {
            logMessage = "Unable to clear all log files. Please try again."
        }
    }

    func refreshLogs(using manager: any RuntimeLogStore) async {
        refreshGeneration &+= 1
        let refreshToken = refreshGeneration
        let refreshID = String(UUID().uuidString.prefix(8))
        var polls = 0
        FileLogger.shared.log("[logRefresh:\(refreshID)] started appPID=\(ProcessInfo.processInfo.processIdentifier)", level: "NOTICE")
        setLoadingLogs(logText.isEmpty)
        defer {
            if refreshToken == refreshGeneration { setLoadingLogs(false) }
            FileLogger.shared.log("[logRefresh:\(refreshID)] ended cancelled=\(Task.isCancelled) polls=\(polls)", level: "NOTICE")
        }
        while !Task.isCancelled, refreshToken == refreshGeneration {
            let token = logGeneration
            if !clearingLogs {
                polls += 1
                let text = await manager.collectLogs()
                guard !Task.isCancelled, refreshToken == refreshGeneration else { return }
                if token == logGeneration, !clearingLogs {
                    updateLogs(text)
                    setLoadingLogs(false)
                }
            }
            do { try await Task.sleep(for: .seconds(2)) } catch { return }
        }
    }

    /// Retain the filtered snapshot across view updates and unchanged polls.
    func updateLogs(_ text: String) {
        guard text != logText else { return }
        logText = text
        filterLogs()
    }

    private func filterLogs() {
        let filtered = DiagnosticsPresentation.filteredLogs(logText, source: logFilter, search: logSearch)
        if filtered != filteredLogText { filteredLogText = filtered }
    }

    private func setLoadingLogs(_ loading: Bool) {
        if loadingLogs != loading { loadingLogs = loading }
    }
}
