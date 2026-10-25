// SPDX-License-Identifier: MIT
import NetworkExtension
import VaultCore
import os.log

struct VpnLogState {
    var generation: UInt64 = 0
    var clearing = false
}

extension VpnManager {
    /// Returns false when the root provider is unavailable and its clear is
    /// persisted for the next startup. Local files are still truncated now.
    @MainActor
    func clearLogs() async throws -> Bool {
        logState.generation &+= 1
        logState.clearing = true
        defer { logState.clearing = false }
        #if os(macOS)
        let token = UUID().uuidString
        logPreferences.set(token, forKey: "clearLogsToken")
        logPreferences.set(true, forKey: "providerLogClearPending")
        if let cache = extensionLogCacheURL, FileManager.default.fileExists(atPath: cache.path) {
            try FileManager.default.removeItem(at: cache)
        }
        #endif
        try FileLogger.shared.clearLogs()
        #if os(macOS)
        let cleared = await clearProviderLogs(token: token)
        if cleared { logPreferences.set(false, forKey: "providerLogClearPending") }
        return cleared
        #else
        return true
        #endif
    }

    #if os(macOS)
    @MainActor
    private func clearProviderLogs(token: String) async -> Bool {
        guard let status = activeVPN?.connection.status, status == .connected || status == .reasserting else { return false }
        struct Command: Encodable { let command = "clearLogs"; let token: String }
        guard let payload = try? JSONEncoder().encode(Command(token: token)) else { return false }
        return await withCheckedContinuation { continuation in
            sendProviderCommand("clearLogs", timeout: 3, payload: payload) { data in
                continuation.resume(returning: data == Data([1]))
            }
        }
    }
    #endif

    #if os(macOS)
    /// The extension's log is trapped inside a sandboxed root daemon's
    /// container; the app can only obtain it over the provider-message
    /// channel while the tunnel is up. Every successful fetch is cached next
    /// to the app's own log so Runtime Logs can still show the most recent
    /// extension log after the tunnel went down.
    private var extensionLogCacheURL: URL? {
        FileLogger.shared.currentLogPath.map {
            URL(fileURLWithPath: $0).deletingLastPathComponent()
                .appendingPathComponent("vault.ne.log")
        }
    }

    /// App log merged chronologically with the extension log (or its most
    /// recent cached copy when the provider is unreachable).
    @MainActor
    func collectLogs() async -> String {
        guard !logState.clearing else { return "" }
        let generation = logState.generation
        if logPreferences.bool(forKey: "providerLogClearPending") {
            if let token = logPreferences.string(forKey: "clearLogsToken"), await clearProviderLogs(token: token) {
                guard generation == logState.generation, !logState.clearing else { return "" }
                logPreferences.set(false, forKey: "providerLogClearPending")
            } else {
                let local = await FileLogger.shared.readLogAsync() ?? ""
                return generation == logState.generation && !logState.clearing ? local : ""
            }
        }
        async let appLog = FileLogger.shared.readLogAsync()
        let sessionGeneration = diagnosticState.generation
        let connection = activeVPN?.connection
        let extensionLog: String?
        if canReadLiveProviderLogs {
            extensionLog = await withCheckedContinuation { continuation in
                sendProviderCommand("logs") { data in
                    continuation.resume(returning: data.flatMap { String(data: $0, encoding: .utf8) })
                }
            }
        } else { extensionLog = nil }
        var parts = [await appLog ?? ""]
        guard generation == logState.generation, !logState.clearing else { return "" }
        if canReadLiveProviderLogs, sessionGeneration == diagnosticState.generation,
            activeVPN?.connection === connection, let extensionLog, !extensionLog.isEmpty {
            if let cache = extensionLogCacheURL {
                try? extensionLog.write(to: cache, atomically: true, encoding: .utf8)
            }
            parts.append(extensionLog)
        } else if let cache = extensionLogCacheURL,
            let cached = try? String(contentsOf: cache, encoding: .utf8), !cached.isEmpty
        {
            parts.append(cached)
        }
        return FileLogger.mergeChronologically(parts.filter { !$0.isEmpty })
    }
    #else
    /// iOS app and extension already share the same log file.
    @MainActor
    func collectLogs() async -> String {
        guard !logState.clearing else { return "" }
        let generation = logState.generation
        let text = await FileLogger.shared.readLogAsync() ?? ""
        return generation == logState.generation && !logState.clearing ? text : ""
    }
    #endif

}
