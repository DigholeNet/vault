// SPDX-License-Identifier: MIT
import NetworkExtension
import os.log
import VaultCore

struct VpnLogState {
    var generation: UInt64 = 0
    var collection: Task<String, Never>?
    var clearTask: Task<Bool, Error>?
    var clearing: Bool { clearTask != nil }
}

extension VpnManager {
    /// Returns false when the root provider is unavailable and its clear is
    /// persisted for the next startup. Local files are still truncated now.
    @MainActor
    func clearLogs() async throws -> Bool {
        if let clearing = logState.clearTask { return try await clearing.value }
        logState.generation &+= 1
        let collection = logState.collection
        logState.collection = nil
        let clearing = Task<Bool, Error> { @MainActor in
            defer { logState.clearTask = nil }
            #if os(macOS)
            let token = UUID().uuidString
            logPreferences.set(token, forKey: "clearLogsToken")
            logPreferences.set(true, forKey: "providerLogClearPending")
            let cache = extensionLogCacheURL
            #else
            let cache: URL? = nil
            #endif
            try await Task.detached(priority: .utility) {
                // Drain every queued cache write before deleting the cache.
                // Generation checks stop older provider replies from enqueueing more.
                _ = await collection?.value
                if let cache, FileManager.default.fileExists(atPath: cache.path) {
                    try FileManager.default.removeItem(at: cache)
                }
                try FileLogger.shared.clearLogs()
            }.value
            #if os(macOS)
            let cleared = await clearProviderLogs(token: token)
            if cleared { logPreferences.set(false, forKey: "providerLogClearPending") }
            return cleared
            #else
            return true
            #endif
        }
        logState.clearTask = clearing
        return try await clearing.value
    }

    #if os(macOS)
    @MainActor
    private func clearProviderLogs(token: String) async -> Bool {
        guard let status = activeVPN?.connection.status, status == .connected || status == .reasserting else { return false }
        return await withCheckedContinuation { continuation in
            sendProviderCommand(.init(.clearLogs, token: token), timeout: 3) { data in
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
                sendProviderCommand(.init(.logs)) { data in
                    continuation.resume(returning: data.flatMap { String(data: $0, encoding: .utf8) })
                }
            }
        } else { extensionLog = nil }
        let local = await appLog ?? ""
        guard generation == logState.generation, !logState.clearing else { return "" }
        let providerLog = canReadLiveProviderLogs && sessionGeneration == diagnosticState.generation
            && activeVPN?.connection === connection ? extensionLog : nil
        let cache = extensionLogCacheURL
        let previous = logState.collection
        let collection = Task.detached(priority: .utility) {
            // Keep file operations ordered even if more than one window collects logs.
            _ = await previous?.value
            var parts = [local]
            if let providerLog, !providerLog.isEmpty {
                if let cache { try? providerLog.write(to: cache, atomically: true, encoding: .utf8) }
                parts.append(providerLog)
            } else if let cache, let cached = try? String(contentsOf: cache, encoding: .utf8), !cached.isEmpty {
                parts.append(cached)
            }
            return FileLogger.mergeChronologically(parts.filter { !$0.isEmpty })
        }
        logState.collection = collection
        let text = await collection.value
        guard generation == logState.generation, !logState.clearing,
              sessionGeneration == diagnosticState.generation, activeVPN?.connection === connection,
              providerLog == nil || canReadLiveProviderLogs
        else { return "" }
        return text
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
