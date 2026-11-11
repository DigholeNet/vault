//
//  FileLogger.swift
//  VaultCore
//
//  vault-core owns the shared file format, rotation, reads and merges. This
//  wrapper supplies the App Group path and serializes asynchronous Swift calls.
//
import Foundation
import os.log

public final class FileLogger: @unchecked Sendable {
    public static let shared = FileLogger()

    private let queue = DispatchQueue(label: "net.dighole.vault.filelogger")
    private let logFileURL: URL?
    private let prevLogFileURL: URL?

    /// Short tag identifying the process that wrote a line ("app", "ne").
    private var tag = ["appex", "systemextension"].contains(Bundle.main.bundleURL.pathExtension) ? "ne" : "app"
    private let tagLock = NSLock()
    public var processTag: String {
        get {
            tagLock.lock()
            defer { tagLock.unlock() }
            return tag
        }
        set {
            tagLock.lock()
            tag = newValue
            tagLock.unlock()
        }
    }

    private init() {
        let start = Date()
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: kAppGroupIdentifier
        ) else {
            logFileURL = nil
            prevLogFileURL = nil
            Logger.network.error(
                "FileLogger: App Group container unavailable (group '\(kAppGroupIdentifier, privacy: .public)', euid \(geteuid()))"
            )
            return
        }
        let logsDir = containerURL.appendingPathComponent("Logs", isDirectory: true)
        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)
        logFileURL = logsDir.appendingPathComponent("vault.log")
        prevLogFileURL = logsDir.appendingPathComponent("vault.prev.log")
        if let path = logFileURL?.path { setLogFilePath(path: path) }
        Logger.network.notice("FileLogger path: \(self.logFileURL?.path ?? "nil", privacy: .public) (euid \(geteuid()))")
        let elapsed = Date().timeIntervalSince(start)
        self.log("FileLogger initialized in \(String(format: "%.3f", elapsed))s, path: \(logFileURL?.path ?? "<none>")", level: "DEBUG")
    }

    init(logDirectory: URL) throws {
        try FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        logFileURL = logDirectory.appendingPathComponent("vault.log")
        prevLogFileURL = logDirectory.appendingPathComponent("vault.prev.log")
        if let path = logFileURL?.path { setLogFilePath(path: path) }
    }

    /// Drain queued Swift writes, then truncate both generations in place.
    public func clearLogs() throws {
        try queue.sync {
            guard logFileURL != nil else { throw CocoaError(.fileNoSuchFile) }
            try clearSharedLogs()
        }
    }

    public func log(_ message: String, level: String = "INFO") {
        // Capture the time at the call site so lines reflect event order,
        // not queue delay.
        let timestamp = Date()
        let source = processTag
        queue.async { [weak self] in
            self?.writeLine(message, level: level, source: source, timestamp: timestamp)
        }
    }

    /// Synchronous variant for lifecycle callbacks where the process may be suspended.
    public func logSync(_ message: String, level: String = "INFO") {
        let timestamp = Date()
        let source = processTag
        queue.sync {
            self.writeLine(message, level: level, source: source, timestamp: timestamp)
        }
    }

    private func writeLine(_ message: String, level: String, source: String, timestamp: Date) {
        guard logFileURL != nil else { return }
        appendSharedLog(
            level: level, source: source, message: message,
            timestampMs: UInt64(timestamp.timeIntervalSince1970 * 1000)
        )
    }

    /// Kept for diagnostics and legacy-format regression coverage.
    static func formattedRecord(_ message: String, level: String, source: String, timestamp: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS'Z'"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        let time = formatter.string(from: timestamp)
        let severity = level == "WARN" ? "WARNING" : level
        return message.components(separatedBy: "\n").map {
            "[\(time)] [\(severity)] [\(source)] \($0)\n"
        }.joined()
    }

    /// Observational snapshot only: does not open a provider-message channel.
    public static func tunnelInterfaceSummary() -> String {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return "unavailable" }
        defer { freeifaddrs(list) }
        var names = Set<String>()
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let name = String(cString: entry.pointee.ifa_name)
            if name.hasPrefix("utun") { names.insert(name) }
        }
        return names.sorted().joined(separator: ",")
    }

    public var currentLogPath: String? {
        logFileURL?.path
    }

    public func readLog() -> String? {
        guard logFileURL != nil, prevLogFileURL != nil else { return nil }
        let offset = Int32(TimeZone.current.secondsFromGMT())
        return try? readSharedLogs(legacyTimezoneOffsetSeconds: offset)
    }

    public func readLogAsync() async -> String? {
        await Task.detached { self.readLog() }.value
    }

    public func rotateForNewSession() {
        queue.sync {
            guard logFileURL != nil else { return }
            try? rotateSharedLogForNewSession()
        }
    }

    /// Compare UTC timestamps, converting older platform logs from local time.
    public static func mergeChronologically(_ parts: [String], legacyTimeZone: TimeZone = .current) -> String {
        mergeSharedLogs(parts: parts, legacyTimezoneOffsetSeconds: Int32(legacyTimeZone.secondsFromGMT()))
    }
}

public extension Logger {
    func noticeAndFile(_ message: String) {
        self.notice("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "NOTICE")
    }

    func errorAndFile(_ message: String) {
        self.error("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "ERROR")
    }

    func warningAndFile(_ message: String) {
        self.warning("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "WARNING")
    }
}
