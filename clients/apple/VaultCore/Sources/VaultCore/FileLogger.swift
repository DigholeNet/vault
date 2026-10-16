//
//  FileLogger.swift
//  VaultCore
//
//
//  Rotating file logger that writes into the shared App Group container so
//  both the main app and the network extension can read the same log.
//
import Foundation
import os.log

public final class FileLogger: @unchecked Sendable {
    public static let shared = FileLogger()

    private let queue = DispatchQueue(label: "net.dighole.vault.filelogger")
    /// Keep the log file under 1 MB; when the limit is exceeded the file is
    /// rotated to vault.prev.log (overwriting the previous backup) instead
    /// of being deleted, so the lines just before a crash survive.
    private let maxLogSize: UInt64 = 1 * 1024 * 1024
    private let logFileURL: URL?
    /// Backup of the previous session's (or pre-rotation) log. Read together
    /// with the current log so a crash that truncated the current file is
    /// still diagnosable.
    private let prevLogFileURL: URL?

    /// Short tag identifying the process that wrote a line ("app", "ne").
    /// Set as early as possible in each process.
    public var processTag = "app"

    private init() {
        let start = Date()
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: kAppGroupIdentifier
        ) else {
            logFileURL = nil
            prevLogFileURL = nil
            return
        }
        let logsDir = containerURL.appendingPathComponent("Logs", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: logsDir,
            withIntermediateDirectories: true,
            attributes: nil
        )
        logFileURL = logsDir.appendingPathComponent("vault.log")
        prevLogFileURL = logsDir.appendingPathComponent("vault.prev.log")
        let elapsed = Date().timeIntervalSince(start)
        self.log(
            "FileLogger initialized in \(String(format: "%.3f", elapsed))s, path: \(logFileURL?.path ?? "<none>")",
            level: "DEBUG"
        )
    }

    /// Append a single line to the shared log file. Thread-safe.
    public func log(_ message: String, level: String = "INFO") {
        queue.async { [weak self] in
            self?.writeLine(message, level: level)
        }
    }

    /// Synchronous variant for lifecycle callbacks (stopTunnel, sleep) where
    /// the process may be suspended or killed as soon as the callback
    /// returns — an async write would lose exactly the lines that explain
    /// why the tunnel went away.
    public func logSync(_ message: String, level: String = "INFO") {
        queue.sync {
            self.writeLine(message, level: level)
        }
    }

    private func writeLine(_ message: String, level: String) {
        guard let url = self.logFileURL else { return }

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        formatter.timeZone = TimeZone.current
        let timestamp = formatter.string(from: Date())

        let line = "[\(timestamp)] [\(level)] [\(self.processTag)] \(message)\n"
        guard let data = line.data(using: .utf8) else { return }

        self.rotateIfNeeded(url: url)
        self.append(data: data, to: url)
    }

    /// Path of the current log file, or nil if the App Group is unavailable.
    public var currentLogPath: String? {
        logFileURL?.path
    }

    /// URL of the current log file, or nil if the App Group is unavailable.
    public var currentLogURL: URL? {
        logFileURL
    }

    /// Read the log synchronously: previous session's backup followed by the
    /// current log, so a crash that truncated the current file is included.
    public func readLog() -> String? {
        let parts = [prevLogFileURL, logFileURL].compactMap {
            $0.flatMap { try? String(contentsOf: $0, encoding: .utf8) }
        }
        return parts.isEmpty ? nil : parts.joined()
    }

    /// Read the entire log asynchronously so large files do not
    /// block the calling thread.
    public func readLogAsync() async -> String? {
        readLog()
    }

    /// Rotate the current log to vault.prev.log and start fresh. Called at
    /// the start of each tunnel session: unlike deleting, this preserves the
    /// previous session's last lines, which is exactly where the evidence is
    /// when the extension process died abnormally.
    public func rotateForNewSession() {
        queue.sync {
            guard let url = self.logFileURL, let prev = self.prevLogFileURL else { return }
            guard FileManager.default.fileExists(atPath: url.path) else { return }
            try? FileManager.default.removeItem(at: prev)
            try? FileManager.default.moveItem(at: url, to: prev)
        }
    }

    private func rotateIfNeeded(url: URL) {
        guard let prev = prevLogFileURL,
            FileManager.default.fileExists(atPath: url.path),
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
            let size = attrs[.size] as? UInt64,
            size > maxLogSize
        else { return }
        try? FileManager.default.removeItem(at: prev)
        try? FileManager.default.moveItem(at: url, to: prev)
    }

    /// Append with O_APPEND so that writes from multiple processes (app,
    /// extension, Rust core) to the shared file cannot overwrite each other.
    private func append(data: Data, to url: URL) {
        let fd = url.path.withCString { open($0, O_WRONLY | O_CREAT | O_APPEND, 0o644) }
        guard fd >= 0 else { return }
        defer { close(fd) }
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress, !buffer.isEmpty else { return }
            _ = Darwin.write(fd, base, buffer.count)
        }
    }
}

public extension Logger {
    /// Log to both os_log (notice level) and the shared file log.
    func noticeAndFile(_ message: String) {
        self.notice("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "NOTICE")
    }

    /// Log to both os_log (error level) and the shared file log.
    func errorAndFile(_ message: String) {
        self.error("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "ERROR")
    }

    /// Log to both os_log (debug level) and the shared file log.
    func debugAndFile(_ message: String) {
        self.debug("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "DEBUG")
    }

    /// Log to both os_log (warning level) and the shared file log.
    func warningAndFile(_ message: String) {
        self.warning("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "WARNING")
    }
}
