//
//  FileLogger.swift
//  VaultCore
//
//
//  Rotating file logger that writes into the shared App Group container.
//  On iOS the app and the network extension share that container; on macOS
//  the system extension is a sandboxed root daemon whose container is
//  unreadable to the app (and the user's container is denied by the
//  extension's sandbox), so the app fetches the extension's log over the
//  provider-message channel instead (see handleAppMessage "logs").
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
            // Also os_log the failure: when file logging itself lands
            // nowhere, the file cannot explain why.
            Logger.network.error(
                "FileLogger: App Group container unavailable (group '\(kAppGroupIdentifier, privacy: .public)', euid \(geteuid()))"
            )
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
        Logger.network.notice(
            "FileLogger path: \(self.logFileURL?.path ?? "nil", privacy: .public) (euid \(geteuid()))"
        )
        let elapsed = Date().timeIntervalSince(start)
        self.log(
            "FileLogger initialized in \(String(format: "%.3f", elapsed))s, path: \(logFileURL?.path ?? "<none>")",
            level: "DEBUG"
        )
    }

    init(logDirectory: URL) throws {
        try FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        logFileURL = logDirectory.appendingPathComponent("vault.log")
        prevLogFileURL = logDirectory.appendingPathComponent("vault.prev.log")
    }

    /// Drain queued Swift writes, then truncate both generations in place.
    /// O_APPEND writers can keep logging new events after the clear finishes.
    public func clearLogs() throws {
        try queue.sync {
            guard let current = logFileURL, let previous = prevLogFileURL else {
                throw CocoaError(.fileNoSuchFile)
            }
            for url in [current, previous] {
                let fd = url.path.withCString { open($0, O_WRONLY | O_CREAT | O_TRUNC, 0o644) }
                guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                close(fd)
            }
        }
    }

    /// Append a single line to the shared log file. Thread-safe.
    public func log(_ message: String, level: String = "INFO") {
        let timestamp = Date()
        let source = processTag
        queue.async { [weak self] in
            self?.writeLine(message, level: level, source: source, timestamp: timestamp)
        }
    }

    /// Synchronous variant for lifecycle callbacks (stopTunnel, sleep) where
    /// the process may be suspended or killed as soon as the callback
    /// returns — an async write would lose exactly the lines that explain
    /// why the tunnel went away.
    public func logSync(_ message: String, level: String = "INFO") {
        let timestamp = Date()
        let source = processTag
        queue.sync {
            self.writeLine(message, level: level, source: source, timestamp: timestamp)
        }
    }

    private func writeLine(_ message: String, level: String, source: String, timestamp: Date) {
        guard let url = self.logFileURL else { return }

        let line = Self.formattedRecord(message, level: level, source: source, timestamp: timestamp)
        guard let data = line.data(using: .utf8) else { return }

        self.rotateIfNeeded(url: url)
        self.append(data: data, to: url)
    }

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

    /// Path of the current log file, or nil if the App Group is unavailable.
    public var currentLogPath: String? {
        logFileURL?.path
    }

    /// Read the log synchronously: previous session's backup followed by the
    /// current log, so a crash that truncated the current file is included.
    public func readLog() -> String? {
        let parts = [prevLogFileURL, logFileURL].compactMap {
            $0.flatMap { try? String(contentsOf: $0, encoding: .utf8) }
        }
        return parts.isEmpty ? nil : Self.mergeChronologically(parts)
    }

    /// Read the entire log on a background thread so large files do not
    /// block the calling thread.
    public func readLogAsync() async -> String? {
        await Task.detached { self.readLog() }.value
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

    /// Compare UTC timestamps, converting older Swift logs from local time.
    /// Equal timestamps retain input order, including each process's own order.
    public static func mergeChronologically(_ parts: [String], legacyTimeZone: TimeZone = .current) -> String {
        let local = DateFormatter()
        local.locale = Locale(identifier: "en_US_POSIX")
        local.timeZone = legacyTimeZone
        local.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        let utc = DateFormatter()
        utc.locale = local.locale
        utc.timeZone = TimeZone(secondsFromGMT: 0)
        utc.dateFormat = local.dateFormat
        var converted: [String: String] = [:]
        func timestamp(_ line: Substring) -> String {
            guard line.first == "[", let end = line.firstIndex(of: "]") else { return "" }
            let value = String(line[line.index(after: line.startIndex)..<end])
            if value.hasSuffix("Z") { return String(value.dropLast()) }
            if let cached = converted[value] { return cached }
            let key = local.date(from: value).map { utc.string(from: $0) } ?? value
            converted[value] = key
            return key
        }
        let lines = parts.flatMap { $0.split(separator: "\n", omittingEmptySubsequences: true) }.map { raw in
            var line = raw
            if line.hasPrefix("[[") {
                while line.hasPrefix("[[") { line = line.dropFirst() }
                guard let end = line.firstIndex(of: "]") else { return raw }
                let value = line[line.index(after: line.startIndex)..<end]
                guard utc.date(from: String(value.hasSuffix("Z") ? value.dropLast() : value)) != nil else { return raw }
            }
            // Older Rust logs put the source before an unbracketed severity.
            if let end = line.firstIndex(of: "]") {
                let tail = line[line.index(after: end)...].trimmingCharacters(in: .whitespaces)
                if tail.hasPrefix("[rust] ") {
                    let fields = tail.dropFirst(7).split(maxSplits: 1, whereSeparator: { $0.isWhitespace })
                    if fields.count == 2, ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].contains(String(fields[0])) {
                        let level = fields[0] == "WARN" ? "WARNING" : String(fields[0])
                        return Substring("\(line[...end]) [\(level)] [rust] \(fields[1])")
                    }
                }
            }
            return line
        }
        struct Entry {
            let index: Int
            let line: Substring
            let time: String
        }
        var entries: [Entry] = []
        for (index, line) in lines.enumerated() {
            entries.append(Entry(index: index, line: line, time: timestamp(line)))
        }
        entries.sort { lhs, rhs in
            lhs.time == rhs.time ? lhs.index < rhs.index : lhs.time < rhs.time
        }
        return entries.map { String($0.line) }.joined(separator: "\n")
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

    /// Log to both os_log (warning level) and the shared file log.
    func warningAndFile(_ message: String) {
        self.warning("\(message, privacy: .public)")
        FileLogger.shared.log(message, level: "WARNING")
    }
}
