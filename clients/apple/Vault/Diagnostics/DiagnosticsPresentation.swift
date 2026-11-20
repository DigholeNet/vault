// SPDX-License-Identifier: MIT
import Foundation
import VaultCore

/// Keeps the Rust snapshot as the only result model. A local failure can
/// invalidate its verdict without losing observations collected before cancellation.
struct DiagnosticsResult: Sendable {
    let snapshot: DiagnosticSnapshot?
    var message: String?

    init(snapshot: DiagnosticSnapshot? = nil, message: String? = nil) {
        self.snapshot = snapshot
        self.message = message
    }

    var engineState: DiagnosticState { message == nil ? snapshot?.state ?? .incomplete : .incomplete }
    var domains: [String]? { snapshot?.domains }
    var checks: [DiagnosticCheck]? { snapshot?.checks }
    var probes: [DiagnosticProbe]? { snapshot?.probes }
    var durationMs: UInt64? { snapshot?.durationMs }
    var activeCheck: String? { snapshot?.activeStage.map { String(describing: $0) } }

    var summary: String {
        if let message { return message }
        guard let snapshot else { return "INCOMPLETE" }
        if snapshot.cancelled { return "INCOMPLETE - diagnostics cancelled or tunnel session changed" }
        let prefix = snapshot.running ? "RUNNING"
            : snapshot.state == .passed ? "OK" : snapshot.state == .failed ? "PROBLEMS FOUND" : "INCOMPLETE"
        let details = snapshot.routeIssues + snapshot.routeUnavailable
        return prefix + (details.isEmpty ? "" : " - " + details.joined(separator: "; "))
    }

    var lines: [String] {
        guard let snapshot else { return [] }
        return snapshot.probes.map {
            "[probe] \($0.stage) \($0.domain): \($0.displayDetail) duration=\($0.durationMs)ms"
        } + (snapshot.routeIssues + snapshot.routeUnavailable).map { "[probe] route: \($0)" }
    }
}

extension DiagnosticCheck {
    var id: String { String(describing: stage) }
}

extension DiagnosticProbe {
    var id: UInt64 { request.id }
    var stage: String { String(describing: request.stage) }
    var domain: String { request.domain }
    var displayDetail: String {
        let target: String
        switch request.operation {
        case .dns(let server, _): target = "\(server): "
        case .tcp(let address, let port): target = "\(address):\(port) · "
        case .https(let address, let port): target = address.map { "\($0):\(port) · " } ?? ""
        case .ping(let address, let sequence, let size): target = "\(address) seq=\(sequence) size=\(size) · "
        case .route: target = ""
        }
        return target + detail
    }
}

/// App-only formatting shared by the iOS and macOS layouts.
enum DiagnosticsPresentation {
    struct CheckRow {
        let state: DiagnosticState?
        let active: Bool
        /// Localization key or a numeric passed/attempted count.
        let resultText: String
        let durationMs: UInt64?
    }

    static func checkRow(_ id: String, result: DiagnosticsResult?, running: Bool) -> CheckRow {
        let check = result?.checks?.first { $0.id == id }
        let active = running && (result?.activeCheck ?? "dns") == id && check == nil
        let text = check.map { $0.attempted == 0 ? "Not measured" : "\($0.passed)/\($0.attempted)" }
            ?? (active ? "Checking" : (running ? "Waiting" : "Not measured"))
        let duration = check.flatMap { $0.attempted > 0 && $0.sampleCount != 0 ? $0.durationMs : nil }
        return CheckRow(state: check?.state, active: active, resultText: text, durationMs: duration)
    }

    static func resultTitle(_ result: DiagnosticsResult?, running: Bool) -> String {
        if running { return "Checking connection…" }
        if passed(result) { return "Connectivity checks passed" }
        return incomplete(result) ? "Diagnostics incomplete" : "Connectivity issues found"
    }

    static let checkIDs = [
        "dns", "tcp", "https", "dns6", "tcp6", "https6", "application", "ping", "ping6"
    ]
    static func visibleChecks(_ result: DiagnosticsResult?) -> [String] {
        result?.snapshot?.plannedChecks.map { String(describing: $0) } ?? checkIDs
    }

    static let pingCheckIDs = ["ping", "ping6"]
    static let pingNote =
        "Ping is informational. ICMP may be filtered; no reply alone does not mean the VPN is broken. RTT averages replies only."

    static func pingProbes(_ result: DiagnosticsResult?) -> [DiagnosticProbe] {
        (result?.probes ?? []).filter { pingCheckIDs.contains($0.stage) }
    }

    static func label(for id: String) -> String {
        [
            "dns": "Tunnel DNS · IPv4", "tcp": "Tunnel TCP · IPv4",
            "https": "Tunnel HTTPS · IPv4", "dns6": "Tunnel DNS · AAAA", "tcp6": "Tunnel TCP · IPv6",
            "https6": "Tunnel HTTPS · IPv6", "application": "Application access",
            "ping": "Ping · IPv4", "ping6": "Ping · IPv6"
        ][id] ?? id
    }

    static func passed(_ result: DiagnosticsResult?) -> Bool {
        result?.engineState == .passed
    }

    static func incomplete(_ result: DiagnosticsResult?) -> Bool {
        result?.engineState == .incomplete
    }

    static func domainState(_ result: DiagnosticsResult, domain: String) -> DiagnosticState {
        result.snapshot?.domainStates.first { $0.domain == domain }?.state ?? .incomplete
    }

    static func filteredLogs(_ text: String, source: String, search: String) -> String {
        guard source != "all" || !search.isEmpty else { return text }
        return text.components(separatedBy: "\n").filter {
            // Include Rust records in the tunnel filter; the shared source tag does
            // not distinguish app-process diagnostics from provider-process records.
            (source == "all" || $0.contains("[\(source)]") || (source == "ne" && $0.contains("[rust]")))
                && (search.isEmpty || $0.localizedCaseInsensitiveContains(search))
        }.joined(separator: "\n")
    }

    static func connectionDuration(_ elapsed: TimeInterval) -> String {
        let seconds = max(0, Int(elapsed))
        return String(format: "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
    }
}
