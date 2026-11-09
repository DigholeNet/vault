// SPDX-License-Identifier: MIT
import Foundation
import SwiftUI
import VaultCore

// MARK: - Connection status

enum VpnStatusUtil {
    static func titleKey(for status: VpnStatus) -> String {
        switch status {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .disconnecting: return "Disconnecting…"
        }
    }

    static func getStatus(_ status: VpnStatus) -> String {
        LanguageManager.shared.tr(titleKey(for: status))
    }
}

#if os(macOS)
enum ConnectionAction {
    case connect, disconnect, configure

    init(status: VpnStatus, configured: Bool) {
        self = status != .disconnected ? .disconnect : (configured ? .connect : .configure)
    }
}

extension AppData {
    var connectionActionTitle: String {
        switch vpnStatus {
        case .connected: return "Disconnect"
        case .connecting: return isRecovering ? "Disconnect" : "Cancel Connection"
        case .disconnecting: return connectionError == nil ? "Disconnecting…" : "Disconnect"
        case .disconnected: return connectionError == nil ? "Connect" : "Retry"
        }
    }
}

#endif

// MARK: - IP Parsing Helpers

extension String {
    /// Splits a supernode-assigned address string ("ipv4" or "ipv4/ipv6")
    /// into its parts; empty parts become nil.
    func parsedIPv4AndIPv6() -> (ipv4: String?, ipv6: String?) {
        guard !self.isEmpty else { return (nil, nil) }

        let components = self.split(separator: "/", omittingEmptySubsequences: false)
        let ipv4 = !components.isEmpty ? String(components[0]).trimmingCharacters(in: .whitespaces) : nil
        let ipv6 = components.count > 1 ? String(components[1]).trimmingCharacters(in: .whitespaces) : nil

        return (
            ipv4?.isEmpty == false ? ipv4 : nil,
            ipv6?.isEmpty == false ? ipv6 : nil
        )
    }
}

// MARK: - Version Helpers

extension Bundle {
    var appVersionShort: String {
        infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }

    var appVersion: String {
        let version = appVersionShort
        let build = infoDictionary?["CFBundleVersion"] as? String ?? "0"
        return "\(version).\(build)"
    }
}

// MARK: - Diagnostic results and display formatting

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

/// App-only display formatting for shared traffic snapshots.
extension PacketStats {
    static func formatBytes(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var unitIndex = 0

        while value >= 1024 && unitIndex < units.count - 1 {
            value /= 1024
            unitIndex += 1
        }

        return String(format: "%.2f %@", value, units[unitIndex])
    }
}

// MARK: - About content

/// Product details shared by the platform-specific About containers.
struct AboutContent: View {
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        VStack(spacing: 0) {
            Text("Vault")
                .font(.system(size: 24, weight: .bold))
                .padding(.bottom, 12)
            Text(languageManager.tr(
                "Version %@ (%@)",
                Bundle.main.appVersionShort,
                Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
            ))
            .font(.system(size: 16))
            .foregroundStyle(.secondary)
            .padding(.bottom, 32)

            Link(destination: URL(string: "https://github.com/DigholeNet/vault")!) {
                Text(verbatim: "https://github.com/DigholeNet/vault")
            }
            .font(.system(size: 14))
            .padding(.bottom, 16)
            Text(languageManager.tr("A secure VPN client for cross-regional connectivity."))
                .font(.system(size: 14))
            #if os(macOS)
                .fixedSize(horizontal: false, vertical: true)
            #endif
                .padding(.bottom, 16)
            Text(verbatim: "© 2026 Dighole Team")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
    }
}
