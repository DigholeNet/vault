import Foundation

/// Shared interpretation of provider results; each platform supplies its layout.
public enum DiagnosticsPresentation {
    public static let requiredCheckIDs = ["dns", "tcp", "https", "dns6", "tcp6", "https6", "application"]
    public static let pingCheckIDs = ["ping", "ping6"]
    public static let checkIDs = requiredCheckIDs + pingCheckIDs
    public static let pingNote = "Ping is informational. ICMP may be filtered; no reply alone does not mean the VPN is broken. RTT averages replies only."

    public static func pingProbes(_ result: DiagnosticsResult?) -> [DiagnosticsProbe] {
        (result?.probes ?? []).filter { pingCheckIDs.contains($0.stage) }
    }

    public static func label(for id: String) -> String {
        ["dns": "Tunnel DNS · IPv4", "tcp": "Tunnel TCP · IPv4",
         "https": "Tunnel HTTPS · IPv4", "dns6": "Tunnel DNS · AAAA", "tcp6": "Tunnel TCP · IPv6",
         "https6": "Tunnel HTTPS · IPv6", "application": "Application access",
         "ping": "Ping · IPv4", "ping6": "Ping · IPv6"][id] ?? id
    }

    public static func passed(_ result: DiagnosticsResult?) -> Bool {
        guard let result, result.summary.hasPrefix("OK") else { return false }
        guard let checks = result.checks else { return true }
        return requiredCheckIDs.allSatisfy { id in
            checks.contains { $0.id == id && $0.state == .passed && $0.attempted > 0 }
        }
    }

    public static func incomplete(_ result: DiagnosticsResult?) -> Bool {
        result?.summary.contains("INCOMPLETE") == true
            || (result?.checks != nil && requiredCheckIDs.contains { id in
                !(result?.checks ?? []).contains { $0.id == id && $0.state != .incomplete }
            })
    }

    public static func durationHeading(_ result: DiagnosticsResult?) -> String {
        result?.checks?.contains { $0.sampleCount == nil } == true ? "Duration" : "Average duration"
    }

    /// Retried candidates remain visible in details. A failed candidate does
    /// not make the domain fail when another candidate completed that stage.
    public static func domainState(_ result: DiagnosticsResult, domain: String) -> DiagnosticsCheck.State {
        let probes = (result.probes ?? []).filter { $0.domain == domain }
        var missingStage = false
        let noAAAA = probes.contains { $0.stage == "dns6" && $0.succeeded && $0.detail.contains("no AAAA records") }
        for stage in requiredCheckIDs where !noAAAA || !["tcp6", "https6"].contains(stage) {
            let attempts = probes.filter { $0.stage == stage }
            if attempts.isEmpty { missingStage = true }
            else if !attempts.contains(where: \.succeeded) { return .failed }
        }
        return missingStage ? .incomplete : .passed
    }

    public static func filteredLogs(_ text: String, source: String, search: String) -> String {
        text.components(separatedBy: "\n").filter {
            // Rust core records are written by the tunnel provider.
            (source == "all" || $0.contains("[\(source)]") || (source == "ne" && $0.contains("[rust]")))
                && (search.isEmpty || $0.localizedCaseInsensitiveContains(search))
        }.joined(separator: "\n")
    }

    public static func connectionDuration(_ elapsed: TimeInterval) -> String {
        let seconds = max(0, Int(elapsed))
        return String(format: "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
    }
}
