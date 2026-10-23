import Foundation

/// Shared interpretation of provider results; each platform supplies its layout.
public enum DiagnosticsPresentation {
    public static let checkIDs = ["dns", "tcp", "https", "application"]

    public static func label(for id: String) -> String {
        ["dns": "Tunnel DNS · IPv4", "tcp": "Tunnel TCP · IPv4",
         "https": "Tunnel HTTPS · IPv4", "application": "Application access"][id] ?? id
    }

    public static func passed(_ result: DiagnosticsResult?) -> Bool {
        guard let result, result.summary.hasPrefix("OK") else { return false }
        return result.checks?.allSatisfy { $0.state == .passed && $0.attempted > 0 } ?? true
    }

    public static func incomplete(_ result: DiagnosticsResult?) -> Bool {
        result?.summary.contains("INCOMPLETE") == true
    }

    public static func durationHeading(_ result: DiagnosticsResult?) -> String {
        result?.checks?.contains { $0.sampleCount == nil } == true ? "Duration" : "Average duration"
    }

    /// Retried candidates remain visible in details. A failed candidate does
    /// not make the domain fail when another candidate completed that stage.
    public static func domainState(_ result: DiagnosticsResult, domain: String) -> DiagnosticsCheck.State {
        let probes = (result.probes ?? []).filter { $0.domain == domain }
        var missingStage = false
        for stage in checkIDs {
            let attempts = probes.filter { $0.stage == stage }
            if attempts.isEmpty { missingStage = true }
            else if !attempts.contains(where: \.succeeded) { return .failed }
        }
        return missingStage ? .incomplete : .passed
    }

    public static func filteredLogs(_ text: String, source: String, search: String) -> String {
        text.components(separatedBy: "\n").filter {
            (source == "all" || $0.contains("[\(source)]"))
                && (search.isEmpty || $0.localizedCaseInsensitiveContains(search))
        }.joined(separator: "\n")
    }

    public static func connectionDuration(_ elapsed: TimeInterval) -> String {
        let seconds = max(0, Int(elapsed))
        return String(format: "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
    }
}
