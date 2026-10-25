import Foundation
import Network

/// Primitive validation shared by platform adapters and the App.
public enum SettingsValidation {
    public static func isValidServer(_ value: String) -> Bool {
        let host = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return IPv4Address(host) != nil || IPv6Address(host) != nil || isValidProbeDomain(host)
    }

    public static func isValidProbeDomain(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 253
            && (try? diagnosticDnsQuery(domain: value.hasSuffix(".") ? String(value.dropLast()) : value, id: 0, ipv6: false)) != nil
    }

    public static func isValidDNSList(_ value: String) -> Bool {
        if value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
        return value.split(separator: ",", omittingEmptySubsequences: false).allSatisfy {
            let address = $0.trimmingCharacters(in: .whitespacesAndNewlines)
            return IPv4Address(address) != nil || IPv6Address(address) != nil
        }
    }

    public static func isValidProbeList(_ value: String) -> Bool {
        if value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
        return value.split(separator: ",", omittingEmptySubsequences: false).allSatisfy {
            isValidProbeDomain($0.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    public static func isValidMTU(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty || Int(trimmed)
            .map { (TunnelLaunchConfiguration.mtuLowerBound ... TunnelLaunchConfiguration.mtuUpperBound).contains($0) } == true
    }
}
