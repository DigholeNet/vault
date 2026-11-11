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

    public static func isValidDNSList(_ value: String, ipv6: Bool? = nil) -> Bool {
        if value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
        let values = value.split(separator: ",", omittingEmptySubsequences: false)
        return values.count <= 4 && values.allSatisfy {
            let address = $0.trimmingCharacters(in: .whitespacesAndNewlines)
            if let ipv6 { return ipv6 ? IPv6Address(address) != nil : isValidIPv4(address) }
            return isValidIPv4(address) || IPv6Address(address) != nil
        }
    }

    private static func isValidIPv4(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 3
                && $0.utf8.allSatisfy { (48 ... 57).contains($0) }
                && UInt8($0) != nil
        }
    }

    public static func isValidProbeList(_ value: String) -> Bool {
        if value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return true }
        let values = value.split(separator: ",", omittingEmptySubsequences: false)
        return values.count <= 32 && values.allSatisfy {
            isValidProbeDomain($0.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    public static func isValidMTU(_ value: String) -> Bool {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty || Int(trimmed)
            .map { (TunnelLaunchConfiguration.mtuLowerBound ... TunnelLaunchConfiguration.mtuUpperBound).contains($0) } == true
    }
}
