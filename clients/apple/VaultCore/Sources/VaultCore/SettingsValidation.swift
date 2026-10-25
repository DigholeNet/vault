import Foundation
import Network

/// Shared validation for settings drafts and the connection entry point.
public struct ConnectionDraft: Equatable, Sendable {
    public enum Section { case all, connection, network, advanced }
    public var host = ""
    public var port = ""
    public var password = ""
    public var dns = ""
    public var mtu = ""
    public var probeDomains = ""

    public init() {}

    public var normalized: Self {
        var draft = self
        draft.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.dns = dns.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.mtu = mtu.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.probeDomains = probeDomains.trimmingCharacters(in: .whitespacesAndNewlines)
        return draft
    }

    public func validationError(in section: Section = .all) -> String? {
        if section == .all || section == .connection {
            guard SettingsValidation.isValidServer(host) else {
                return "Enter a server IP address or hostname without a URL scheme."
            }
            guard let number = Int(port), (1...65535).contains(number) else {
                return "Port must be a number between 1 and 65535."
            }
            guard !password.isEmpty else { return "Enter the server password." }
        }
        if section == .all || section == .network {
            guard SettingsValidation.isValidDNSList(dns) else { return "Enter valid DNS IP addresses, separated by commas." }
        }
        if section == .all || section == .advanced {
            guard SettingsValidation.isValidMTU(mtu) else { return "MTU must be between 1280 and 1427, or empty for automatic." }
            guard SettingsValidation.isValidProbeList(probeDomains) else {
                return "Enter domain names separated by commas, without URLs."
            }
        }
        return nil
    }
}

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
        return trimmed.isEmpty || Int(trimmed).map { (1280...1427).contains($0) } == true
    }
}
