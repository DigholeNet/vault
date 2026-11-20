import Foundation

/// Primitive validation shared by platform adapters and the App.
public enum SettingsValidation {
    public static func isValidServer(_ value: String) -> Bool {
        VaultCore.isValidServer(value: value)
    }

    public static func isValidProbeDomain(_ value: String) -> Bool {
        VaultCore.isValidDomain(value: value)
    }

    public static func isValidDNSList(_ value: String, ipv6: Bool? = nil) -> Bool {
        VaultCore.isValidDnsList(value: value, ipv6: ipv6)
    }

    public static func isValidProbeList(_ value: String) -> Bool {
        VaultCore.isValidDomainList(value: value)
    }

    public static func isValidMTU(_ value: String) -> Bool {
        VaultCore.isValidMtu(value: value)
    }
}
