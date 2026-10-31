// SPDX-License-Identifier: MIT
import CoreFoundation
import Foundation

// MARK: - Saved launch configuration

/// Immutable configuration stored in the OS VPN profile for on-demand restarts.
/// DNS settings use separate IPv4 and IPv6 fields; the old combined field is ignored.
public struct TunnelLaunchConfiguration {
    public static let mtuLowerBound = 1280
    public static let mtuUpperBound = 1427

    public enum InvalidField: Error { case host, port, password, peerID, dnsIpv4, dnsIpv6 }

    public let host: String
    public let port: UInt16
    public let password: String
    public let peerID: Data
    public let dnsIpv4: [String]
    public let dnsIpv6: [String]
    public let probeDomains: [String]
    public let mtuCap: Int
    public let clearLogsToken: String?

    public init(providerConfiguration values: [String: Any], clearLogsToken: String? = nil) throws {
        guard let rawHost = values["host"] as? String else { throw InvalidField.host }
        let trimmed = rawHost.trimmingCharacters(in: .whitespacesAndNewlines)
        host = trimmed.hasPrefix("[") && trimmed.hasSuffix("]") ? String(trimmed.dropFirst().dropLast()) : trimmed
        guard !host.isEmpty else { throw InvalidField.host }
        guard let number = values["port"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let port = UInt16(exactly: number.doubleValue), port > 0 else { throw InvalidField.port }
        guard let password = values["password"] as? String, !password.isEmpty else { throw InvalidField.password }
        guard let peerID = values["id"] as? Data, peerID.count == 16 else { throw InvalidField.peerID }
        self.port = port
        self.password = password
        self.peerID = peerID
        let ipv4 = values["dnsIpv4"] as? String ?? ""
        let ipv6 = values["dnsIpv6"] as? String ?? ""
        guard SettingsValidation.isValidDNSList(ipv4, ipv6: false) else { throw InvalidField.dnsIpv4 }
        guard SettingsValidation.isValidDNSList(ipv6, ipv6: true) else { throw InvalidField.dnsIpv6 }
        dnsIpv4 = Self.list(ipv4)
        dnsIpv6 = Self.list(ipv6)
        probeDomains = Self.list(values["probeDomains"] as? String)
        let mtu = (values["mtu"] as? String).flatMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
        mtuCap = min(max(mtu ?? Self.mtuUpperBound, Self.mtuLowerBound), Self.mtuUpperBound)
        self.clearLogsToken = clearLogsToken ?? values["clearLogsToken"] as? String
    }

    public var providerConfiguration: [String: Any] {
        var values: [String: Any] = [
            "host": host, "port": port, "password": password, "id": peerID,
            "dnsIpv4": dnsIpv4.joined(separator: ","), "dnsIpv6": dnsIpv6.joined(separator: ","),
            "probeDomains": probeDomains.joined(separator: ","), "mtu": String(mtuCap)
        ]
        if let clearLogsToken { values["clearLogsToken"] = clearLogsToken }
        return values
    }

    public func effectiveDNS(ipv4: Bool, ipv6: Bool) -> [String] {
        var servers: [String] = []
        if ipv4 { servers += dnsIpv4.isEmpty ? ["1.1.1.1", "8.8.8.8"] : dnsIpv4 }
        if ipv6 { servers += dnsIpv6.isEmpty ? ["2001:4860:4860::8888", "2001:4860:4860::8844"] : dnsIpv6 }
        return servers
    }

    private static func list(_ value: String?) -> [String] {
        (value ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
}

// MARK: - Applied tunnel configuration

/// Platform configuration that has either been requested or applied to the TUN.
public struct TunnelConfiguration: Equatable, Sendable {
    public let ipv4: String
    public let mask: String
    public let ipv6: String
    public let prefix: Int32
    public let mtu: Int
    public let dns: [String]

    public init(ipv4: String, mask: String, ipv6: String, prefix: Int32, mtu: Int, dns: [String] = []) {
        self.ipv4 = ipv4
        self.mask = mask
        self.ipv6 = ipv6
        self.prefix = prefix
        self.mtu = mtu
        self.dns = dns
    }

    public var addresses: String { ipv6.isEmpty ? ipv4 : "\(ipv4)/\(ipv6)" }
}

// MARK: - Traffic snapshot

/// In-memory provider snapshots. Both apps read them through provider status IPC.
public enum PacketStats {
    public struct Stats: Codable, Sendable {
        public var packetsSent: UInt64 = 0
        public var packetsReceived: UInt64 = 0
        public var bytesSent: UInt64 = 0
        public var bytesReceived: UInt64 = 0
        public var bytesSentPerSecond: UInt64 = 0
        public var bytesReceivedPerSecond: UInt64 = 0

        public static var zero: Stats { Stats() }
        public init() {}

        public init(_ core: TrafficStats) {
            packetsSent = UInt64(max(0, core.packetsSent))
            packetsReceived = UInt64(max(0, core.packetsReceived))
            bytesSent = UInt64(max(0, core.bytesSent))
            bytesReceived = UInt64(max(0, core.bytesReceived))
            bytesSentPerSecond = UInt64(max(0, core.sendSpeed))
            bytesReceivedPerSecond = UInt64(max(0, core.receiveSpeed))
        }
    }
}
