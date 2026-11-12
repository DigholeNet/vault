// SPDX-License-Identifier: MIT
import CoreFoundation
import Foundation

// MARK: - Saved launch configuration

/// Immutable configuration stored in the OS VPN profile for on-demand restarts.
/// DNS settings use separate IPv4 and IPv6 fields; the old combined field is ignored.
public struct TunnelLaunchConfiguration {
    private static let parameters = tunnelParameters()
    public static let mtuLowerBound = Int(parameters.mtuMin)
    public static let mtuUpperBound = Int(parameters.mtuMax)

    public enum InvalidField: Error { case host, port, password, peerID, dnsIpv4, dnsIpv6, probeDomains }

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
        guard let number = values["port"] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              UInt16(exactly: number.doubleValue) != nil, number.doubleValue > 0 else { throw InvalidField.port }
        guard let password = values["password"] as? String else { throw InvalidField.password }
        guard let peerID = values["id"] as? Data, peerID.count == 16 else { throw InvalidField.peerID }
        let ipv4 = values["dnsIpv4"] as? String ?? ""
        let ipv6 = values["dnsIpv6"] as? String ?? ""
        let probes = values["probeDomains"] as? String ?? ""
        let validated: ValidatedEdgeSettings
        do {
            validated = try validateEdgeSettings(settings: EdgeSettings(
                host: rawHost, port: number.stringValue, password: password,
                dnsIpv4: ipv4, dnsIpv6: ipv6, mtu: "", probeDomains: probes
            ))
        } catch let error as SettingsError {
            throw Self.invalidField(error)
        }
        host = validated.host
        port = validated.port
        self.password = validated.password
        self.peerID = peerID
        dnsIpv4 = validated.dnsIpv4
        dnsIpv6 = validated.dnsIpv6
        probeDomains = validated.probeDomains
        let mtu = (values["mtu"] as? String).flatMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
        mtuCap = mtu.map { min(max($0, Self.mtuLowerBound), Self.mtuUpperBound) } ?? Self.mtuUpperBound
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
        (try? effectiveDnsServers(
            ipv4: ipv4, ipv6: ipv6, configuredIpv4: dnsIpv4, configuredIpv6: dnsIpv6
        )) ?? []
    }

    private static func invalidField(_ error: SettingsError) -> InvalidField {
        switch error {
        case .Host: .host
        case .Port: .port
        case .Password: .password
        case .PeerId: .peerID
        case .DnsIpv4: .dnsIpv4
        case .DnsIpv6: .dnsIpv6
        case .ProbeDomains: .probeDomains
        // Unreachable: mtu is always "" here, and Assignment only comes from
        // the parse helpers, not validateEdgeSettings.
        case .Mtu, .Assignment: .host
        }
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

    public init(assignment: TunnelAssignment, mtu: Int, dns: [String]) {
        ipv4 = assignment.ipv4?.address ?? ""
        mask = assignment.ipv4?.netmask ?? ""
        ipv6 = assignment.ipv6?.address ?? ""
        prefix = Int32(assignment.ipv6?.prefixLen ?? 0)
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
