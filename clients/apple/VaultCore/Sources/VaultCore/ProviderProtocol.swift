// SPDX-License-Identifier: MIT
import Foundation

// MARK: - Status and command envelope

public struct ProviderStatus: Codable, Sendable {
    /// Stable for the lifetime of these counters; absent in legacy providers.
    public var session: String?
    /// Addresses assigned by the supernode, "ipv4" or "ipv4/ipv6".
    public var ip: String
    public var stats: PacketStats.Stats

    public init(ip: String, stats: PacketStats.Stats, session: String? = nil) {
        self.session = session
        self.ip = ip
        self.stats = stats
    }
}

public enum ProviderCommand: String, Codable, Sendable {
    case status, logs, startupStatus, diagnosticContext, diagnosticProbe, cancelDiagnostics, clearLogs
}

/// One wire envelope for every command; Data payloads use Codable's base64 encoding.
public struct ProviderCommandEnvelope: Codable, Sendable {
    public let command: ProviderCommand
    public let token: String?
    public let payload: Data?
    public private(set) var requestID: String?
    public private(set) var trace: Bool?

    public init(_ command: ProviderCommand, token: String? = nil, payload: Data? = nil) {
        self.command = command
        self.token = token
        self.payload = payload
    }

    public static func decode(_ data: Data) throws -> Self {
        if data.isEmpty { return Self(.status) }
        return try JSONDecoder().decode(Self.self, from: data)
    }

    public func encoded(requestID: String, trace: Bool) throws -> Data {
        // Retain the original empty status request for existing providers.
        if command == .status { return Data() }
        var envelope = self
        envelope.requestID = requestID
        envelope.trace = trace
        return try JSONEncoder().encode(envelope)
    }
}

// MARK: - Diagnostic requests and responses

/// Live provider configuration. Never construct this from cached AppStorage.
public struct AppleDiagnosticContext: Codable, Sendable {
    public var provider: String
    public var generation: UInt64
    public var connectionGeneration: UInt64
    public var ipv4: String
    public var mask: String
    public var ipv6: String?
    public var mtu: Int
    public var dns: [String]
    public var domains: [String]

    public init(
        provider: String, generation: UInt64, ipv4: String, mask: String,
        ipv6: String?, mtu: Int, dns: [String], domains: [String], connectionGeneration: UInt64 = 0
    ) {
        self.provider = provider
        self.generation = generation
        self.connectionGeneration = connectionGeneration
        self.ipv4 = ipv4
        self.mask = mask
        self.ipv6 = ipv6
        self.mtu = mtu
        self.dns = dns
        self.domains = domains
    }

    public func isSameSession(as other: AppleDiagnosticContext) -> Bool {
        provider == other.provider && generation == other.generation
            && connectionGeneration == other.connectionGeneration
            && ipv4 == other.ipv4 && mask == other.mask && ipv6 == other.ipv6 && mtu == other.mtu
    }

    public func makeEngine() throws -> DiagnosticEngine {
        let bytes = mask.split(separator: ".").compactMap { UInt8($0) }
        let bits = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let prefix: UInt8? =
            bytes.count == 4 && (bits == 0 || (bits | (bits &- 1)) == UInt32.max)
                ? UInt8(bits.nonzeroBitCount) : nil
        return try DiagnosticEngine(
            config: DiagnosticConfig(
                sessionId: generation,
                domains: domains, dnsServers: dns, tunnelIpv4: ipv4.isEmpty ? nil : ipv4,
                tunnelIpv4Prefix: prefix, tunnelIpv6: ipv6?.isEmpty == false ? ipv6 : nil,
                tunnelMtu: UInt16(clamping: mtu)
            )
        )
    }
}

/// Codable IPC request for one Rust-selected transport operation.
public struct AppleProbeRequest: Codable, Sendable {
    public enum Operation: Codable, Sendable, Equatable {
        case dns(server: String, ipv6: Bool)
        case tcp(address: String, port: UInt16)
        case https(address: String?)
        case ping(address: String, sequence: UInt16, packetSize: UInt16)
        case route
    }

    public var run: String
    public var provider: String
    public var generation: UInt64
    public var connectionGeneration: UInt64
    public var id: UInt64
    public var domain: String
    public var tunnel: Bool
    public var timeout: TimeInterval
    public var operation: Operation

    /// IPC dispatch and reply delivery must outlive the transport deadline so a
    /// normal probe timeout reaches the engine as a result, not a lost session.
    public var replyTimeout: TimeInterval { timeout + 3 }

    public init(
        request: DiagnosticRequest, context: AppleDiagnosticContext, run: String, remainingMs: UInt64
    ) {
        self.run = run
        provider = context.provider
        generation = context.generation
        connectionGeneration = context.connectionGeneration
        id = request.id
        domain = request.domain
        tunnel = request.scope == .tunnel
        timeout = Double(remainingMs) / 1000
        switch request.operation {
        case .route: operation = .route
        case .dns(let server, let ipv6): operation = .dns(server: server, ipv6: ipv6)
        case .tcp(let address, let port): operation = .tcp(address: address, port: port)
        case .https(let address, _): operation = .https(address: address)
        case .ping(let address, let sequence, let packetSize):
            operation = .ping(address: address, sequence: sequence, packetSize: packetSize)
        }
    }
}

public enum AppleProbeResponse: Codable, Sendable {
    case route(ipv4: String?, ipv6: String?)
    case dns(addresses: [String])
    case tcp
    case https(statusLine: String, receivedBytes: UInt32, tlsMs: UInt64, certificate: String)
    case ping(rttMs: UInt64)
    case failed(kind: DiagnosticErrorKind, detail: String)

    public init(_ value: DiagnosticResponse) {
        switch value {
        case .route(let v4, let v6): self = .route(ipv4: v4, ipv6: v6)
        case .dns(let addresses): self = .dns(addresses: addresses)
        case .tcp: self = .tcp
        case .https(let status, let bytes, let tls, let certificate):
            self = .https(statusLine: status, receivedBytes: bytes, tlsMs: tls, certificate: certificate)
        case .ping(let rtt): self = .ping(rttMs: rtt)
        case .failed(let kind, let detail): self = .failed(kind: kind, detail: detail)
        }
    }

    public var rust: DiagnosticResponse {
        switch self {
        case .route(let v4, let v6): return .route(ipv4: v4, ipv6: v6)
        case .dns(let addresses): return .dns(addresses: addresses)
        case .tcp: return .tcp
        case .https(let status, let bytes, let tls, let cert):
            return .https(statusLine: status, receivedBytes: bytes, tlsDurationMs: tls, certificate: cert)
        case .ping(let rtt): return .ping(rttMs: rtt)
        case .failed(let kind, let detail): return .failed(kind: kind, detail: detail)
        }
    }
}

public struct AppleProbeReply: Codable, Sendable {
    public var run: String
    public var id: UInt64
    public var response: AppleProbeResponse
    public init(request: AppleProbeRequest, response: AppleProbeResponse) {
        run = request.run
        id = request.id
        self.response = response
    }
}

extension DiagnosticErrorKind: Codable {
    private static var values: [Self] {
        [.timeout, .dns, .connect, .tls, .http, .permission, .unavailable, .invalidResponse]
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let name = try container.decode(String.self)
        guard let value = Self.values.first(where: { String(describing: $0) == name }) else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "unknown diagnostic error kind"
            )
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(String(describing: self))
    }
}
