//
//  ProviderStatus.swift
//  VaultCore
//
//
//  Status payload returned by the tunnel provider over the Network
//  Extension provider-message channel (`sendProviderMessage` /
//  `handleAppMessage`).
//
//  macOS polls this payload for assigned addresses and statistics because
//  its system extension runs outside the user's App Group session.
//  Diagnostics obtains live configuration through diagnosticContext.
//

import Foundation

public struct ProviderStatus: Codable, Sendable {
    /// Addresses assigned by the supernode, "ipv4" or "ipv4/ipv6".
    public var ip: String
    public var stats: PacketStats.Stats

    public init(ip: String, stats: PacketStats.Stats) {
        self.ip = ip
        self.stats = stats
    }
}

/// Optional trace metadata; empty legacy status requests retain their wire form.
public struct ProviderCommandEnvelope: Codable {
    public var command: String
    public var requestID: String?
    public var trace: Bool?
    public var token: String?
    public var payload: Data?

    public static func tracedPayload(command: String, requestID: String, trace: Bool, payload: Data?) throws -> Data {
        if let payload, payload.isEmpty { return payload }
        var fields: [String: Any] = ["command": command]
        if let payload {
            guard let decoded = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else { return payload }
            fields = decoded
        }
        fields["requestID"] = requestID
        fields["trace"] = trace
        return try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    }
}
