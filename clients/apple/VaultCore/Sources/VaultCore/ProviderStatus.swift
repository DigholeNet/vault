//
//  ProviderStatus.swift
//  VaultCore
//
//
//  Status payload returned by the tunnel provider over the Network
//  Extension provider-message channel (`sendProviderMessage` /
//  `handleAppMessage`).
//
//  Both apps query current assigned addresses for route diagnostics.
//  macOS also polls this payload for statistics because its system
//  extension runs outside the user's App Group session.
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
