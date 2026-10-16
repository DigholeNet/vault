//
//  ProviderStatus.swift
//  VaultCore
//
//
//  Status payload returned by the tunnel provider over the Network
//  Extension provider-message channel (`sendProviderMessage` /
//  `handleAppMessage`).
//
//  Needed on macOS: there the provider is a system extension running
//  outside the user's session, so App Group UserDefaults are not shared
//  between it and the app. The app queries this instead.
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
