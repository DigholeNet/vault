import Foundation
import Testing
@testable import VaultCore

@Test func endedStatsSession() throws {
    var session = PacketStats.Session()
    #expect(session.status(ip: "") == nil)
    session.begin()
    var stats = PacketStats.Stats.zero
    stats.bytesSent = 100
    session.update(stats)
    let live = try #require(session.status(ip: "10.0.0.2", publicIp: "203.0.113.10"))
    #expect(live.stats.bytesSent == 100)
    #expect(live.publicIp == "203.0.113.10")
    #expect(session.status(ip: "10.0.0.3")?.session == live.session)

    session.end()
    // A status handler queued before cleanup executes against ended state.
    #expect(session.status(ip: "10.0.0.2") == nil)
    session.update(stats)
    #expect(session.status(ip: "10.0.0.2") == nil)
    session.end()

    session.begin()
    let restarted = try #require(session.status(ip: "10.0.0.4"))
    #expect(restarted.session != live.session)
    #expect(restarted.stats.bytesSent == 0)
    #expect(restarted.publicIp == nil)
    // A snapshot already sent before cleanup retains its original identity.
    #expect(live.stats.bytesSent == 100)
}

@Test func legacyProviderStatus() throws {
    let data = try JSONEncoder().encode(ProviderStatus(ip: "10.0.0.2", stats: .zero, session: "legacy"))
    let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    #expect(object["publicIp"] == nil)
    let decoded = try JSONDecoder().decode(ProviderStatus.self, from: data)
    #expect(decoded.ip == "10.0.0.2")
    #expect(decoded.publicIp == nil)
}
