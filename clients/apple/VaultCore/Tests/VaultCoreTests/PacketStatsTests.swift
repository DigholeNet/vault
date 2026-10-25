import Testing
@testable import VaultCore

@Test func endedStatsSessionRejectsQueuedReadsAndUpdates() throws {
    var session = PacketStats.Session()
    #expect(session.status(ip: "") == nil)
    session.begin()
    var stats = PacketStats.Stats.zero
    stats.bytesSent = 100
    session.update(stats)
    let live = try #require(session.status(ip: "10.0.0.2"))
    #expect(live.stats.bytesSent == 100)
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
    // A snapshot already sent before cleanup retains its original identity.
    #expect(live.stats.bytesSent == 100)
}
