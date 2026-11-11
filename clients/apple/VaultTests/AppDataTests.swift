import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

extension VaultTests {
    func testSessionStats() {
        let data = AppData()
        var stats = PacketStats.Stats.zero
        stats.bytesSent = 100
        stats.bytesReceived = 200
        data.applyStatus(ProviderStatus(ip: "10.0.0.2", stats: stats, session: "first"))
        // The replacement can already exceed the previous sample: the session
        // identity, rather than counter regression alone, must detect its reset.
        stats.bytesSent = 150
        stats.bytesReceived = 250
        stats.bytesSentPerSecond = 12
        data.applyStatus(ProviderStatus(ip: "10.0.0.3", stats: stats, session: "second"))
        XCTAssertEqual(data.bytesSent, 250)
        XCTAssertEqual(data.bytesReceived, 450)
        XCTAssertEqual(data.bytesSentPerSecond, 12)
        data.applyStatus(ProviderStatus(ip: "10.0.0.3", stats: stats, session: "second"))
        XCTAssertEqual(data.bytesSent, 250)
        data.resetStats()
        data.applyStatus(ProviderStatus(ip: "10.0.0.3", stats: stats, session: "second"))
        XCTAssertEqual(data.bytesSent, 150)
    }

    func testPublicIpUpdatesAndClears() {
        let data = AppData()
        let status = ProviderStatus(ip: "10.0.0.2", stats: .zero, session: "same", publicIp: "203.0.113.10")
        data.applyStatus(status)
        XCTAssertEqual(data.publicIp, "203.0.113.10")

        var updates = 0
        let observer = data.objectWillChange.sink { updates += 1 }
        defer { observer.cancel() }
        data.applyStatus(status)
        XCTAssertEqual(updates, 0)

        data.applyStatus(ProviderStatus(ip: "10.0.0.2", stats: .zero, session: "same", publicIp: "2001:db8::10"))
        XCTAssertEqual(updates, 1)
        XCTAssertEqual(data.publicIp, "2001:db8::10")
        data.applyStatus(ProviderStatus(ip: "10.0.0.2", stats: .zero, session: "same"))
        XCTAssertEqual(updates, 2)
        XCTAssertTrue(data.publicIp.isEmpty)

        data.applyStatus(status)
        data.resetStats()
        XCTAssertTrue(data.publicIp.isEmpty)
    }

    func testQuietStats() {
        let data = AppData()
        var stats = PacketStats.Stats.zero
        stats.bytesSent = 100
        stats.bytesReceived = 200
        stats.bytesReceivedPerSecond = 50
        let status = ProviderStatus(ip: "10.0.0.2", stats: stats, session: "same")
        data.applyStatus(status)
        var updates = 0
        let observer = data.objectWillChange.sink { updates += 1 }
        defer { observer.cancel() }
        data.applyStatus(status)
        XCTAssertEqual(updates, 0)
        stats.bytesReceivedPerSecond = 75
        data.applyStatus(ProviderStatus(ip: "10.0.0.2", stats: stats, session: "same"))
        XCTAssertEqual(updates, 1)
        XCTAssertEqual(data.bytesReceivedPerSecond, 75)
        XCTAssertEqual(data.bytesReceived, 200)
    }
}
