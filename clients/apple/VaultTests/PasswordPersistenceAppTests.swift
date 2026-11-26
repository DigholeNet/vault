import Combine
import NetworkExtension
import VaultCore
import XCTest
@testable import Vault

extension VaultTests {
    func testReplacementStats() throws {
        let data = AppData()
        var previous = PacketStats.Session()
        previous.begin()
        var stats = PacketStats.Stats.zero
        stats.bytesSent = 100
        previous.update(stats)
        data.applyStatus(try XCTUnwrap(previous.status(ip: "10.0.0.2")))

        previous.end()
        if let queued = previous.status(ip: "") { data.applyStatus(queued) }
        XCTAssertEqual(data.bytesSent, 100)

        var replacement = PacketStats.Session()
        replacement.begin()
        stats.bytesSent = 50
        replacement.update(stats)
        data.applyStatus(try XCTUnwrap(replacement.status(ip: "10.0.0.3")))
        XCTAssertEqual(data.bytesSent, 150)
        XCTAssertNil(previous.status(ip: ""))
    }

    func testRuntimeAssignedIP() throws {
        let (_, defaults) = try makeConfig()
        defaults.set("10.0.0.99", forKey: "ip")
        let config = VaultConfig(defaults: defaults)
        XCTAssertTrue(config.profiles.isEmpty)
        XCTAssertNil(defaults.object(forKey: "ip"))
        let data = AppData()
        XCTAssertTrue(data.assignedIp.isEmpty)
        data.requestedProfileName = "Work"
        data.switchingProfileName = "Work"
        data.applyStatus(ProviderStatus(
            ip: "10.0.0.2", stats: .zero, session: "live", profileName: "Work"
        ))
        XCTAssertEqual(data.assignedIp, "10.0.0.2")
        XCTAssertEqual(data.runningProfileName, "Work")
        XCTAssertNil(data.requestedProfileName)
        XCTAssertNil(data.switchingProfileName)
        data.resetStats()
        XCTAssertTrue(data.assignedIp.isEmpty)
        XCTAssertNil(data.runningProfileName)
    }
}
