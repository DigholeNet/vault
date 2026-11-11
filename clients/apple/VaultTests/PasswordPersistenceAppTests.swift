import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
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
        // Simulate the old instance servicing a queued status request after takeover.
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
}

extension VaultTests {
    func testRuntimeAssignedIP() throws {
        let (_, defaults) = try makeConfig()
        defaults.set("10.0.0.99", forKey: "ip")
        let passwords = PasswordPersistence(read: { "secret" }, write: { _ in }, readLegacy: { nil }, clearLegacy: {})
        _ = VaultConfig(defaults: defaults, passwords: passwords)
        XCTAssertNil(defaults.object(forKey: "ip"))
        let data = AppData()
        XCTAssertTrue(data.assignedIp.isEmpty)
        data.applyStatus(ProviderStatus(ip: "10.0.0.2", stats: .zero, session: "live"))
        XCTAssertEqual(data.assignedIp, "10.0.0.2")
        XCTAssertNil(defaults.object(forKey: "ip"))
        XCTAssertTrue(AppData().assignedIp.isEmpty)
        data.resetStats()
        XCTAssertTrue(data.assignedIp.isEmpty)
    }

    func testPasswordReadRetry() throws {
        let (_, defaults) = try makeConfig()
        var unavailable = true
        var writes: [String] = []
        let passwords = PasswordPersistence(read: {
            if unavailable { throw NSError(domain: "Keychain", code: 1) }
            return "saved-password"
        }, write: { writes.append($0) }, readLegacy: { nil }, clearLegacy: {})
        let config = VaultConfig(defaults: defaults, passwords: passwords)
        XCTAssertTrue(config.password.isEmpty)
        XCTAssertNotNil(config.passwordStorageError)
        unavailable = false
        config.retryPasswordStorage()
        XCTAssertEqual(config.password, "saved-password")
        XCTAssertNil(config.passwordStorageError)
        XCTAssertTrue(writes.isEmpty)
        config.retryPasswordStorage()
        XCTAssertTrue(writes.isEmpty)
        XCTAssertTrue(config.saveConnection(host: "test.invalid", port: 9527, password: "saved-password"))
        XCTAssertTrue(writes.isEmpty)
        XCTAssertTrue(config.saveConnection(host: "test.invalid", port: 9527, password: "replacement"))
        XCTAssertEqual(writes, ["replacement"])
    }

    func testPasswordMigrationRetry() throws {
        let (_, defaults) = try makeConfig()
        defaults.set("recovery", forKey: "password")
        var unavailable = true
        var writes: [String] = []
        let passwords = PasswordPersistence(
            read: { XCTFail("Migration retry should save the recovery copy")
                return "stale"
            },
            write: {
                if unavailable { throw NSError(domain: "Keychain", code: 1) }
                writes.append($0)
            },
            readLegacy: { defaults.string(forKey: "password") },
            clearLegacy: { defaults.removeObject(forKey: "password") }
        )
        let config = VaultConfig(defaults: defaults, passwords: passwords)
        XCTAssertEqual(config.password, "recovery")
        unavailable = false
        config.retryPasswordStorage()
        XCTAssertEqual(writes, ["recovery"])
        XCTAssertNil(config.passwordStorageError)
        XCTAssertNil(defaults.object(forKey: "password"))
    }

}
