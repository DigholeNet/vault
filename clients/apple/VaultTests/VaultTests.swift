import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

final class VaultTests: XCTestCase {
    func makeConfig(password initialPassword: String = "") throws -> (config: VaultConfig, defaults: UserDefaults) {
        let suite = "VaultTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        var password = initialPassword
        let passwords = PasswordPersistence(
            read: { password }, write: { password = $0 },
            readLegacy: { defaults.string(forKey: "password") },
            clearLegacy: { defaults.removeObject(forKey: "password") }
        )
        return (VaultConfig(defaults: defaults, passwords: passwords), defaults)
    }

    func testConfigUsesIsolatedStorage() throws {
        let (config, defaults) = try makeConfig()
        XCTAssertFalse(config.id.isEmpty)
        XCTAssertEqual(defaults.string(forKey: "id"), config.id)
        XCTAssertTrue(config.saveConnection(host: "test.invalid", port: 9527, password: "test-password"))
        XCTAssertEqual(defaults.string(forKey: "host"), "test.invalid")
        XCTAssertEqual(config.password, "test-password")
        config.retryPasswordStorage()
        XCTAssertNil(config.passwordStorageError)
    }

    func testStatusKeys() {
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .disconnected), "Disconnected")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .connecting), "Connecting")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .connected), "Connected")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .disconnecting), "Disconnecting…")
    }

    func testConnectionToggle() {
        let data = AppData()
        for (status, enabled) in [(VpnStatus.disconnected, false), (.connecting, true), (.connected, true), (.disconnecting, false)] {
            data.vpnStatus = status
            XCTAssertEqual(data.vpnOn, enabled)
        }
    }

    #if os(macOS)
    func testConnectionAction() {
        XCTAssertEqual(ConnectionAction(status: .disconnected, configured: false), .configure)
        XCTAssertEqual(ConnectionAction(status: .disconnected, configured: true), .connect)
        for status in [VpnStatus.connecting, .connected, .disconnecting] {
            XCTAssertEqual(ConnectionAction(status: status, configured: false), .disconnect)
            XCTAssertEqual(ConnectionAction(status: status, configured: true), .disconnect)
        }
    }

    func testConnectionTitles() {
        let data = AppData()
        XCTAssertEqual(data.connectionActionTitle, "Connect")
        data.connectionError = "failed"
        XCTAssertEqual(data.connectionActionTitle, "Retry")
        data.vpnStatus = .connecting
        XCTAssertEqual(data.connectionActionTitle, "Cancel Connection")
        data.isRecovering = true
        XCTAssertEqual(data.connectionActionTitle, "Disconnect")
        data.vpnStatus = .connected
        XCTAssertEqual(data.connectionActionTitle, "Disconnect")
        data.vpnStatus = .disconnecting
        XCTAssertEqual(data.connectionActionTitle, "Disconnect")
        data.connectionError = nil
        XCTAssertEqual(data.connectionActionTitle, "Disconnecting…")
    }
    #endif

    func testAssignedAddressParsing() {
        let addresses = "192.168.10.2/2607:8700:5500:d2b6:0:1:0:3".parsedIPv4AndIPv6()
        XCTAssertEqual(addresses.ipv4, "192.168.10.2")
        XCTAssertEqual(addresses.ipv6, "2607:8700:5500:d2b6:0:1:0:3")
        XCTAssertNil("".parsedIPv4AndIPv6().ipv4)
        XCTAssertNil("192.168.10.2/".parsedIPv4AndIPv6().ipv6)
    }

    func testLicenses() throws {
        for name in ["LICENSE", "NOTICE"] {
            let url = try XCTUnwrap(Bundle.main.url(forResource: name, withExtension: nil))
            XCTAssertFalse(try String(contentsOf: url, encoding: .utf8).isEmpty)
        }
    }
}
