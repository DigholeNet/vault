import XCTest
@testable import Vault

final class VaultTests: XCTestCase {
    func testConnectionStatusKeysAreSharedAndIndependentOfLanguage() {
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .off), "Disconnected")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .connecting), "Connecting")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .on), "Connected")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .disconnecting), "Disconnecting…")
    }

    func testAssignedAddressParsing() {
        let addresses = "192.168.10.2/2607:8700:5500:d2b6:0:1:0:3".parsedIPv4AndIPv6()
        XCTAssertEqual(addresses.ipv4, "192.168.10.2")
        XCTAssertEqual(addresses.ipv6, "2607:8700:5500:d2b6:0:1:0:3")
        XCTAssertNil("".parsedIPv4AndIPv6().ipv4)
        XCTAssertNil("192.168.10.2/".parsedIPv4AndIPv6().ipv6)
    }
}
