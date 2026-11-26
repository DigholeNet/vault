@testable import Vault
import VaultCore
import XCTest

final class ConnectionDraftTests: XCTestCase {
    func testConnectionValidation() {
        func error(
            host: String = " vpn.example.com ", port: String = "9527",
            password: String = "secret", dnsIpv4: String = "", dnsIpv6: String = "", mtu: String = ""
        ) -> String? {
            var draft = ConnectionDraft()
            draft.name = "Test"
            draft.host = host
            draft.port = port
            draft.password = password
            draft.dnsIpv4 = dnsIpv4
            draft.dnsIpv6 = dnsIpv6
            draft.mtu = mtu
            return draft.validationError()
        }
        XCTAssertTrue(error() == nil)
        XCTAssertTrue(error(host: "https://vpn.example.com") != nil)
        XCTAssertTrue(error(port: "") != nil)
        XCTAssertTrue(error(port: "0") != nil)
        XCTAssertTrue(error(port: "65536") != nil)
        XCTAssertTrue(error(password: "") != nil)
        XCTAssertTrue(error(dnsIpv4: "1.1.1.1,") != nil)
        XCTAssertTrue(error(dnsIpv4: "::1") != nil)
        XCTAssertTrue(error(dnsIpv6: "1.1.1.1") != nil)
        XCTAssertTrue(error(mtu: "abc") != nil)
        XCTAssertTrue(error(dnsIpv4: "1.1.1.1", dnsIpv6: "::1", mtu: " 1280 ") == nil)
    }
}

extension ConnectionDraftTests {
    func testLaunchConfiguration() throws {
        var draft = ConnectionDraft()
        draft.name = "Test"
        draft.host = " vpn.example.com "
        draft.port = "9527"
        draft.password = " secret "
        draft.dnsIpv4 = " 1.1.1.1 "
        draft.dnsIpv6 = " ::1 "
        draft.mtu = " 1280 "
        let launch = try TunnelLaunchConfiguration(
            draft: draft, id: String(repeating: "ab", count: 16),
            probeDomains: " example.com, github.com ", clearLogsToken: "clear"
        )
        XCTAssertEqual(launch.host, "vpn.example.com")
        XCTAssertEqual(launch.password, " secret ")
        XCTAssertEqual(launch.dnsIpv4, ["1.1.1.1"])
        XCTAssertEqual(launch.dnsIpv6, ["::1"])
        XCTAssertEqual(launch.probeDomains, ["example.com", "github.com"])
        XCTAssertEqual(launch.mtuCap, 1280)
        XCTAssertEqual(launch.clearLogsToken, "clear")
        XCTAssertThrowsError(try TunnelLaunchConfiguration(draft: draft, id: "invalid"))
        draft.port = "65536"
        XCTAssertThrowsError(try TunnelLaunchConfiguration(draft: draft, id: String(repeating: "ab", count: 16)))
    }
}
