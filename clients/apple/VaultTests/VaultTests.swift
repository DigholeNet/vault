//
//  VaultTests.swift
//  VaultTests
//
//

import XCTest
@testable import Vault

class VaultTests: XCTestCase {

    func testVpnStatusUtil() {
        XCTAssertEqual(VpnStatusUtil.getStatus(.off), "Off")
        XCTAssertEqual(VpnStatusUtil.getStatus(.connecting), "Connecting")
        XCTAssertEqual(VpnStatusUtil.getStatus(.on), "On")
        XCTAssertEqual(VpnStatusUtil.getStatus(.disconnecting), "Disconnecting")
    }

    func testNumberFormatterNoneSeparator() {
        let formatter = NumberFormatter.noneSeparator
        XCTAssertEqual(formatter.numberStyle, .decimal)
        XCTAssertEqual(formatter.groupingSeparator, "")
    }

    func testVaultConfigDefaults() {
        let config = VaultConfig()
        XCTAssertEqual(config.port, 9527)
        XCTAssertFalse(config.id.isEmpty)
    }
}
