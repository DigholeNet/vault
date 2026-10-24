import NetworkExtension
import XCTest
@testable import Vault

final class VaultTests: XCTestCase {
    func testConnectionStatusKeysAreSharedAndIndependentOfLanguage() {
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .off), "Disconnected")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .connecting), "Connecting")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .on), "Connected")
        XCTAssertEqual(VpnStatusUtil.titleKey(for: .disconnecting), "Disconnecting…")
    }

    func testConnectionToggleDerivesFromPublishedStatus() {
        let data = AppData()
        for (status, enabled) in [(VpnStatus.off, false), (.connecting, true), (.on, true), (.disconnecting, false)] {
            data.vpnStatus = status
            XCTAssertEqual(data.vpnOn, enabled)
        }
    }

    func testAssignedAddressParsing() {
        let addresses = "192.168.10.2/2607:8700:5500:d2b6:0:1:0:3".parsedIPv4AndIPv6()
        XCTAssertEqual(addresses.ipv4, "192.168.10.2")
        XCTAssertEqual(addresses.ipv6, "2607:8700:5500:d2b6:0:1:0:3")
        XCTAssertNil("".parsedIPv4AndIPv6().ipv4)
        XCTAssertNil("192.168.10.2/".parsedIPv4AndIPv6().ipv6)
    }
}

private final class TestVPNConnection: NEVPNConnection {
    var testStatus: NEVPNStatus = .connected
    var stopCalls = 0
    var onStop: (() -> Void)?
    override var status: NEVPNStatus { testStatus }
    override func stopVPNTunnel() {
        stopCalls += 1
        testStatus = .disconnecting
        onStop?()
    }
}

private final class TestTunnelManager: NETunnelProviderManager {
    let testConnection = TestVPNConnection()
    var onSave: (((Error?) -> Void)?) -> Void = { _ in }
    override var connection: NEVPNConnection { testConnection }
    override func saveToPreferences(completionHandler: ((Error?) -> Void)? = nil) {
        onSave(completionHandler)
    }
}

extension VaultTests {
    @MainActor
    func testDisconnectSaveFailureCanBeRetried() async {
        let data = AppData()
        let controller = VpnManager(config: VaultConfig(), appData: data)
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        controller.activeVPN = profile
        defer { data.stopStatsMonitoring() }

        let failed = expectation(description: "disconnect failed")
        profile.onSave = { completion in
            completion?(NSError(domain: NEVPNErrorDomain, code: NEVPNError.configurationReadWriteFailed.rawValue))
        }
        controller.disconnect { succeeded in
            XCTAssertFalse(succeeded)
            failed.fulfill()
        }
        await fulfillment(of: [failed], timeout: 2)
        XCTAssertEqual(data.vpnStatus, .on)
        XCTAssertNotNil(data.connectionError)
        XCTAssertTrue(profile.isOnDemandEnabled)
        XCTAssertEqual(profile.testConnection.stopCalls, 0)

        let stopped = expectation(description: "retry stopped tunnel")
        let completed = expectation(description: "retry completed")
        profile.onSave = { $0?(nil) }
        profile.testConnection.onStop = { stopped.fulfill() }
        controller.disconnect { succeeded in
            XCTAssertTrue(succeeded)
            completed.fulfill()
        }
        await fulfillment(of: [stopped], timeout: 2)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [completed], timeout: 2)
        XCTAssertEqual(data.vpnStatus, .off)
        XCTAssertNil(data.connectionError)
    }

    @MainActor
    func testDisconnectCompletionWaitsForSaveAndTunnelShutdown() async {
        let data = AppData()
        let controller = VpnManager(config: VaultConfig(), appData: data)
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        controller.activeVPN = profile
        let saving = expectation(description: "saving disabled on-demand rule")
        let stopping = expectation(description: "stopping tunnel")
        let completed = expectation(description: "cleanup completed")
        var saved: ((Error?) -> Void)?
        var finished = false
        profile.onSave = { saved = $0; saving.fulfill() }
        profile.testConnection.onStop = { stopping.fulfill() }
        controller.disconnect { succeeded in
            finished = true
            XCTAssertTrue(succeeded)
            completed.fulfill()
        }
        await fulfillment(of: [saving], timeout: 2)
        XCTAssertFalse(finished)
        XCTAssertEqual(profile.testConnection.stopCalls, 0)
        saved?(nil)
        await fulfillment(of: [stopping], timeout: 2)
        XCTAssertFalse(finished)
        XCTAssertEqual(data.vpnStatus, .disconnecting)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [completed], timeout: 2)
        XCTAssertEqual(data.vpnStatus, .off)
    }
}
