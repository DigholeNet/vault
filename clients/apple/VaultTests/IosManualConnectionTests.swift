#if os(iOS)
import NetworkExtension
@testable import Vault
import VaultCore
import XCTest

extension VaultTests {
    @MainActor
    func testIosManualFailureReleasesProfileSelection() async throws {
        let controller = try makeIosManualController()
        controller.connect()
        let manager = try XCTUnwrap(controller.managers.last)
        XCTAssertFalse(manager.isOnDemandEnabled)
        XCTAssertEqual(manager.testConnection.startCalls, 1)

        manager.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(manager)
        await drainIosMainQueue()

        XCTAssertEqual(controller.vpnStatus, .disconnected)
        XCTAssertEqual(controller.appData.connectionError, "Could not reach the server.")
        XCTAssertNil(controller.appData.requestedProfileName)
        XCTAssertFalse(controller.isProfileActive("Test"))
        controller.requestProfileSelection("Second")
        XCTAssertEqual(controller.config.selectedProfileName, "Second")
        XCTAssertEqual(controller.managers.count, 1)
    }

    @MainActor
    func testIosSwitchDuringStartupKeepsLatestProfileAndRecoversFromFailure() async throws {
        let controller = try makeIosManualController()
        controller.connect()
        let first = try XCTUnwrap(controller.managers.last)

        controller.requestProfileSelection("Second")
        controller.requestProfileSelection("Third")
        await drainIosMainQueue()
        XCTAssertEqual(first.testConnection.stopCalls, 1)
        XCTAssertEqual(controller.managers.count, 1)
        first.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(first)

        XCTAssertEqual(controller.config.selectedProfileName, "Third")
        XCTAssertEqual(controller.appData.requestedProfileName, "Third")
        XCTAssertEqual(controller.managers.count, 2)
        let third = try XCTUnwrap(controller.managers.last)
        third.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(third)
        await drainIosMainQueue()

        XCTAssertNil(controller.appData.switchingProfileName)
        XCTAssertNil(controller.appData.requestedProfileName)
        controller.requestProfileSelection("Second")
        XCTAssertEqual(controller.config.selectedProfileName, "Second")
        XCTAssertEqual(controller.managers.count, 2)
    }

    @MainActor
    func testIosFirstConnectionEnablesOnDemandAndSerializesUserStop() async throws {
        let controller = try makeIosManualController()
        controller.connect()
        let manager = try XCTUnwrap(controller.managers.last)
        var writes: [Bool] = []
        var completeWrite: ((Error?) -> Void)?
        manager.onSave = { [weak manager] completion in
            guard let manager else { return }
            writes.append(manager.isOnDemandEnabled)
            completeWrite = completion
        }
        defer { manager.onSave = { _ in } }

        manager.testConnection.testStatus = .connected
        controller.updateVPNStatus(manager)
        XCTAssertEqual(writes, [true])
        controller.disconnect()
        manager.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(manager)
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        XCTAssertEqual(writes, [true])

        try XCTUnwrap(completeWrite)(nil)
        await drainIosMainQueue()
        XCTAssertEqual(writes, [true, false])
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        try XCTUnwrap(completeWrite)(nil)
        await drainIosMainQueue()
        XCTAssertEqual(controller.vpnStatus, .disconnected)
        XCTAssertFalse(manager.isOnDemandEnabled)
    }

    @MainActor
    private func makeIosManualController() throws -> IosManualTestManager {
        let config = try makeConfig().config
        for name in ["Test", "Second", "Third"] {
            XCTAssertTrue(saveTestProfile(config, name: name))
        }
        let controller = IosManualTestManager(config: config, appData: AppData())
        addTeardownBlock { await MainActor.run { controller.stopStatsMonitoring() } }
        return controller
    }

    @MainActor
    private func drainIosMainQueue() async {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
    }
}

private final class IosManualTestManager: VpnManager {
    private(set) var managers: [TestTunnelManager] = []

    override func loadAndCreateProviderManager(
        launch: TunnelLaunchConfiguration,
        _ complete: @escaping (NETunnelProviderManager?, Bool, Error?) -> Void
    ) {
        let manager = TestTunnelManager()
        manager.protocolConfiguration = NETunnelProviderProtocol()
        manager.testConnection.testStatus = .disconnected
        manager.isOnDemandEnabled = true
        let configured = configureProviderManager(manager, launch: launch)
        managers.append(manager)
        complete(manager, configured, nil)
    }
}
#endif
