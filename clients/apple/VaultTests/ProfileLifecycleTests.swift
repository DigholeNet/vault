import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

#if os(macOS)
extension VaultTests {
    @MainActor
    func makeController() throws -> DelayedLoadVpnManager {
        let storage = try makeConfig()
        let config = storage.config
        XCTAssertTrue(config.saveConnection(host: "test.invalid", port: 9527, password: "test-password"))
        let data = AppData()
        let controller = DelayedLoadVpnManager(config: config, appData: data)
        addTeardownBlock { await MainActor.run { controller.stopStatsMonitoring() } }
        controller.logPreferences = storage.defaults
        controller.systemExtensionManager = SystemExtensionManager(
            submitRequest: { [weak controller] in controller?.activationRequests.append($0) },
            openApprovalSettings: { [weak controller] in controller?.approvalPrompts += 1 }
        )
        return controller
    }

    @MainActor
    private func activate(_ controller: DelayedLoadVpnManager) async throws {
        let preparing = expectation(description: "profile preparation started")
        controller.onPreparation = { preparing.fulfill() }
        controller.systemExtensionManager.request(
            try XCTUnwrap(controller.activationRequests.last), didFinishWithResult: .completed
        )
        await fulfillment(of: [preparing], timeout: 2)
    }

    @MainActor
    private func drainMainQueue() async {
        let drained = expectation(description: "main queue callbacks processed")
        DispatchQueue.main.async { drained.fulfill() }
        await fulfillment(of: [drained], timeout: 2)
    }

    @MainActor
    func testInvalidConnect() async throws {
        for (host, password) in [("", ""), ("test.invalid", ""), ("", "test-password")] {
            let config = try makeConfig(password: password).config
            config.host = host
            let data = AppData()
            let controller = DelayedLoadVpnManager(config: config, appData: data)
            defer { controller.stopStatsMonitoring() }
            var startupFinished = false
            controller.startObservingStatus { startupFinished = true }
            let startupReply = try XCTUnwrap(controller.loaded)
            controller.connect()
            XCTAssertTrue(data.showConfigureGuide)
            XCTAssertEqual(data.vpnStatus, .disconnected)
            let profile = TestTunnelManager()
            startupReply(profile, nil)
            await drainMainQueue()
            XCTAssertTrue(controller.activeVPN === profile)
            XCTAssertEqual(data.vpnStatus, .connected)
            XCTAssertTrue(startupFinished)
            // The retained observer must continue following the real session.
            profile.testConnection.testStatus = .disconnected
            NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: profile.testConnection)
            XCTAssertEqual(data.vpnStatus, .disconnected)
        }
    }

    @MainActor
    func testApprovalCancellationRetry() async throws {
        let controller = try makeController()
        var startupFinished = false
        controller.startObservingStatus { startupFinished = true }
        let startupReply = try XCTUnwrap(controller.loaded)
        controller.connect()
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 1)
        let request = try XCTUnwrap(controller.activationRequests.first)
        let stopped = expectation(description: "cancelled activation stopped")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded)
            stopped.fulfill()
        }
        await drainMainQueue()
        controller.loaded?(nil, nil)
        await fulfillment(of: [stopped], timeout: 2)
        XCTAssertEqual(controller.vpnStatus, .disconnected)
        startupReply(TestTunnelManager(), nil)
        await drainMainQueue()
        XCTAssertNil(controller.activeVPN)
        XCTAssertFalse(startupFinished)
        controller.systemExtensionManager.requestNeedsUserApproval(request)
        XCTAssertEqual(controller.approvalPrompts, 0)
        controller.connect()
        XCTAssertEqual(controller.approvalPrompts, 1)
        XCTAssertEqual(controller.activationRequests.count, 1)
        try await activate(controller)
        XCTAssertEqual(controller.preparationCalls, 1)
    }

    @MainActor
    func testConnectDuringStop() async throws {
        let controller = try makeController()
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = false
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        let stopping = expectation(description: "stop issued")
        profile.testConnection.onStop = { stopping.fulfill() }
        controller.disconnect()
        await fulfillment(of: [stopping], timeout: 2)
        controller.connect()
        controller.connect()
        XCTAssertTrue(controller.activationRequests.isEmpty)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await drainMainQueue()
        XCTAssertEqual(controller.activationRequests.count, 1)
        XCTAssertEqual(controller.vpnStatus, .connecting)
    }

    @MainActor
    func testStopTimeout() async throws {
        let controller = try makeController()
        controller.tunnelStopTimeout = 0
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = false
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        let failed = expectation(description: "system stop timed out")
        var replies = 0
        controller.disconnect { succeeded in
            XCTAssertFalse(succeeded)
            replies += 1
            failed.fulfill()
        }
        await fulfillment(of: [failed], timeout: 2)
        XCTAssertTrue(controller.appData.canToggleConnection)
        XCTAssertNotNil(controller.appData.connectionError)
        controller.tunnelStopTimeout = 2
        let stopping = expectation(description: "retry issued")
        profile.testConnection.onStop = { stopping.fulfill() }
        let finished = expectation(description: "retry finished")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded)
            finished.fulfill()
        }
        await fulfillment(of: [stopping], timeout: 2)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [finished], timeout: 2)
        XCTAssertEqual(replies, 1)
    }

    @MainActor
    func testOnDemandPreparationRestart() async throws {
        let controller = try makeController()
        controller.connect()
        try await activate(controller)
        let profile = TestTunnelManager()
        controller.updateVPNStatus(profile)
        XCTAssertEqual(controller.vpnStatus, .connecting)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        controller.prepared?(profile, true)
        await drainMainQueue()
        XCTAssertEqual(controller.vpnStatus, .connecting)
        XCTAssertEqual(profile.testConnection.startCalls, 1)
        profile.testConnection.testStatus = .connected
        controller.updateVPNStatus(profile)
        XCTAssertEqual(controller.vpnStatus, .connected)
    }

    @MainActor
    func testOnDemandSingleStart() async throws {
        let controller = try makeController()
        controller.connect()
        try await activate(controller)
        let profile = TestTunnelManager()
        controller.updateVPNStatus(profile)
        XCTAssertEqual(controller.vpnStatus, .connecting)
        controller.prepared?(profile, true)
        await drainMainQueue()
        XCTAssertEqual(controller.vpnStatus, .connected)
        XCTAssertEqual(profile.testConnection.startCalls, 0)
        XCTAssertTrue(controller.activeVPN === profile)
    }

    @MainActor
    func testOnDemandReloadFailure() async throws {
        let controller = try makeController()
        controller.connect()
        try await activate(controller)
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        controller.updateVPNStatus(profile)
        let stopped = expectation(description: "failed reload still stops on-demand session")
        profile.onSave = { $0?(nil) }
        profile.testConnection.onStop = { stopped.fulfill() }
        controller.prepared?(profile, false)
        await fulfillment(of: [stopped], timeout: 2)
        XCTAssertFalse(profile.isOnDemandEnabled)
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        XCTAssertEqual(controller.vpnStatus, .disconnected)
        XCTAssertNotNil(controller.appData.connectionError)
    }

    @MainActor
    func testPreparationCancelCleanup() async throws {
        let controller = try makeController()
        controller.connect()
        try await activate(controller)
        let prepared = try XCTUnwrap(controller.prepared)
        var finished = false
        let stopped = expectation(description: "cancelled preparation cleaned up")
        controller.disconnect { succeeded in
            XCTAssertTrue(succeeded)
            finished = true
            stopped.fulfill()
        }
        await drainMainQueue()
        XCTAssertNil(controller.loaded) // No teardown lookup may overlap preparation.
        await drainMainQueue()
        XCTAssertFalse(finished)
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 1)
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        var saved: ((Error?) -> Void)?
        let saving = expectation(description: "late profile disabled")
        profile.onSave = { saved = $0
            saving.fulfill()
        }
        prepared(profile, true)
        await fulfillment(of: [saving], timeout: 2)
        XCTAssertEqual(profile.testConnection.startCalls, 0)
        XCTAssertFalse(finished)
        let stopping = expectation(description: "late tunnel stopped")
        profile.testConnection.onStop = { stopping.fulfill() }
        saved?(nil)
        await fulfillment(of: [stopping], timeout: 2)
        XCTAssertFalse(finished)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [stopped], timeout: 2)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 2)
    }

    @MainActor
    func testFailedStartCleanup() async throws {
        for reloadSucceeded in [false, true] {
            let controller = try makeController()
            controller.connect()
            try await activate(controller)
            let profile = TestTunnelManager()
            profile.isOnDemandEnabled = true
            profile.testConnection.testStatus = .disconnected
            profile.testConnection.startError = NEVPNError(.configurationInvalid)
            var saved: ((Error?) -> Void)?
            let saving = expectation(description: "failed connection profile cleanup")
            profile.onSave = { saved = $0
                saving.fulfill()
            }
            controller.prepared?(profile, reloadSucceeded)
            await fulfillment(of: [saving], timeout: 2)
            XCTAssertEqual(profile.testConnection.startCalls, reloadSucceeded ? 1 : 0)
            XCTAssertEqual(controller.vpnStatus, .disconnecting)
            // No second request: failed startup must report its error after cleanup.
            XCTAssertEqual(controller.activationRequests.count, 1)
            saved?(nil)
            await drainMainQueue()
            XCTAssertEqual(profile.testConnection.stopCalls, 0)
            XCTAssertEqual(controller.vpnStatus, .disconnected)
            XCTAssertNotNil(controller.appData.connectionError)
            XCTAssertFalse(profile.isOnDemandEnabled)
            controller.connect()
            XCTAssertEqual(controller.activationRequests.count, 2)
        }
    }

    @MainActor
    func testStaleStatusNotifications() async throws {
        let controller = try makeController()
        controller.connect()
        try await activate(controller)
        let first = TestTunnelManager()
        first.isOnDemandEnabled = true
        first.testConnection.testStatus = .disconnected
        controller.prepared?(first, true)
        await drainMainQueue()
        XCTAssertEqual(first.testConnection.startCalls, 1)
        first.testConnection.testStatus = .connected
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: first.testConnection)
        XCTAssertEqual(controller.vpnStatus, .connected)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 1)
        let stopping = expectation(description: "connected tunnel stopping")
        first.onSave = { $0?(nil) }
        first.testConnection.onStop = { stopping.fulfill() }
        controller.disconnect()
        await fulfillment(of: [stopping], timeout: 2)
        first.testConnection.testStatus = .disconnected
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: first.testConnection)
        XCTAssertEqual(controller.vpnStatus, .disconnected)
        controller.connect()
        try await activate(controller)
        let second = TestTunnelManager() // On-demand has already connected this profile.
        controller.prepared?(second, true)
        await drainMainQueue()
        XCTAssertEqual(second.testConnection.startCalls, 0)
        XCTAssertTrue(controller.activeVPN === second)
        XCTAssertEqual(controller.vpnStatus, .connected)
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: first.testConnection)
        XCTAssertEqual(controller.vpnStatus, .connected)
        XCTAssertNil(controller.appData.connectionError)
    }

    @MainActor
    func testActivationAndLoadRetry() async throws {
        let controller = try makeController()
        controller.connect()
        controller.systemExtensionManager.request(
            try XCTUnwrap(controller.activationRequests.first), didFailWithError: NEVPNError(.configurationInvalid)
        )
        await drainMainQueue()
        XCTAssertEqual(controller.vpnStatus, .disconnected)
        XCTAssertNotNil(controller.appData.connectionError)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 2)
        try await activate(controller)
        controller.prepared?(nil, false)
        await drainMainQueue()
        XCTAssertEqual(controller.vpnStatus, .disconnected)
        XCTAssertNotNil(controller.appData.connectionError)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 3)
    }

    @MainActor
    func testDisconnectLoadRetry() async throws {
        let controller = try makeController()
        let failed = expectation(description: "profile lookup failed")
        controller.disconnect { succeeded in XCTAssertFalse(succeeded)
            failed.fulfill()
        }
        await drainMainQueue()
        controller.loaded?(nil, NEVPNError(.configurationReadWriteFailed))
        await fulfillment(of: [failed], timeout: 2)
        XCTAssertEqual(controller.vpnStatus, .disconnected)
        let retried = expectation(description: "profile lookup retried")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded)
            retried.fulfill()
        }
        await drainMainQueue()
        controller.loaded?(nil, nil)
        await fulfillment(of: [retried], timeout: 2)
        XCTAssertEqual(controller.vpnStatus, .disconnected)
    }

    @MainActor
    func testQuitTimeoutRetry() async throws {
        let controller = try makeController()
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        controller.activeVPN = profile
        let saving = expectation(description: "quit cleanup started")
        var saved: ((Error?) -> Void)?
        profile.onSave = { saved = $0
            saving.fulfill()
        }
        var firstReplies = 0
        let timedOut = expectation(description: "quit cancelled on timeout")
        AppDelegate.disconnectBeforeTermination(controller, timeout: 0) { succeeded in
            XCTAssertFalse(succeeded)
            firstReplies += 1
            timedOut.fulfill()
        }
        await fulfillment(of: [saving, timedOut], timeout: 2)
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        controller.connect()
        XCTAssertTrue(controller.activationRequests.isEmpty)
        let retried = expectation(description: "next quit waits for cleanup")
        AppDelegate.disconnectBeforeTermination(controller, timeout: 2) { succeeded in
            XCTAssertTrue(succeeded)
            retried.fulfill()
        }
        let stopping = expectation(description: "quit tunnel stopped")
        profile.testConnection.onStop = { stopping.fulfill() }
        saved?(nil)
        await fulfillment(of: [stopping], timeout: 2)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [retried], timeout: 2)
        XCTAssertEqual(firstReplies, 1)
        XCTAssertEqual(controller.vpnStatus, .disconnected)
    }

    @MainActor
    func testCancelBeforeProviderStart() async throws {
        let controller = try makeController()
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        profile.testConnection.testStatus = .connecting
        controller.activeVPN = profile
        profile.onSave = { $0?(nil) }
        let probing = expectation(description: "waiting for provider to own the startup")
        controller.onStartupProbe = { probing.fulfill() }
        let completed = expectation(description: "cancellation finished")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded)
            completed.fulfill()
        }
        await fulfillment(of: [probing], timeout: 2)
        XCTAssertEqual(profile.testConnection.stopCalls, 0)
        XCTAssertFalse(profile.isOnDemandEnabled)
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        var repeatedCompletions = 0
        for _ in 0 ..< 10 {
            controller.disconnect { succeeded in
                XCTAssertTrue(succeeded)
                repeatedCompletions += 1
            }
            controller.connect()
        }
        XCTAssertTrue(controller.activationRequests.isEmpty)
        XCTAssertEqual(repeatedCompletions, 0)
        let stopping = expectation(description: "provider acknowledged startup, stopping is now safe")
        profile.testConnection.onStop = { stopping.fulfill() }
        controller.startupProbe?(true)
        await fulfillment(of: [stopping], timeout: 2)
        XCTAssertEqual(profile.testConnection.stopCalls, 1)
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [completed], timeout: 2)
        XCTAssertEqual(repeatedCompletions, 10)
        XCTAssertEqual(profile.testConnection.stopCalls, 1)
        XCTAssertNil(controller.appData.connectionError)
    }

    @MainActor
    func testCancelWithoutStartupReply() async throws {
        for startupSucceeded in [true, false] {
            let controller = try makeController()
            let profile = TestTunnelManager()
            profile.testConnection.testStatus = .connecting
            controller.activeVPN = profile
            let probing = expectation(description: "startup queried")
            controller.onStartupProbe = { probing.fulfill() }
            let completed = expectation(description: "startup settled")
            controller.disconnect { succeeded in XCTAssertTrue(succeeded)
                completed.fulfill()
            }
            await fulfillment(of: [probing], timeout: 2)
            profile.testConnection.testStatus = startupSucceeded ? .connected : .disconnected
            controller.startupProbe?(false)
            await drainMainQueue()
            XCTAssertEqual(profile.testConnection.stopCalls, startupSucceeded ? 1 : 0)
            if startupSucceeded {
                profile.testConnection.testStatus = .disconnected
                controller.updateVPNStatus(profile)
            }
            await fulfillment(of: [completed], timeout: 2)
            XCTAssertEqual(controller.vpnStatus, .disconnected)
            XCTAssertNil(controller.appData.connectionError)
        }
    }

    @MainActor
    func testStartupWaitTimeout() async throws {
        let controller = try makeController()
        controller.providerStartupTimeout = 0
        let profile = TestTunnelManager()
        profile.testConnection.testStatus = .connecting
        controller.activeVPN = profile
        let probing = expectation(description: "startup queried")
        controller.onStartupProbe = { probing.fulfill() }
        let failed = expectation(description: "unsafe cancellation rejected")
        controller.disconnect { succeeded in XCTAssertFalse(succeeded)
            failed.fulfill()
        }
        await fulfillment(of: [probing], timeout: 2)
        controller.startupProbe?(false)
        await fulfillment(of: [failed], timeout: 2)
        XCTAssertEqual(profile.testConnection.stopCalls, 0)
        XCTAssertEqual(controller.vpnStatus, .connecting)
        XCTAssertNotNil(controller.appData.connectionError)
        profile.testConnection.testStatus = .connected
        let stopping = expectation(description: "retry stops an initialized provider")
        profile.testConnection.onStop = { stopping.fulfill() }
        let completed = expectation(description: "retry completed")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded)
            completed.fulfill()
        }
        await fulfillment(of: [stopping], timeout: 2)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [completed], timeout: 2)
        XCTAssertNil(controller.appData.connectionError)
    }

    @MainActor
    func testQuitStatusMessages() async throws {
        let controller = try makeController()
        let profile = TestTunnelManager()
        controller.activeVPN = profile
        controller.terminationInProgress = true
        controller.updateVPNStatus(profile)
        await drainMainQueue()
        XCTAssertTrue(controller.sentProviderMessages.isEmpty)

        controller.stopStatsMonitoring()
        controller.usesRealStartupProbe = true
        profile.isOnDemandEnabled = false
        profile.testConnection.testStatus = .connecting
        controller.onProviderMessage = { message, completion in
            let envelope = try? JSONDecoder().decode(ProviderCommandEnvelope.self, from: message)
            XCTAssertEqual(envelope?.command, .startupStatus)
            completion(Data([1]))
        }
        let stopping = expectation(description: "quit safely stops initialized provider")
        profile.testConnection.onStop = { stopping.fulfill() }
        let completed = expectation(description: "quit stop completed")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded)
            completed.fulfill()
        }
        await fulfillment(of: [stopping], timeout: 2)
        XCTAssertEqual(controller.sentProviderMessages.count, 1)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        await fulfillment(of: [completed], timeout: 2)
    }

    @MainActor
    func testStaleStartupLoad() async throws {
        let data = AppData()
        let controller = DelayedLoadVpnManager(config: try makeConfig().config, appData: data)
        defer { controller.stopStatsMonitoring() }
        var startupFinished = false
        controller.startObservingStatus { startupFinished = true }
        let startupReply = try XCTUnwrap(controller.loaded)
        let current = TestTunnelManager()
        current.isOnDemandEnabled = false
        controller.activeVPN = current
        let stopping = expectation(description: "user disconnect superseded startup")
        let completed = expectation(description: "disconnect completed")
        current.testConnection.onStop = { stopping.fulfill() }
        controller.disconnect { _ in completed.fulfill() }
        await fulfillment(of: [stopping], timeout: 2)
        current.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(current)
        await fulfillment(of: [completed], timeout: 2)

        startupReply(TestTunnelManager(), nil)
        let drained = expectation(description: "startup reply processed")
        DispatchQueue.main.async { drained.fulfill() }
        await fulfillment(of: [drained], timeout: 2)
        XCTAssertTrue(controller.activeVPN === current)
        XCTAssertEqual(data.vpnStatus, .disconnected)
        XCTAssertFalse(startupFinished)
    }

}
#endif
