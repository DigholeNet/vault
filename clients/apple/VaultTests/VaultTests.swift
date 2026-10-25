import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

final class VaultTests: XCTestCase {
    private func makeConfig(password initialPassword: String = "") throws -> (config: VaultConfig, defaults: UserDefaults) {
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
    var startCalls = 0
    var startError: Error?
    var onStop: (() -> Void)?
    override var status: NEVPNStatus { testStatus }
    override func startVPNTunnel() throws {
        startCalls += 1
        if let startError { throw startError }
        testStatus = .connecting
    }

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
    func testDisconnectSaveRetry() async throws {
        let data = AppData()
        let controller = VpnManager(config: try makeConfig().config, appData: data)
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        controller.activeVPN = profile
        defer { controller.stopStatsMonitoring() }

        let failed = expectation(description: "disconnect failed")
        profile.onSave = { completion in
            completion?(NSError(domain: NEVPNErrorDomain, code: NEVPNError.configurationReadWriteFailed.rawValue))
        }
        controller.disconnect { succeeded in
            XCTAssertFalse(succeeded)
            failed.fulfill()
        }
        await fulfillment(of: [failed], timeout: 2)
        XCTAssertEqual(data.vpnStatus, .connected)
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
        XCTAssertEqual(data.vpnStatus, .disconnected)
        XCTAssertNil(data.connectionError)
    }

    @MainActor
    func testDisconnectCompletion() async throws {
        let data = AppData()
        let controller = VpnManager(config: try makeConfig().config, appData: data)
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        controller.activeVPN = profile
        let saving = expectation(description: "saving disabled on-demand rule")
        let stopping = expectation(description: "stopping tunnel")
        let completed = expectation(description: "cleanup completed")
        var saved: ((Error?) -> Void)?
        var finished = false
        profile.onSave = { saved = $0
            saving.fulfill()
        }
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
        XCTAssertEqual(data.vpnStatus, .disconnected)
    }
}

#if os(macOS)
private final class DelayedLoadVpnManager: VpnManager {
    var loaded: ((NETunnelProviderManager?, Error?) -> Void)?
    var onLoad: (() -> Void)?
    var prepared: ((NETunnelProviderManager?, Bool) -> Void)?
    var onPreparation: (() -> Void)?
    var preparationCalls = 0
    var activationRequests: [OSSystemExtensionRequest] = []
    var approvalPrompts = 0
    var startupProbe: ((Bool) -> Void)?
    var onStartupProbe: (() -> Void)?
    var usesRealStartupProbe = false
    var sentProviderMessages: [Data] = []
    var onProviderMessage: ((Data, @escaping (Data?) -> Void) -> Void)?

    override func deliverProviderMessage(
        _ message: Data,
        manager: NETunnelProviderManager,
        completion: @escaping (Data?) -> Void
    ) throws {
        sentProviderMessages.append(message)
        if let onProviderMessage { onProviderMessage(message, completion) }
        else { completion(nil) }
    }

    override func queryProviderStarted(completion: @escaping (Bool) -> Void) {
        if usesRealStartupProbe { super.queryProviderStarted(completion: completion)
            return
        }
        startupProbe = completion
        onStartupProbe?()
    }

    override func loadAndCreateProviderManager(_ complete: @escaping (NETunnelProviderManager?, Bool) -> Void) {
        preparationCalls += 1
        prepared = complete
        onPreparation?()
    }

    override func loadProviderManager(_ complete: @escaping (NETunnelProviderManager?, Error?) -> Void) {
        loaded = complete
        onLoad?()
    }
}

extension VaultTests {
    @MainActor
    private func makeController() throws -> DelayedLoadVpnManager {
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
    func testOfflineLogRead() async throws {
        let controller = try makeController()
        _ = await controller.collectLogs()
        XCTAssertNil(controller.loaded)
        XCTAssertTrue(controller.sentProviderMessages.isEmpty)
        XCTAssertNil(controller.activeVPN)
    }

    @MainActor
    func testUnavailableProviderLogs() async throws {
        for status in [NEVPNStatus.invalid, .disconnected, .connecting, .disconnecting, .reasserting] {
            let controller = try makeController()
            let profile = TestTunnelManager()
            profile.testConnection.testStatus = status
            controller.activeVPN = profile
            controller.appData.vpnStatus = .connected // Deliberately stale UI state.
            _ = await controller.collectLogs()
            XCTAssertTrue(controller.sentProviderMessages.isEmpty)
            XCTAssertNil(controller.loaded)
        }
        let controller = try makeController()
        controller.activeVPN = TestTunnelManager()
        controller.appData.vpnStatus = .connected
        controller.terminationInProgress = true
        _ = await controller.collectLogs()
        XCTAssertTrue(controller.sentProviderMessages.isEmpty)
    }

    @MainActor
    func testLateLogRead() async throws {
        let controller = try makeController()
        let profile = TestTunnelManager()
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        controller.stopStatsMonitoring()
        controller.sentProviderMessages.removeAll()
        let sent = expectation(description: "active provider log request sent")
        var reply: ((Data?) -> Void)?
        controller.onProviderMessage = { data, completion in
            let message = try? JSONDecoder().decode(ProviderCommandEnvelope.self, from: data)
            XCTAssertEqual(message?.command, .logs)
            reply = completion
            sent.fulfill()
        }
        let reading = Task { await controller.collectLogs() }
        await fulfillment(of: [sent], timeout: 2)
        controller.terminationInProgress = true
        profile.testConnection.testStatus = .disconnected
        let stale = "stale-provider-log-\(UUID().uuidString)"
        reply?(Data(stale.utf8))
        let logs = await reading.value
        XCTAssertFalse(logs.contains(stale))
        _ = await controller.collectLogs()
        XCTAssertEqual(controller.sentProviderMessages.count, 1)
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

    @MainActor
    func testActivationApprovalRetry() throws {
        for approvalBeforeCancellation in [true, false] {
            var requests: [OSSystemExtensionRequest] = []
            var prompts = 0
            let activation = SystemExtensionManager(
                submitRequest: { requests.append($0) },
                openApprovalSettings: { prompts += 1 }
            )
            activation.ensureActivated { _ in }
            let request = try XCTUnwrap(requests.first)
            if approvalBeforeCancellation { activation.requestNeedsUserApproval(request) }
            activation.cancelActivationWait()
            let previousPrompts = prompts
            if !approvalBeforeCancellation { activation.requestNeedsUserApproval(request) }
            XCTAssertEqual(prompts, previousPrompts)
            var activated = false
            activation.ensureActivated { result in
                if case .success = result { activated = true }
            }
            XCTAssertEqual(prompts, previousPrompts + 1)
            XCTAssertEqual(requests.count, 1)
            activation.request(request, didFinishWithResult: .completed)
            XCTAssertTrue(activated)
            activation.ensureActivated { _ in }
            XCTAssertEqual(requests.count, 2)
            XCTAssertEqual(prompts, previousPrompts + 1)
            activation.cancelActivationWait()
        }
    }

    @MainActor
    func testCancelledActivationRetry() throws {
        var requests: [OSSystemExtensionRequest] = []
        let activation = SystemExtensionManager(submitRequest: { requests.append($0) })
        var cancelled = false
        activation.ensureActivated { result in
            if case .failure(let error) = result { cancelled = error is CancellationError }
        }
        activation.cancelActivationWait()
        XCTAssertTrue(cancelled)
        var activated = false
        activation.ensureActivated { result in
            if case .success = result { activated = true }
        }
        XCTAssertEqual(requests.count, 1)
        activation.request(try XCTUnwrap(requests.first), didFinishWithResult: .completed)
        XCTAssertTrue(activated)
    }

    @MainActor
    func testLateActivationCompletion() throws {
        var request: OSSystemExtensionRequest?
        let activation = SystemExtensionManager(submitRequest: { request = $0 })
        var replies = 0
        activation.ensureActivated { _ in replies += 1 }
        activation.cancelActivationWait()
        activation.request(try XCTUnwrap(request), didFinishWithResult: .completed)
        XCTAssertEqual(replies, 1)
    }
}
#endif

@MainActor
private final class LogControlTestManager: RuntimeLogStore {
    var logReply: CheckedContinuation<String, Never>?
    var onLogRead: (() -> Void)?
    var clearComplete = true
    var clearError: Error?
    func collectLogs() async -> String {
        await withCheckedContinuation { continuation in
            logReply = continuation
            onLogRead?()
        }
    }

    func clearLogs() async throws -> Bool {
        if let clearError { throw clearError }
        return clearComplete
    }
}

extension VaultTests {
    @MainActor
    func testClearDuringRefresh() async throws {
        let controller = LogControlTestManager()
        let model = DiagnosticsViewModel()
        let reading = expectation(description: "old logs reading")
        controller.onLogRead = { reading.fulfill() }
        let refresh = Task { await model.refreshLogs(using: controller) }
        await fulfillment(of: [reading], timeout: 2)
        await model.clearLogs(using: controller)
        controller.logReply?.resume(returning: "old file contents")
        controller.logReply = nil
        let resumed = expectation(description: "old refresh resumed after clear")
        DispatchQueue.main.async { resumed.fulfill() }
        await fulfillment(of: [resumed], timeout: 2)
        XCTAssertEqual(model.logText, "")
        refresh.cancel()
        await refresh.value
        XCTAssertFalse(model.clearingLogs)
        XCTAssertNil(model.logMessage)
    }

    @MainActor
    func testClearLogsFailure() async throws {
        let controller = LogControlTestManager()
        let model = DiagnosticsViewModel()
        controller.clearComplete = false
        await model.clearLogs(using: controller)
        XCTAssertEqual(model.logMessage, "Local logs cleared. Provider logs will be cleared on the next connection.")
        controller.clearError = CocoaError(.fileWriteNoPermission)
        await model.clearLogs(using: controller)
        XCTAssertEqual(model.logMessage, "Unable to clear all log files. Please try again.")
        XCTAssertFalse(model.clearingLogs)
    }
}

extension VaultTests {
    func testDraftSaveValidatesBeforeWriting() throws {
        let config = try makeConfig().config
        var draft = config.connectionDraft
        draft.host = " test.invalid "
        draft.password = " secret "
        draft.dns = "invalid-dns"
        XCTAssertNotNil(config.save(draft))
        XCTAssertEqual(config.host, "")
        XCTAssertEqual(config.password, "")
        draft.dns = " 1.1.1.1 "
        draft.mtu = " 1280 "
        draft.probeDomains = " example.com "
        XCTAssertNil(config.save(draft))
        XCTAssertEqual(config.host, "test.invalid")
        XCTAssertEqual(config.password, " secret ")
        XCTAssertEqual(config.dns, "1.1.1.1")
        XCTAssertEqual(config.mtu, "1280")
        XCTAssertEqual(config.probeDomains, "example.com")
    }

    func testDraftSectionSavePreservesOtherSettings() throws {
        let config = try makeConfig().config
        var draft = config.connectionDraft
        draft.dns = "8.8.8.8"
        draft.mtu = "1280"
        // Network/advanced can be saved before connection settings are complete.
        XCTAssertNil(config.save(draft, section: .network))
        XCTAssertEqual(config.dns, "8.8.8.8")
        XCTAssertEqual(config.mtu, "")
        XCTAssertNil(config.save(draft, section: .advanced))
        XCTAssertEqual(config.mtu, "1280")
        draft.host = "test.invalid"
        draft.password = "secret"
        draft.dns = "invalid"
        XCTAssertNil(config.save(draft, section: .connection))
        XCTAssertEqual(config.host, "test.invalid")
        XCTAssertEqual(config.dns, "8.8.8.8")
    }

    func testDraftPasswordFailureLeavesSettingsIntact() throws {
        let suite = "VaultDraft.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        let passwords = PasswordPersistence(read: { "old" }, write: { _ in
            throw NSError(domain: "Keychain", code: 1)
        }, readLegacy: { nil }, clearLegacy: {})
        let config = VaultConfig(defaults: defaults, passwords: passwords)
        var draft = config.connectionDraft
        draft.host = "test.invalid"
        draft.password = "new"
        draft.dns = "1.1.1.1"
        XCTAssertNotNil(config.save(draft))
        XCTAssertEqual(config.host, "")
        XCTAssertEqual(config.password, "old")
        XCTAssertEqual(config.dns, "")
    }

    func testStatsAccumulateAcrossProviderSessions() {
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
}

private final class StatusQueryVpnManager: VpnManager {
    var replies: [(Data?) -> Void] = []
    override func deliverProviderMessage(
        _ message: Data,
        manager: NETunnelProviderManager,
        completion: @escaping (Data?) -> Void
    ) throws {
        replies.append(completion)
    }
}

extension VaultTests {
    @MainActor
    func testStatusPollingRejectsLateReplyAfterDisconnect() async throws {
        let data = AppData()
        let config = try makeConfig().config
        let controller = StatusQueryVpnManager(config: config, appData: data)
        let profile = TestTunnelManager()
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        defer { controller.stopStatsMonitoring() }
        XCTAssertEqual(controller.replies.count, 1)
        // Status flaps must neither stack timers nor overlap a pending IPC query.
        profile.testConnection.testStatus = .reasserting
        controller.updateVPNStatus(profile)
        profile.testConnection.testStatus = .connected
        controller.updateVPNStatus(profile)
        XCTAssertEqual(controller.replies.count, 1)
        profile.testConnection.testStatus = .disconnected
        controller.updateVPNStatus(profile)
        var stats = PacketStats.Stats.zero
        stats.bytesSent = 100
        let stale = ProviderStatus(ip: "10.0.0.2", stats: stats, session: "old")
        controller.replies[0](try JSONEncoder().encode(stale))
        let drained = expectation(description: "late reply delivered")
        DispatchQueue.main.async { drained.fulfill() }
        await fulfillment(of: [drained], timeout: 2)
        XCTAssertEqual(data.bytesSent, 0)
        XCTAssertEqual(data.assignedIp, "")
        XCTAssertEqual(controller.vpnStatus, .disconnected)
    }

    @MainActor
    func testStatusSnapshotPublishesAddressAndCountersTogether() async throws {
        let data = AppData()
        let config = try makeConfig().config
        let controller = StatusQueryVpnManager(config: config, appData: data)
        let profile = TestTunnelManager()
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        defer { controller.stopStatsMonitoring() }
        var stats = PacketStats.Stats.zero
        stats.bytesSent = 123
        let status = ProviderStatus(ip: "10.0.0.2", stats: stats, session: "live")
        let reply = try XCTUnwrap(controller.replies.first)
        reply(try JSONEncoder().encode(status))
        let drained = expectation(description: "status published")
        DispatchQueue.main.async { drained.fulfill() }
        await fulfillment(of: [drained], timeout: 2)
        XCTAssertEqual(data.bytesSent, 123)
        XCTAssertEqual(data.assignedIp, "10.0.0.2")
        // Mutating UI storage cannot change the controller's authoritative phase.
        data.vpnStatus = .disconnected
        XCTAssertEqual(controller.vpnStatus, .connected)
        controller.updateVPNStatus(profile)
        XCTAssertEqual(data.vpnStatus, .connected)
    }
}

extension VaultTests {
    func testProviderReplacementDoesNotCountCleanedUpTotalsTwice() throws {
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
    func testAssignedIpLivesOnlyInRuntimeState() throws {
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

    func testPasswordReadRetryDoesNotWriteCredentials() throws {
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

    func testPasswordMigrationRetryWritesRecoveryCopyOnce() throws {
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

    @MainActor
    func testProviderReplyArrivesOnMainOnceFromWorker() async throws {
        let controller = StatusQueryVpnManager(config: try makeConfig().config, appData: AppData())
        controller.activeVPN = TestTunnelManager()
        let completed = expectation(description: "one main-queue reply")
        var calls = 0
        controller.sendProviderCommand(.init(.diagnosticContext)) { response in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertEqual(response, Data([1]))
            calls += 1
            completed.fulfill()
        }
        let reply = try XCTUnwrap(controller.replies.first)
        DispatchQueue.global().async { reply(Data([1]))
            reply(Data([2]))
        }
        await fulfillment(of: [completed], timeout: 2)
        XCTAssertEqual(calls, 1)
    }

    @MainActor
    func testBlockedAndTimedOutProviderRepliesAreAsynchronousOnMain() async throws {
        let controller = StatusQueryVpnManager(config: try makeConfig().config, appData: AppData())
        let blocked = expectation(description: "blocked request")
        var called = false
        controller.sendProviderCommand(.init(.status)) { response in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertNil(response)
            called = true
            blocked.fulfill()
        }
        XCTAssertFalse(called)
        await fulfillment(of: [blocked], timeout: 2)
        controller.activeVPN = TestTunnelManager()
        let timedOut = expectation(description: "timeout on main")
        controller.sendProviderCommand(.init(.diagnosticContext), timeout: 0.01) { response in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertNil(response)
            timedOut.fulfill()
        }
        await fulfillment(of: [timedOut], timeout: 2)
    }
}

private final class InvalidDiagnosticContextVpnManager: VpnManager {
    let context = AppleDiagnosticContext(
        provider: "provider-test",
        generation: 7,
        ipv4: "10.0.0.2",
        mask: "255.255.255.0",
        ipv6: nil,
        mtu: 1427,
        dns: ["invalid-address"],
        domains: ["example.com"]
    )
    var probeRequests = 0

    override func deliverProviderMessage(
        _ message: Data,
        manager: NETunnelProviderManager,
        completion: @escaping (Data?) -> Void
    ) throws {
        switch try ProviderCommandEnvelope.decode(message).command {
        case .diagnosticContext: completion(try JSONEncoder().encode(context))
        case .status: completion(try JSONEncoder().encode(ProviderStatus(ip: context.ipv4, stats: .zero)))
        default:
            probeRequests += 1
            completion(nil)
        }
    }
}

extension VaultTests {
    @MainActor
    func testRustDiagnosticErrorIsPresentedByApp() async throws {
        let controller = InvalidDiagnosticContextVpnManager(config: try makeConfig().config, appData: AppData())
        let profile = TestTunnelManager()
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        defer { controller.stopStatsMonitoring() }
        let completed = expectation(description: "App presents the engine error")
        controller.requestDiagnostics { result in
            XCTAssertTrue(Thread.isMainThread)
            XCTAssertEqual(result?.engineState, .incomplete)
            XCTAssertNil(result?.snapshot)
            XCTAssertTrue(result?.summary.contains("INCOMPLETE - Rust diagnostics:") == true)
            XCTAssertNil(controller.diagnosticState.cancellation)
            completed.fulfill()
        }
        await fulfillment(of: [completed], timeout: 3)
        XCTAssertEqual(controller.probeRequests, 0)
    }
}
