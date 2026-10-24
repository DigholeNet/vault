import NetworkExtension
import XCTest
import VaultCore
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

final class VaultTests: XCTestCase {
    private func makeConfig() throws -> (config: VaultConfig, defaults: UserDefaults) {
        let suite = "VaultTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        var password = ""
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
    func testDisconnectSaveFailureCanBeRetried() async throws {
        let data = AppData()
        let controller = VpnManager(config: try makeConfig().config, appData: data)
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
    func testDisconnectCompletionWaitsForSaveAndTunnelShutdown() async throws {
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

#if os(macOS)
private final class DelayedLoadVpnManager: VpnManager {
    var loaded: ((NETunnelProviderManager?, Error?) -> Void)?
    var onLoad: (() -> Void)?
    var prepared: ((NETunnelProviderManager?, Bool) -> Void)?
    var onPreparation: (() -> Void)?
    var preparationCalls = 0
    var activationRequests: [OSSystemExtensionRequest] = []
    var approvalPrompts = 0

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
        let config = try makeConfig().config
        XCTAssertTrue(config.saveConnection(host: "test.invalid", port: 9527, password: "test-password"))
        let data = AppData()
        addTeardownBlock { await MainActor.run { data.stopStatsMonitoring() } }
        let controller = DelayedLoadVpnManager(config: config, appData: data)
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
    func testInvalidConnectPreservesStartupObservation() async throws {
        for (host, password) in [("", ""), ("test.invalid", ""), ("", "test-password")] {
            let config = try makeConfig().config
            config.host = host
            config.password = password
            let data = AppData()
            defer { data.stopStatsMonitoring() }
            let controller = DelayedLoadVpnManager(config: config, appData: data)
            var startupFinished = false
            controller.startObservingStatus { startupFinished = true }
            let startupReply = try XCTUnwrap(controller.loaded)
            controller.connect()
            XCTAssertTrue(data.showConfigureGuide)
            XCTAssertEqual(data.vpnStatus, .off)
            let profile = TestTunnelManager()
            startupReply(profile, nil)
            await drainMainQueue()
            XCTAssertTrue(controller.activeVPN === profile)
            XCTAssertEqual(data.vpnStatus, .on)
            XCTAssertTrue(startupFinished)
            // The retained observer must continue following the real session.
            profile.testConnection.testStatus = .disconnected
            NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: profile.testConnection)
            XCTAssertEqual(data.vpnStatus, .off)
        }
    }

    @MainActor
    func testStartupThenConnectThenApprovalCancellationAndRetry() async throws {
        let controller = try makeController()
        var startupFinished = false
        controller.startObservingStatus { startupFinished = true }
        let startupReply = try XCTUnwrap(controller.loaded)
        controller.connect()
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 1)
        let request = try XCTUnwrap(controller.activationRequests.first)
        let stopped = expectation(description: "cancelled activation stopped")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded); stopped.fulfill() }
        await drainMainQueue()
        controller.loaded?(nil, nil)
        await fulfillment(of: [stopped], timeout: 2)
        XCTAssertEqual(controller.vpnStatus, .off)
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
    func testCancelledPreparationWaitsForSavedProfileCleanupBeforeReconnect() async throws {
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
        controller.loaded?(nil, nil)
        await drainMainQueue()
        XCTAssertFalse(finished)
        XCTAssertEqual(controller.vpnStatus, .disconnecting)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 1)
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        var saved: ((Error?) -> Void)?
        let saving = expectation(description: "late profile disabled")
        profile.onSave = { saved = $0; saving.fulfill() }
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
    func testReloadAndStartFailuresCleanOnDemandBeforeAllowingRetry() async throws {
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
            let stopping = expectation(description: "failed connection tunnel stopped")
            profile.onSave = { saved = $0; saving.fulfill() }
            profile.testConnection.onStop = { stopping.fulfill() }
            controller.prepared?(profile, reloadSucceeded)
            await fulfillment(of: [saving], timeout: 2)
            XCTAssertEqual(profile.testConnection.startCalls, reloadSucceeded ? 1 : 0)
            XCTAssertEqual(controller.vpnStatus, .disconnecting)
            controller.connect()
            XCTAssertEqual(controller.activationRequests.count, 1)
            saved?(nil)
            await fulfillment(of: [stopping], timeout: 2)
            profile.testConnection.testStatus = .disconnected
            controller.updateVPNStatus(profile)
            XCTAssertEqual(controller.vpnStatus, .off)
            XCTAssertNotNil(controller.appData.connectionError)
            XCTAssertFalse(profile.isOnDemandEnabled)
            controller.connect()
            XCTAssertEqual(controller.activationRequests.count, 2)
        }
    }

    @MainActor
    func testConnectDisconnectReconnectIgnoresOldStatusNotifications() async throws {
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
        XCTAssertEqual(controller.vpnStatus, .on)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 1)
        let stopping = expectation(description: "connected tunnel stopping")
        first.onSave = { $0?(nil) }
        first.testConnection.onStop = { stopping.fulfill() }
        controller.disconnect()
        await fulfillment(of: [stopping], timeout: 2)
        first.testConnection.testStatus = .disconnected
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: first.testConnection)
        XCTAssertEqual(controller.vpnStatus, .off)
        controller.connect()
        try await activate(controller)
        let second = TestTunnelManager() // On-demand has already connected this profile.
        controller.prepared?(second, true)
        await drainMainQueue()
        XCTAssertEqual(second.testConnection.startCalls, 0)
        XCTAssertTrue(controller.activeVPN === second)
        XCTAssertEqual(controller.vpnStatus, .on)
        NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: first.testConnection)
        XCTAssertEqual(controller.vpnStatus, .on)
        XCTAssertNil(controller.appData.connectionError)
    }

    @MainActor
    func testActivationFailureAndProfileLoadFailureAllowRetry() async throws {
        let controller = try makeController()
        controller.connect()
        controller.systemExtensionManager.request(
            try XCTUnwrap(controller.activationRequests.first), didFailWithError: NEVPNError(.configurationInvalid)
        )
        await drainMainQueue()
        XCTAssertEqual(controller.vpnStatus, .off)
        XCTAssertNotNil(controller.appData.connectionError)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 2)
        try await activate(controller)
        controller.prepared?(nil, false)
        await drainMainQueue()
        XCTAssertEqual(controller.vpnStatus, .off)
        XCTAssertNotNil(controller.appData.connectionError)
        controller.connect()
        XCTAssertEqual(controller.activationRequests.count, 3)
    }

    @MainActor
    func testDisconnectLoadFailureAllowsAnotherDisconnect() async throws {
        let controller = try makeController()
        let failed = expectation(description: "profile lookup failed")
        controller.disconnect { succeeded in XCTAssertFalse(succeeded); failed.fulfill() }
        await drainMainQueue()
        controller.loaded?(nil, NEVPNError(.configurationReadWriteFailed))
        await fulfillment(of: [failed], timeout: 2)
        XCTAssertEqual(controller.vpnStatus, .off)
        let retried = expectation(description: "profile lookup retried")
        controller.disconnect { succeeded in XCTAssertTrue(succeeded); retried.fulfill() }
        await drainMainQueue()
        controller.loaded?(nil, nil)
        await fulfillment(of: [retried], timeout: 2)
        XCTAssertEqual(controller.vpnStatus, .off)
    }

    @MainActor
    func testQuitTimeoutThenLateCleanupAndQuitRetryReplyOnce() async throws {
        let controller = try makeController()
        let profile = TestTunnelManager()
        profile.isOnDemandEnabled = true
        controller.activeVPN = profile
        let saving = expectation(description: "quit cleanup started")
        var saved: ((Error?) -> Void)?
        profile.onSave = { saved = $0; saving.fulfill() }
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
        XCTAssertEqual(controller.vpnStatus, .off)
    }

    @MainActor
    func testLateLogLookupDoesNotReplaceActiveConnection() async throws {
        let controller = DelayedLoadVpnManager(config: try makeConfig().config, appData: AppData())
        let loading = expectation(description: "log profile lookup started")
        controller.onLoad = { loading.fulfill() }
        let reading = Task { await controller.collectLogs() }
        await fulfillment(of: [loading], timeout: 2)
        let current = TestTunnelManager()
        controller.activeVPN = current
        controller.loaded?(TestTunnelManager(), nil)
        _ = await reading.value
        XCTAssertTrue(controller.activeVPN === current)
    }

    @MainActor
    func testStaleStartupLoadDoesNotReplaceManagerOrRunAutoConnect() async throws {
        let data = AppData()
        defer { data.stopStatsMonitoring() }
        let controller = DelayedLoadVpnManager(config: try makeConfig().config, appData: data)
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
        XCTAssertEqual(data.vpnStatus, .off)
        XCTAssertFalse(startupFinished)
    }

    @MainActor
    func testActivationRetryReopensApprovalForBothCallbackOrders() throws {
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
    func testCancelledActivationCanBeRetriedWithoutAnotherOSRequest() throws {
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
    func testLateActivationCompletionDoesNotResumeCancelledConnection() throws {
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
