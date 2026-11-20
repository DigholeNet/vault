import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

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
extension VaultTests {
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
