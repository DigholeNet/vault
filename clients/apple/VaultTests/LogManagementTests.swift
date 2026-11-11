import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

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
        model.updateLogs("[rust] old log")
        model.logFilter = "ne"
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
        XCTAssertEqual(model.filteredLogText, "")
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

    @MainActor
    func testLogSnapshot() {
        let model = DiagnosticsViewModel()
        let text = "[app] ready\n[ne] DNS ready\n[rust] Handshake failed\n"
        model.updateLogs(text)
        XCTAssertEqual(model.filteredLogText, text)
        var updates = 0
        let observer = model.objectWillChange.sink { updates += 1 }
        defer { observer.cancel() }
        model.updateLogs(text)
        XCTAssertEqual(updates, 0)
        model.logFilter = "ne"
        XCTAssertEqual(model.filteredLogText, "[ne] DNS ready\n[rust] Handshake failed")
        model.logSearch = "HANDSHAKE"
        XCTAssertEqual(model.filteredLogText, "[rust] Handshake failed")
        model.updateLogs("[app] ready\n[rust] Handshake recovered")
        XCTAssertEqual(model.filteredLogText, "[rust] Handshake recovered")
        model.logFilter = "app"
        XCTAssertEqual(model.filteredLogText, "")
        model.logSearch = ""
        XCTAssertEqual(model.filteredLogText, "[app] ready")
    }

    @MainActor
    func testQuietLogRefresh() async {
        let controller = LogControlTestManager()
        let model = DiagnosticsViewModel()
        model.updateLogs("unchanged")
        var updates = 0
        let observer = model.objectWillChange.sink { updates += 1 }
        defer { observer.cancel() }
        let first = expectation(description: "first read")
        controller.onLogRead = { first.fulfill() }
        let refresh = Task { await model.refreshLogs(using: controller) }
        await fulfillment(of: [first], timeout: 2)
        let second = expectation(description: "next poll after unchanged reply")
        controller.onLogRead = { second.fulfill() }
        controller.logReply?.resume(returning: "unchanged")
        controller.logReply = nil
        await fulfillment(of: [second], timeout: 5)
        XCTAssertEqual(updates, 0)
        refresh.cancel()
        controller.logReply?.resume(returning: "cancelled reply")
        controller.logReply = nil
        await refresh.value
        XCTAssertEqual(updates, 0)
        XCTAssertEqual(model.logText, "unchanged")
    }

    @MainActor
    func testReplacedLogRefresh() async {
        let model = DiagnosticsViewModel()
        let oldStore = LogControlTestManager()
        let newStore = LogControlTestManager()
        let oldRead = expectation(description: "old read")
        oldStore.onLogRead = { oldRead.fulfill() }
        let oldRefresh = Task { await model.refreshLogs(using: oldStore) }
        await fulfillment(of: [oldRead], timeout: 2)
        oldRefresh.cancel()
        let newRead = expectation(description: "replacement read")
        newStore.onLogRead = { newRead.fulfill() }
        let newRefresh = Task { await model.refreshLogs(using: newStore) }
        await fulfillment(of: [newRead], timeout: 2)
        oldStore.logReply?.resume(returning: "stale logs")
        oldStore.logReply = nil
        await oldRefresh.value
        XCTAssertTrue(model.loadingLogs)
        XCTAssertEqual(model.logText, "")
        newRefresh.cancel()
        newStore.logReply?.resume(returning: "cancelled logs")
        newStore.logReply = nil
        await newRefresh.value
        XCTAssertFalse(model.loadingLogs)
        XCTAssertEqual(model.filteredLogText, "")
    }
}


#if os(macOS)
extension VaultTests {
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
}
#endif
