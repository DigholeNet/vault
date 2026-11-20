import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

private final class StatusQueryVpnManager: VpnManager {
    var replies: [(Data?) -> Void] = []
    var messages: [Data] = []
    var activeVPNReadOffMain = false
    var onDeliver: (() -> Void)?
    override var activeVPN: NETunnelProviderManager? {
        get {
            activeVPNReadOffMain = activeVPNReadOffMain || !Thread.isMainThread
            return super.activeVPN
        }
        set { super.activeVPN = newValue }
    }

    override func deliverProviderMessage(
        _ message: Data,
        manager: NETunnelProviderManager,
        completion: @escaping (Data?) -> Void
    ) throws {
        messages.append(message)
        replies.append(completion)
        onDeliver?()
    }
}

extension VaultTests {
    @MainActor
    func testQuietPolling() async throws {
        let controller = StatusQueryVpnManager(config: try makeConfig().config, appData: AppData())
        let profile = TestTunnelManager()
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        controller.stopStatsMonitoring()
        for reply in controller.replies { reply(nil) }
        controller.replies.removeAll()
        controller.messages.removeAll()
        controller.providerMessages.lastMessageTrace.removeAll()

        for command in [ProviderCommand.status, .logs] {
            controller.sendProviderCommand(.init(command)) { _ in }
            try XCTUnwrap(controller.replies.popLast())(Data([1]))
            let initial = try XCTUnwrap(controller.providerMessages.lastMessageTrace[command])
            // An unchanged healthy context must stay quiet even after the
            // old thirty-second trace interval has elapsed.
            controller.providerMessages.lastMessageTrace[command] = (initial.signature, 0)
            controller.sendProviderCommand(.init(command)) { _ in }
            try XCTUnwrap(controller.replies.popLast())(Data([1]))
            XCTAssertEqual(controller.providerMessages.lastMessageTrace[command]?.time, 0)
            if command == .logs {
                let data = try XCTUnwrap(controller.messages.last)
                XCTAssertEqual(try ProviderCommandEnvelope.decode(data).trace, false)
            }

            profile.isOnDemandEnabled.toggle()
            controller.sendProviderCommand(.init(command)) { _ in }
            try XCTUnwrap(controller.replies.popLast())(Data([1]))
            XCTAssertNotEqual(controller.providerMessages.lastMessageTrace[command]?.signature, initial.signature)
            XCTAssertGreaterThan(controller.providerMessages.lastMessageTrace[command]?.time ?? 0, 0)
        }

        // Explicit diagnostic commands keep their existing tracing behavior.
        for _ in 0 ..< 2 {
            controller.sendProviderCommand(.init(.diagnosticContext)) { _ in }
            try XCTUnwrap(controller.replies.popLast())(Data([1]))
            let data = try XCTUnwrap(controller.messages.last)
            XCTAssertEqual(try ProviderCommandEnvelope.decode(data).trace, true)
        }
    }

    @MainActor
    func testLateStatusReply() async throws {
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
    func testStatusSnapshot() async throws {
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
    @MainActor
    func testWorkerReply() async throws {
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
    func testBlockedAndTimedOutReplies() async throws {
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

extension VaultTests {
    @MainActor
    func testWorkerCommand() async throws {
        let controller = StatusQueryVpnManager(config: try makeConfig().config, appData: AppData())
        controller.activeVPN = TestTunnelManager()
        let sent = expectation(description: "provider message sent")
        controller.onDeliver = { sent.fulfill() }
        let completed = expectation(description: "provider reply completed")
        DispatchQueue.global().async {
            controller.sendProviderCommand(.init(.diagnosticContext)) { response in
                XCTAssertTrue(Thread.isMainThread)
                XCTAssertEqual(response, Data([1]))
                completed.fulfill()
            }
        }
        await fulfillment(of: [sent], timeout: 2)
        XCTAssertFalse(controller.activeVPNReadOffMain)
        try XCTUnwrap(controller.replies.first)(Data([1]))
        await fulfillment(of: [completed], timeout: 2)
    }
}
