import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

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
    var holdsDiagnosticContext = false
    var contextReplies: [(Data?) -> Void] = []
    var cancellationRequests = 0

    override func deliverProviderMessage(
        _ message: Data,
        manager: NETunnelProviderManager,
        completion: @escaping (Data?) -> Void
    ) throws {
        switch try ProviderCommandEnvelope.decode(message).command {
        case .diagnosticContext:
            if holdsDiagnosticContext { contextReplies.append(completion) }
            else { completion(try JSONEncoder().encode(context)) }
        case .cancelDiagnostics:
            cancellationRequests += 1
            completion(Data())
        case .status: completion(try JSONEncoder().encode(ProviderStatus(ip: context.ipv4, stats: .zero)))
        default:
            probeRequests += 1
            completion(nil)
        }
    }
}

extension VaultTests {
    @MainActor
    func testDiagnosticError() async throws {
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

    @MainActor
    func testDiagnosticCancelFinishesBeforeProviderReplyAndAllowsAnotherRun() async throws {
        let controller = InvalidDiagnosticContextVpnManager(config: try makeConfig().config, appData: AppData())
        let profile = TestTunnelManager()
        controller.activeVPN = profile
        controller.updateVPNStatus(profile)
        controller.holdsDiagnosticContext = true
        defer { controller.stopStatsMonitoring() }

        let model = DiagnosticsViewModel()
        model.run(using: controller)
        XCTAssertEqual(controller.contextReplies.count, 1)
        model.cancel(using: controller)
        XCTAssertFalse(model.running)
        XCTAssertTrue(model.wasCancelled)
        XCTAssertEqual(model.statusTitle, "Checks cancelled")
        XCTAssertNil(controller.diagnosticState.cancellation)
        XCTAssertEqual(controller.cancellationRequests, 1)

        let nextRunCompleted = expectation(description: "Replacement run completes independently")
        controller.requestDiagnostics { result in
            XCTAssertTrue(result?.summary.contains("INCOMPLETE - Rust diagnostics:") == true)
            nextRunCompleted.fulfill()
        }
        XCTAssertEqual(controller.contextReplies.count, 2)
        let nextRun = try XCTUnwrap(controller.diagnosticState.cancellation)
        let response = try JSONEncoder().encode(controller.context)
        controller.holdsDiagnosticContext = false
        controller.contextReplies[0](response)
        controller.contextReplies[1](response)
        XCTAssertTrue(controller.diagnosticState.cancellation === nextRun)
        await fulfillment(of: [nextRunCompleted], timeout: 3)
        XCTAssertNil(controller.diagnosticState.cancellation)
        XCTAssertEqual(model.statusTitle, "Checks cancelled")
    }
}
