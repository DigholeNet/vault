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
}
