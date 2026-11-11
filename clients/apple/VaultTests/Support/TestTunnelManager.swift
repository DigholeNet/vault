import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

final class TestVPNConnection: NEVPNConnection {
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

final class TestTunnelManager: NETunnelProviderManager {
    let testConnection = TestVPNConnection()
    var onSave: (((Error?) -> Void)?) -> Void = { _ in }
    override var connection: NEVPNConnection { testConnection }
    override func saveToPreferences(completionHandler: ((Error?) -> Void)? = nil) {
        onSave(completionHandler)
    }
}
