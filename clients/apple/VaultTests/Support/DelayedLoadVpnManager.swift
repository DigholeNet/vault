import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

#if os(macOS)
final class DelayedLoadVpnManager: VpnManager {
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
        if let onProviderMessage { onProviderMessage(message, completion) } else { completion(nil) }
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
#endif
