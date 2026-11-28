// SPDX-License-Identifier: MIT
import NetworkExtension
import os.log
import VaultCore

extension VpnManager {
    func createProviderManager(host: String) -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.serverAddress = host
        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Vault"
        return manager
    }

    func configureProviderManager(_ manager: NETunnelProviderManager, launch: TunnelLaunchConfiguration) -> Bool {
        guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else {
            Logger.network.errorAndFile("Invalid protocol configuration type")
            return false
        }
        #if os(macOS)
        // Older configurations can still point at the embedded app extension.
        configuration.providerBundleIdentifier = SystemExtensionManager.extensionBundleIdentifier
        #endif
        configuration.serverAddress = launch.host
        configuration.providerConfiguration = launch.providerConfiguration
        manager.protocolConfiguration = configuration
        manager.isEnabled = true
        manager.onDemandRules = [NEOnDemandRuleConnect()]
        #if os(iOS)
        // A manual startup is bounded by Vault, including when an older profile had On Demand enabled.
        manager.isOnDemandEnabled = false
        #else
        manager.isOnDemandEnabled = true
        #endif
        return true
    }
}
