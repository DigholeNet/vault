//
//  VpnManager.swift
//  Vault
//
//
import NetworkExtension
import VaultCore
import os.log

let kProxyServiceVPNStatusNotification = "kProxyServiceVPNStatusNotification"

enum VpnStatus {
    case off
    case connecting
    case on
    case disconnecting
}

class VpnManager {
    let config: VaultConfig
    let appData: AppData

    var activeVPN: NETunnelProviderManager?
    private var observers: [NSObjectProtocol]
    /// Guards against repeated connect() invocations while a connect
    /// attempt is still in its async setup phase (vpnStatus is still .off
    /// and the UI control is still tappable in that window).
    private var connectInFlight = false

    fileprivate(set) var vpnStatus = VpnStatus.off {
        didSet {
            NotificationCenter.default.post(
                name: Notification.Name(kProxyServiceVPNStatusNotification),
                object: nil
            )
        }
    }

    init(
        config: VaultConfig,
        appData: AppData
    ) {
        self.config = config
        self.appData = appData
        self.observers = []

        #if os(macOS)
        // macOS: the provider is a system extension running outside the
        // user's session, so App Group UserDefaults are not shared with
        // it — stats and the assigned IP are queried over the NE
        // provider-message channel instead.
        appData.providerStatusQuery = { [weak self] completion in
            guard let self = self else { return completion(nil) }
            self.queryProviderStatus(completion: completion)
        }
        appData.onAssignedIp = { [weak self] ip in
            guard let self = self, self.config.ip != ip else { return }
            self.config.ip = ip
        }
        #endif
    }

    deinit {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    /// Pick this app's configuration from the list returned by
    /// `loadAllFromPreferences`, falling back to the first entry.
    private func preferredManager(
        from managers: [NETunnelProviderManager]
    ) -> NETunnelProviderManager? {
        return managers.first { $0.localizedDescription == "Vault" }
            ?? managers.first
    }

    func loadProviderManager(
        _ complete: @escaping (NETunnelProviderManager?) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, _) in
            if let managers = managers,
                let manager = self.preferredManager(from: managers) {
                complete(manager)
                return
            }
            complete(nil)
        }
    }

    func updateVPNStatus(_ manager: NEVPNManager) {
        let oldStatus = self.vpnStatus

        switch manager.connection.status {
        case .disconnected:
            self.vpnStatus = .off
        case .connecting:
            self.vpnStatus = .connecting
        case .connected:
            self.vpnStatus = .on
        case .disconnecting:
            self.vpnStatus = .disconnecting
        case .invalid:
            // Configuration was removed or became unusable (e.g. the user
            // deleted the VPN in system settings) — reflect it as off.
            self.vpnStatus = .off
        case .reasserting:
            // Network is re-asserting (e.g. Wi-Fi <-> cellular switch);
            // treat it as connecting so the UI doesn't show a fake "on".
            self.vpnStatus = .connecting
        @unknown default:
            break
        }

        if oldStatus != self.vpnStatus {
            // App-side record of tunnel state transitions; a connected ->
            // off transition the user did not initiate means the extension
            // died or the system stopped the tunnel.
            Logger.network.noticeAndFile(
                "VPN status: \(oldStatus) -> \(self.vpnStatus) (NEVPNStatus rawValue \(manager.connection.status.rawValue))"
            )
            if self.vpnStatus == .on {
                self.appData.startStatsMonitoring()
            } else if self.vpnStatus == .off {
                self.appData.stopStatsMonitoring()
            }
        }

        self.appData.vpnStatus = self.vpnStatus
        self.appData.vpnOn =
            (self.vpnStatus == VpnStatus.on
                || self.vpnStatus == VpnStatus.connecting)
    }

    fileprivate func createProviderManager() -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        let conf = NETunnelProviderProtocol()
        conf.serverAddress = self.config.host
        #if os(macOS)
        // On macOS the tunnel provider is a system extension with its own
        // bundle ID; without this the system looks for an embedded appex.
        conf.providerBundleIdentifier = SystemExtensionManager.extensionBundleIdentifier
        #endif
        manager.protocolConfiguration = conf
        manager.localizedDescription = "Vault"
        return manager
    }

    private func removeVpnStatusObservers() {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
        observers.removeAll()
    }

    private func observeVPNStatus(for manager: NETunnelProviderManager) {
        let observer = NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NEVPNStatusDidChange,
            object: manager.connection,
            queue: OperationQueue.main
        ) { [weak self] _ in
            self?.updateVPNStatus(manager)
        }
        observers.append(observer)
    }

    #if os(macOS)
    /// Query the tunnel provider for assigned IP and traffic counters.
    private func queryProviderStatus(completion: @escaping (ProviderStatus?) -> Void) {
        guard let manager = self.activeVPN else {
            reportQueryFailure("no activeVPN manager")
            completion(nil)
            return
        }
        guard let session = manager.connection as? NETunnelProviderSession else {
            reportQueryFailure("connection is not NETunnelProviderSession")
            completion(nil)
            return
        }
        do {
            try session.sendProviderMessage(Data()) { data in
                guard let data = data else {
                    self.reportQueryFailure("provider returned no data")
                    return completion(nil)
                }
                guard let status = try? JSONDecoder().decode(ProviderStatus.self, from: data)
                else {
                    self.reportQueryFailure("ProviderStatus decode failed")
                    return completion(nil)
                }
                self.reportQueryFailure(nil)
                completion(status)
            }
        } catch {
            reportQueryFailure("sendProviderMessage threw: \(error.localizedDescription)")
            completion(nil)
        }
    }

    /// Log only on state change; the query runs once per second.
    private var lastQueryFailure: String?
    private func reportQueryFailure(_ reason: String?) {
        guard reason != lastQueryFailure else { return }
        lastQueryFailure = reason
        if let reason = reason {
            Logger.network.errorAndFile("Provider status query failed: \(reason)")
        } else {
            Logger.network.noticeAndFile("Provider status query succeeded")
        }
    }
    #endif

    /// Load the existing VPN configuration, start observing status changes
    /// and sync the current status to the UI. Should be called once at app
    /// launch so the UI reflects the real VPN state.
    func startObservingStatus() {
        loadProviderManager { [weak self] manager in
            guard let self = self, let manager = manager else { return }
            self.activeVPN = manager
            self.observeVPNStatus(for: manager)
            DispatchQueue.main.async {
                self.updateVPNStatus(manager)
            }
        }
    }

    fileprivate func loadAndCreateProviderManager(
        _ complete: @escaping (NETunnelProviderManager?) -> Void
    ) {
        removeVpnStatusObservers()

        NETunnelProviderManager.loadAllFromPreferences {
            [self] (managers, error) in
            guard let managers = managers else {
                Logger.network.errorAndFile(
                    "loadAllFromPreferences failed: \(error?.localizedDescription ?? "unknown")"
                )
                complete(nil)
                return
            }
            // Diagnostic: duplicate saved configurations can make the
            // system run multiple providers/tunnels at once.
            Logger.network.noticeAndFile(
                "Loaded \(managers.count) VPN configuration(s): \(managers.compactMap { $0.localizedDescription })"
            )
            let manager: NETunnelProviderManager
            if let existing = self.preferredManager(from: managers) {
                manager = existing
            } else {
                manager = self.createProviderManager()
            }

            self.observeVPNStatus(for: manager)

            guard let idBytes = [UInt8](hex: self.config.id) else {
                Logger.network.errorAndFile("Invalid config id format")
                complete(nil)
                return
            }
            let id = Data(idBytes)

            var conf = [String: AnyObject]()
            conf["host"] = self.config.host as AnyObject
            conf["port"] = UInt16(self.config.port) as AnyObject

            conf["id"] = id as AnyObject
            // The password travels in providerConfiguration: on macOS the
            // provider is a system extension running outside the user's
            // session, so App Group UserDefaults are not shared with it.
            conf["password"] = self.config.password as AnyObject

            guard let originConf =
                manager.protocolConfiguration as? NETunnelProviderProtocol else {
                Logger.network.errorAndFile("Invalid protocol configuration type")
                complete(nil)
                return
            }
            #if os(macOS)
            // Configs created by older app-extension builds lack this and
            // keep launching the stale embedded appex.
            originConf.providerBundleIdentifier =
                SystemExtensionManager.extensionBundleIdentifier
            #endif
            originConf.providerConfiguration = conf
            manager.protocolConfiguration = originConf
            manager.isEnabled = true
            // Keep the tunnel up across suspends, network switches and
            // extension crashes: without an on-demand rule the system never
            // restarts a tunnel that died on its own.
            manager.onDemandRules = [NEOnDemandRuleConnect()]
            manager.isOnDemandEnabled = true

            manager.saveToPreferences { [self] error in
                if let error = error {
                    self.appData.vpnStatus = VpnStatus.off

                    if let neError = error as? NEVPNError,
                        neError.code == .configurationReadWriteFailed {
                        Logger.network.errorAndFile(
                            "User denied VPN configuration permission."
                        )
                    } else {
                        Logger.network.errorAndFile(
                            "Failed to save VPN configuration: \(error)"
                        )
                    }
                    complete(nil)
                    return
                }
                manager.loadFromPreferences {
                    if $0 != nil {
                        Logger.network.error(
                            "loadFromPreferences \($0.debugDescription)"
                        )
                        complete(nil)
                        return
                    }
                    complete(manager)
                }
            }
        }
    }
}

extension VpnManager {

    func connect(onError: @escaping () -> Void) {
        if self.config.host.isEmpty || self.config.password.isEmpty {
            self.appData.vpnStatus = VpnStatus.off
            self.appData.showConfigureGuide = true
            onError()
            return
        }

        guard !self.connectInFlight else {
            Logger.network.noticeAndFile("Connect already in progress, ignoring")
            return
        }
        self.connectInFlight = true
        Logger.network.noticeAndFile("connect() starting")

        #if os(macOS)
        // The tunnel provider is a system extension on macOS; make sure it is
        // activated (installing it if needed) before starting the tunnel.
        SystemExtensionManager.shared.ensureActivated { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success:
                self.startTunnel(onError: onError)
            case .failure(let error):
                self.connectInFlight = false
                Logger.network.error(
                    "System extension unavailable: \(error.localizedDescription, privacy: .public)"
                )
                self.appData.vpnStatus = VpnStatus.off
                onError()
            }
        }
        #else
        startTunnel(onError: onError)
        #endif
    }

    /// Save the VPN configuration and start the tunnel. Caller must hold
    /// connectInFlight; it is released here once the start attempt resolves.
    private func startTunnel(onError: @escaping () -> Void) {
        self.loadAndCreateProviderManager { (manager) in
            self.connectInFlight = false
            guard let manager = manager else {
                onError()
                return
            }
            do {
                self.activeVPN = manager
                Logger.network.noticeAndFile("calling startVPNTunnel()")
                try manager.connection.startVPNTunnel()
            } catch {
                Logger.network.errorAndFile("Start tunnel error \(error)")
                self.appData.vpnStatus = VpnStatus.off
                onError()
            }
        }
    }

    func disconnect() {
        Logger.network.noticeAndFile("disconnect() called")
        loadProviderManager { manager in
            guard let manager = manager else { return }
            // Disable on-demand first, otherwise the system immediately
            // restarts the tunnel we are trying to stop.
            if manager.isOnDemandEnabled {
                manager.isOnDemandEnabled = false
                manager.saveToPreferences { error in
                    if let error = error {
                        Logger.network.errorAndFile(
                            "Failed to disable on-demand before disconnect: \(error)"
                        )
                    }
                    manager.connection.stopVPNTunnel()
                }
            } else {
                manager.connection.stopVPNTunnel()
            }
            self.activeVPN = nil
        }
    }

}
