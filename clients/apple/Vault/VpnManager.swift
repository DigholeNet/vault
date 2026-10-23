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
                // The assigned address belongs to the session that just
                // ended; leaving it persisted would show a stale IP on the
                // status page and on the next app launch.
                self.config.ip = ""
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
            // Defensive clamp: a port persisted before range validation
            // existed must not trap UInt16(Int). Repair the stored value too.
            let port = min(max(self.config.port, 1), 65535)
            if port != self.config.port {
                Logger.network.errorAndFile(
                    "Persisted port \(self.config.port) out of range, clamping to \(port)"
                )
                self.config.port = port
            }
            conf["port"] = UInt16(port) as AnyObject
            conf["dns"] = self.config.dns as AnyObject
            conf["probeDomains"] = self.config.probeDomains as AnyObject
            conf["mtu"] = self.config.mtu as AnyObject

            conf["id"] = id as AnyObject
            // The password is persisted in the OS VPN providerConfiguration: on macOS the
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

    /// Send a provider-message command and return the raw reply. The reply
    /// arrives on an unspecified queue; nil means the message channel itself
    /// failed (no manager, not a provider session, no response).
    private func sendProviderCommand(_ command: String, completion: @escaping (Data?) -> Void) {
        struct Command: Codable { var command: String }
        let send: (NETunnelProviderManager) -> Void = { manager in
            guard let session = manager.connection as? NETunnelProviderSession else {
                Logger.network.errorAndFile("Provider command '\(command)' failed: connection is not NETunnelProviderSession")
                completion(nil)
                return
            }
            guard let message = try? JSONEncoder().encode(Command(command: command)) else {
                completion(nil)
                return
            }
            do {
                try session.sendProviderMessage(message) { data in
                    completion(data)
                }
            } catch {
                Logger.network.errorAndFile("Provider command '\(command)' failed: \(error.localizedDescription)")
                completion(nil)
            }
        }
        if let manager = self.activeVPN {
            send(manager)
        } else {
            loadProviderManager { manager in
                guard let manager = manager else {
                    Logger.network.errorAndFile("Provider command '\(command)' failed: no VPN manager")
                    completion(nil)
                    return
                }
                self.activeVPN = manager
                send(manager)
            }
        }
    }

    /// Ask the running provider to execute the connectivity probe suite.
    /// The reply arrives when the suite finishes (up to ~60s); nil means the
    /// message channel itself failed.
    func requestDiagnostics(completion: @escaping (DiagnosticsResult?) -> Void) {
        // The extension's own sockets bypass the tunnel, so only the app can
        // observe where the default route really sends user traffic. A
        // "Connected" tunnel whose routes never materialized is invisible to
        // every bound probe — check it here.
        let routeSuspects = checkDefaultRoutes()
        sendProviderCommand("diagnose") { data in
            guard let data = data,
                var result = try? JSONDecoder().decode(DiagnosticsResult.self, from: data)
            else {
                Logger.network.errorAndFile("Diagnostics request failed: provider returned no usable data")
                completion(nil)
                return
            }
            if !routeSuspects.isEmpty {
                if result.summary.hasPrefix("OK") {
                    result.summary = "PROBLEMS FOUND (route check)"
                }
                result.summary += "; "
                    + routeSuspects.map { "suspect: \($0)" }.joined(separator: "; ")
                result.lines.append(contentsOf: routeSuspects.map { "[probe] suspect: \($0)" })
            }
            completion(result)
        }
    }

    /// Compares the default route's chosen local addresses with the
    /// tunnel-assigned addresses. Any mismatch means user traffic of that
    /// family bypasses the tunnel even though the VPN shows Connected.
    private func checkDefaultRoutes() -> [String] {
        let routes = RouteCheck.defaultRouteLocalAddresses()
        let assigned = config.ip.parsedIPv4AndIPv6()
        Logger.network.noticeAndFile(
            "[probe] route check: default-route local addresses ipv4=\(routes.ipv4 ?? "none") ipv6=\(routes.ipv6 ?? "none"), tunnel assigned=\(config.ip.isEmpty ? "none" : config.ip)"
        )
        var suspects: [String] = []
        if let tunnelV4 = assigned.ipv4, routes.ipv4 != tunnelV4 {
            suspects.append(
                "IPv4 default route does not enter the tunnel (traffic would exit via \(routes.ipv4 ?? "nothing")); IPv4 bypasses the VPN"
            )
        }
        if let tunnelV6 = assigned.ipv6, routes.ipv6 != tunnelV6 {
            suspects.append(
                "IPv6 default route does not enter the tunnel (traffic would exit via \(routes.ipv6 ?? "nothing")); IPv6 bypasses the VPN"
            )
        }
        return suspects
    }

    #if os(macOS)
    /// The extension's log is trapped inside a sandboxed root daemon's
    /// container; the app can only obtain it over the provider-message
    /// channel while the tunnel is up. Every successful fetch is cached next
    /// to the app's own log so View Logs can still show the most recent
    /// extension log after the tunnel went down.
    private var extensionLogCacheURL: URL? {
        FileLogger.shared.currentLogPath.map {
            URL(fileURLWithPath: $0).deletingLastPathComponent()
                .appendingPathComponent("vault.ne.log")
        }
    }

    /// App log merged chronologically with the extension log (or its most
    /// recent cached copy when the provider is unreachable).
    func collectLogs() async -> String {
        async let appLog = FileLogger.shared.readLogAsync()
        let extensionLog: String? = await withCheckedContinuation { continuation in
            sendProviderCommand("logs") { data in
                continuation.resume(returning: data.flatMap { String(data: $0, encoding: .utf8) })
            }
        }
        var parts = [await appLog ?? ""]
        if let extensionLog, !extensionLog.isEmpty {
            if let cache = extensionLogCacheURL {
                try? extensionLog.write(to: cache, atomically: true, encoding: .utf8)
            }
            parts.append(extensionLog)
        } else if let cache = extensionLogCacheURL,
            let cached = try? String(contentsOf: cache, encoding: .utf8), !cached.isEmpty
        {
            parts.append(cached)
        }
        return FileLogger.mergeChronologically(parts.filter { !$0.isEmpty })
    }
    #endif

}
