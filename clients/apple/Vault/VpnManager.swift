//
//  VpnManager.swift
//  Vault
//
//
import NetworkExtension
import VaultCore
import os.log

typealias VpnStatus = VPNConnectionLifecycle.Phase

class VpnManager {
    let config: VaultConfig
    let appData: AppData

    var activeVPN: NETunnelProviderManager?
    private var observers: [NSObjectProtocol]
    private var observationGeneration: UInt64 = 0
    private var connectionFailurePending = false
    private var connectionRequestedAt: TimeInterval?
    private var tunnelStartIssuedAt: TimeInterval?
    var logState = VpnLogState()
    var terminationInProgress = false
    var lastMessageTrace: [String: (signature: String, time: TimeInterval)] = [:]
    var logPreferences = UserDefaults.standard
    private var stopCompletions: [(Bool) -> Void] = []
    var tunnelStopTimeout: TimeInterval = 15
    private var tunnelStopTimeoutWorkItem: DispatchWorkItem?
    #if os(macOS)
    var systemExtensionManager = SystemExtensionManager.shared
    var providerStartupTimeout: TimeInterval = 30
    func queryProviderStarted(completion: @escaping (Bool) -> Void) {
        sendProviderCommand("startupStatus", timeout: 0.5) { completion($0 == Data([1])) }
    }
    #endif
    /// Serializes preparation, cancellation and teardown on both platforms.
    private var connectionLifecycle = VPNConnectionLifecycle()
    var providerOperation: (id: UInt64, preparing: Bool, stopping: Bool) {
        (connectionLifecycle.generation, connectionLifecycle.isPreparing, connectionLifecycle.isStopping)
    }
    private var connectInFlight: Bool { connectionLifecycle.isPreparing }

    var diagnosticState = VpnDiagnosticState()
    private(set) var vpnStatus: VpnStatus {
        get { appData.vpnStatus }
        set {
            if newValue != appData.vpnStatus {
                diagnosticState.generation &+= 1
                diagnosticState.cancellation?.cancel()
                appData.vpnStatus = newValue
            }
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

    /// Called only after the main-queue send gate has checked live state.
    func deliverProviderMessage(_ message: Data, manager: NETunnelProviderManager,
        completion: @escaping (Data?) -> Void) throws {
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw NEVPNError(.connectionFailed)
        }
        try session.sendProviderMessage(message, responseHandler: completion)
    }

    var canReadLiveProviderLogs: Bool {
        !terminationInProgress && !connectionLifecycle.isPreparing && !connectionLifecycle.isStopping
            && vpnStatus == .connected && activeVPN?.connection.status == .connected
    }

    func canSendProviderCommand(_ command: String, manager: NETunnelProviderManager) -> Bool {
        let status = manager.connection.status
        // Startup acknowledgement is part of safe cancellation, including Quit.
        if command == "startupStatus" {
            return status == .connecting || status == .connected || status == .reasserting
        }
        guard !terminationInProgress, !connectionLifecycle.isPreparing, !connectionLifecycle.isStopping else { return false }
        if command == "logs" { return canReadLiveProviderLogs && manager === activeVPN }
        return status == .connected || status == .reasserting
    }

    private func logStage(_ stage: String, operation: UInt64, since started: TimeInterval, error: Error? = nil) {
        let elapsed = Int(((ProcessInfo.processInfo.systemUptime - started) * 1000).rounded())
        let message = "[operation:\(operation)] \(stage) durationMs=\(elapsed)"
        if let error { Logger.network.errorAndFile("\(message) error=\(error.localizedDescription)") }
        else { Logger.network.noticeAndFile(message) }
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
        _ complete: @escaping (NETunnelProviderManager?, Error?) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
            if let error { complete(nil, error); return }
            if let managers = managers,
                let manager = self.preferredManager(from: managers) {
                complete(manager, nil)
                return
            }
            complete(nil, nil)
        }
    }

    func updateVPNStatus(_ manager: NEVPNManager) {
        // On-demand can connect and disconnect while preferences are saving.
        // Preparation owns the operation until its callback reads the current
        // session status; intermediate notifications must not complete it.
        if connectInFlight { return }
        var stopResult: Bool?
        if connectionLifecycle.isStopping {
            let down = manager.connection.status == .disconnected || manager.connection.status == .invalid
            guard connectionLifecycle.completeStopIfReady(tunnelDown: down) else {
                publishStatus(.disconnecting)
                appData.connectionError = nil
                return
            }
            stopResult = !connectionLifecycle.stopFailed
        }
        let oldStatus = self.vpnStatus

        let status: VpnStatus
        switch manager.connection.status {
        case .disconnected, .invalid: status = .disconnected
        case .connecting, .reasserting: status = .connecting
        case .connected: status = .connected
        case .disconnecting: status = .disconnecting
        @unknown default: status = vpnStatus
        }
        publishStatus(status, recovering: manager.connection.status == .reasserting)

        updateSessionDetails(manager, previousStatus: oldStatus)

        if stopResult == nil, self.vpnStatus == .connected { connectionLifecycle.observedConnected() }
        let unexpectedDisconnect = stopResult == nil && self.vpnStatus == .disconnected && connectionLifecycle.observedDisconnected()
        if self.vpnStatus == .connected {
            self.appData.connectionError = nil
        } else if self.vpnStatus == .disconnected {
            if unexpectedDisconnect {
                self.appData.connectionError = "Connection ended unexpectedly. Check your network and server configuration."
            }
        }
        if let stopResult { finishDisconnect(succeeded: stopResult) }
    }

    private func publishStatus(_ status: VpnStatus, recovering: Bool = false) {
        vpnStatus = status
        #if os(macOS)
        appData.isRecovering = recovering
        #endif
    }

    private func updateSessionDetails(_ manager: NEVPNManager, previousStatus oldStatus: VpnStatus) {
        if oldStatus != self.vpnStatus {
            // App-side record of tunnel state transitions; a connected ->
            // off transition the user did not initiate means the extension
            // died or the system stopped the tunnel.
            Logger.network.noticeAndFile(
                """
                VPN status: \(oldStatus) -> \(self.vpnStatus) (NEVPNStatus rawValue \
                \(manager.connection.status.rawValue)) terminating=\(terminationInProgress) interfaces=\(FileLogger.tunnelInterfaceSummary())
                """
            )
            if self.vpnStatus == .connected {
                if let started = connectionRequestedAt {
                    logStage("Connection ready", operation: connectionLifecycle.generation, since: started)
                    connectionRequestedAt = nil
                }
                if let issued = tunnelStartIssuedAt {
                    logStage("System tunnel startup completed", operation: connectionLifecycle.generation, since: issued)
                    tunnelStartIssuedAt = nil
                }
                self.appData.startStatsMonitoring()
                self.queryProviderStatus { status in
                    if let ip = status?.ip, !ip.isEmpty { self.config.ip = ip }
                }
            } else if self.vpnStatus == .disconnected {
                self.appData.stopStatsMonitoring()
                // The assigned address belongs to the session that just
                // ended; leaving it persisted would show a stale IP on the
                // status page and on the next app launch.
                self.config.ip = ""
            }
        }

        if self.vpnStatus == .connected, self.appData.connectedSince == nil {
            self.appData.connectedSince = manager.connection.connectedDate ?? Date()
        } else if self.vpnStatus == .disconnected {
            self.appData.connectedSince = nil
        }
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
        observationGeneration &+= 1
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
        observers.removeAll()
    }

    private func observeVPNStatus(for manager: NETunnelProviderManager) {
        removeVpnStatusObservers()
        let generation = observationGeneration
        let observer = NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NEVPNStatusDidChange,
            object: manager.connection,
            queue: OperationQueue.main
        ) { [weak self] _ in
            guard let self, self.observationGeneration == generation else { return }
            self.updateVPNStatus(manager)
        }
        observers.append(observer)
    }

    /// Read authoritative session addresses on both platforms. An AppStorage
    /// value can lag another process, so diagnostics must not use it as evidence.
    private func queryProviderStatus(completion: @escaping (ProviderStatus?) -> Void) {
        guard let connection = activeVPN?.connection else { completion(nil); return }
        let generation = diagnosticState.generation
        sendProviderCommand("status", timeout: 3, payload: Data()) { data in
            DispatchQueue.main.async {
                guard self.diagnosticState.generation == generation,
                    self.activeVPN?.connection === connection,
                    connection.status == .connected || connection.status == .reasserting else {
                    completion(nil)
                    return
                }
                guard let data, let status = try? JSONDecoder().decode(ProviderStatus.self, from: data) else {
                    self.reportQueryFailure("provider status unavailable or invalid")
                    completion(nil)
                    return
                }
                self.reportQueryFailure(nil)
                completion(status)
            }
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

    /// Load the existing VPN configuration, start observing status changes
    /// and sync the current status to the UI. Should be called once at app
    /// launch so the UI reflects the real VPN state.
    func startObservingStatus(completion: (() -> Void)? = nil) {
        let generation = connectionLifecycle.generation
        loadProviderManager { [weak self] manager, _ in
            DispatchQueue.main.async {
                // A user action supersedes startup, including its auto-connect callback.
                guard let self, self.connectionLifecycle.generation == generation else { return }
                if let manager {
                    self.activeVPN = manager
                    self.observeVPNStatus(for: manager)
                    self.updateVPNStatus(manager)
                }
                completion?()
            }
        }
    }

    func loadAndCreateProviderManager(
        _ complete: @escaping (NETunnelProviderManager?, _ loaded: Bool) -> Void
    ) {
        removeVpnStatusObservers()
        let operation = connectionLifecycle.generation
        let loadStarted = ProcessInfo.processInfo.systemUptime
        Logger.network.noticeAndFile("[operation:\(operation)] Loading VPN configurations")

        NETunnelProviderManager.loadAllFromPreferences {
            [self] (managers, error) in
            DispatchQueue.main.async {
                self.logStage("VPN configurations loaded", operation: operation, since: loadStarted, error: error)
                guard let managers = managers else {
                    Logger.network.errorAndFile(
                        "loadAllFromPreferences failed: \(error?.localizedDescription ?? "unknown")"
                    )
                    complete(nil, false)
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

                guard let idBytes = [UInt8](hex: self.config.id) else {
                    Logger.network.errorAndFile("Invalid config id format")
                    complete(nil, false)
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
                if let token = self.logPreferences.string(forKey: "clearLogsToken") {
                    conf["clearLogsToken"] = token as AnyObject
                }

                conf["id"] = id as AnyObject
                // The password is persisted in the OS VPN providerConfiguration: on macOS the
                // provider is a system extension running outside the user's
                // session, so App Group UserDefaults are not shared with it.
                conf["password"] = self.config.password as AnyObject

                guard let originConf =
                    manager.protocolConfiguration as? NETunnelProviderProtocol else {
                    Logger.network.errorAndFile("Invalid protocol configuration type")
                    complete(nil, false)
                    return
                }
                #if os(macOS)
                // Configs created by older app-extension builds lack this and
                // keep launching the stale embedded appex.
                originConf.providerBundleIdentifier =
                    SystemExtensionManager.extensionBundleIdentifier
                #endif
                originConf.serverAddress = self.config.host
                originConf.providerConfiguration = conf
                manager.protocolConfiguration = originConf
                manager.isEnabled = true
                // Keep the tunnel up across suspends, network switches and
                // extension crashes: without an on-demand rule the system never
                // restarts a tunnel that died on its own.
                manager.onDemandRules = [NEOnDemandRuleConnect()]
                manager.isOnDemandEnabled = true

                let saveStarted = ProcessInfo.processInfo.systemUptime
                Logger.network.noticeAndFile("[operation:\(operation)] Saving VPN configuration onDemand=true")
                manager.saveToPreferences { error in
                    self.logStage("VPN configuration save completed", operation: operation, since: saveStarted, error: error)
                    if let error = error {
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
                        complete(nil, false)
                        return
                    }
                    let reloadStarted = ProcessInfo.processInfo.systemUptime
                    Logger.network.noticeAndFile("[operation:\(operation)] Reloading VPN configuration")
                    manager.loadFromPreferences { error in
                        self.logStage("VPN configuration reload completed", operation: operation, since: reloadStarted, error: error)
                        if error != nil {
                            // The saved on-demand profile still needs cleanup.
                            complete(manager, false)
                            return
                        }
                        complete(manager, true)
                    }
                }
            }
        }
    }
}

extension VpnManager {

    func connect() {
        if !Thread.isMainThread {
            DispatchQueue.main.async { self.connect() }
            return
        }
        guard vpnStatus == .disconnected || connectionLifecycle.isStopping else { return }
        guard !config.host.isEmpty, !config.password.isEmpty else {
            appData.showConfigureGuide = true
            return
        }
        if let error = SettingsValidation.configurationError(host: config.host, port: String(config.port),
            password: config.password, dns: config.dns, mtu: config.mtu, probeDomains: config.probeDomains) {
            appData.connectionError = error
            return
        }
        config.host = config.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let token = connectionLifecycle.beginConnect() else {
            Logger.network.noticeAndFile("Ignoring connect while a connection operation is still active")
            return
        }
        appData.connectionError = nil
        publishStatus(.connecting)
        connectionRequestedAt = ProcessInfo.processInfo.systemUptime
        tunnelStartIssuedAt = nil
        Logger.network.noticeAndFile("[operation:\(token)] Connection requested")
        #if os(macOS)
        let activationStarted = ProcessInfo.processInfo.systemUptime
        Logger.network.noticeAndFile("[operation:\(token)] Activating system extension")
        systemExtensionManager.ensureActivated { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                let activationError: Error?
                if case .failure(let error) = result { activationError = error } else { activationError = nil }
                self.logStage("System extension activation completed", operation: token,
                    since: activationStarted, error: activationError)
                guard self.connectionLifecycle.canStart(token) else {
                    self.connectionLifecycle.finishPreparation(token)
                    self.advanceConnection()
                    return
                }
                switch result {
                case .failure(let error):
                    Logger.network.errorAndFile("System extension activation failed: \(error.localizedDescription)")
                    self.failConnect(token)
                case .success:
                    self.prepareConnection(token)
                }
            }
        }
        #else
        prepareConnection(token)
        #endif
    }

    private func prepareConnection(_ token: UInt64) {
        loadAndCreateProviderManager { manager, loaded in
            DispatchQueue.main.async {
                let permitted = self.connectionLifecycle.canStart(token)
                self.connectionLifecycle.finishPreparation(token)
                guard permitted else {
                    if let manager { self.activeVPN = manager }
                    self.advanceConnection()
                    return
                }
                guard let manager else { self.failConnect(token); return }
                self.activeVPN = manager
                if !loaded {
                    self.connectionFailurePending = true
                    self.disconnect()
                    return
                }
                self.observeVPNStatus(for: manager)
                guard self.connectionLifecycle.markStarted(token) else { return }
                do {
                    // Saving an on-demand profile may already have started it.
                    if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                        let issued = ProcessInfo.processInfo.systemUptime
                        self.tunnelStartIssuedAt = issued
                        Logger.network.noticeAndFile("[operation:\(token)] Calling startVPNTunnel status=\(manager.connection.status.rawValue)")
                        try manager.connection.startVPNTunnel()
                        self.logStage("startVPNTunnel returned; waiting for system status", operation: token, since: issued)
                    } else {
                        Logger.network.noticeAndFile("[operation:\(token)] Adopting on-demand tunnel status=\(manager.connection.status.rawValue)")
                        self.updateVPNStatus(manager)
                    }
                } catch {
                    Logger.network.errorAndFile("startVPNTunnel failed: \(error.localizedDescription)")
                    self.connectionFailurePending = true
                    self.disconnect()
                }
            }
        }
    }

    func disconnect(completion: ((Bool) -> Void)? = nil) {
        if !Thread.isMainThread { DispatchQueue.main.async { self.disconnect(completion: completion) }; return }
        if let completion { stopCompletions.append(completion) }
        guard let token = connectionLifecycle.beginDisconnect() else { return }
        appData.connectionError = nil
        #if os(macOS)
        // Release only the activation waiter; a profile save must still finish.
        systemExtensionManager.cancelActivationWait()
        #endif
        publishStatus(.disconnecting)
        connectionRequestedAt = nil
        tunnelStartIssuedAt = nil
        Logger.network.noticeAndFile("[operation:\(token)] Disconnection requested")
        // A pending save may still create an enabled profile. Wait for its
        // callback before loading or disabling anything.
        advanceConnection()
    }

    private func failConnect(_ token: UInt64) {
        guard connectionLifecycle.failConnect(token) else { return }
        connectionRequestedAt = nil
        tunnelStartIssuedAt = nil
        publishIdle()
        appData.connectionError = "Unable to connect. Check your network and server configuration."
    }

    private func publishIdle() {
        publishStatus(.disconnected)
        appData.connectedSince = nil
        appData.stopStatsMonitoring()
        config.ip = ""
        activeVPN = nil
    }

    private func completeStopIfPossible() {
        guard connectionLifecycle.isStopping else { return }
        if let manager = activeVPN { updateVPNStatus(manager) }
        else if connectionLifecycle.completeStopIfReady(tunnelDown: true) {
            publishIdle()
            finishDisconnect(succeeded: !connectionLifecycle.stopFailed)
        }
    }

    private func finishDisconnect(succeeded: Bool) {
        tunnelStopTimeoutWorkItem?.cancel()
        tunnelStopTimeoutWorkItem = nil
        if connectionFailurePending {
            connectionFailurePending = false
            appData.connectionError = "Unable to connect. Check your network and server configuration."
        }
        if !succeeded {
            appData.connectionError = "Unable to disconnect. Please try again."
        }
        let completions = stopCompletions
        stopCompletions.removeAll()
        let reconnect = succeeded && connectionLifecycle.wantsConnection
        completions.forEach { $0(succeeded) }
        if reconnect {
            DispatchQueue.main.async {
                guard self.connectionLifecycle.wantsConnection else { return }
                self.advanceConnection()
            }
        }
    }

    /// The only handoff between preparation, teardown and a queued reconnect.
    private func advanceConnection() {
        guard !connectionLifecycle.isPreparing else { return }
        if connectionLifecycle.isStopping {
            performStop(connectionLifecycle.generation, manager: activeVPN)
        } else if connectionLifecycle.wantsConnection, vpnStatus == .disconnected {
            connect()
        }
    }

    private func performStop(_ token: UInt64, manager: NETunnelProviderManager?) {
        guard connectionLifecycle.beginTeardown(token) else { return }
        let stop: (NETunnelProviderManager?, Error?) -> Void = { manager, error in
            DispatchQueue.main.async {
                guard self.connectionLifecycle.acceptsStop(token) else { return }
                if let error {
                    Logger.network.errorAndFile("Failed to load VPN configuration for disconnect: \(error)")
                    self.connectionLifecycle.finishTeardown(token, succeeded: false)
                    self.completeStopIfPossible()
                    return
                }
                guard let manager else {
                    self.connectionLifecycle.finishTeardown(token)
                    self.completeStopIfPossible()
                    return
                }
                self.activeVPN = manager
                self.observeVPNStatus(for: manager)
                let finish: () -> Void = {
                    DispatchQueue.main.async {
                        #if os(macOS)
                        let deadline = ProcessInfo.processInfo.systemUptime + self.providerStartupTimeout
                        #else
                        let deadline = ProcessInfo.processInfo.systemUptime
                        #endif
                        self.stopTunnelWhenReady(token, manager: manager, deadline: deadline)
                    }
                }
                if manager.isOnDemandEnabled {
                    manager.isOnDemandEnabled = false
                    let disableStarted = ProcessInfo.processInfo.systemUptime
                    Logger.network.noticeAndFile("[operation:\(token)] Disabling on-demand VPN configuration")
                    manager.saveToPreferences { error in
                        self.logStage("On-demand disable completed", operation: token, since: disableStarted, error: error)
                        if let error {
                            DispatchQueue.main.async {
                                guard self.connectionLifecycle.acceptsStop(token) else { return }
                                // Restore the in-memory flag too, so Retry persists it again.
                                manager.isOnDemandEnabled = true
                                Logger.network.errorAndFile("Failed to disable on-demand: \(error)")
                                self.connectionLifecycle.finishTeardown(token, succeeded: false)
                                self.completeStopIfPossible()
                            }
                            return
                        }
                        finish()
                    }
                } else { finish() }
            }
        }
        if let manager { stop(manager, nil) }
        else { loadProviderManager(stop) }
    }

    /// A connecting session can still be allocating its utun inside nehelper.
    /// Stopping before the provider enters startTunnel leaves that allocation orphaned.
    private func stopTunnelWhenReady(_ token: UInt64, manager: NETunnelProviderManager, deadline: TimeInterval) {
        guard connectionLifecycle.acceptsStop(token) else { return }
        #if os(macOS)
        if manager.connection.status == .connecting {
            queryProviderStarted { started in
                DispatchQueue.main.async {
                    guard self.connectionLifecycle.acceptsStop(token) else { return }
                    if started || manager.connection.status != .connecting {
                        self.finishTunnelStop(token, manager: manager)
                    } else if ProcessInfo.processInfo.systemUptime >= deadline {
                        Logger.network.errorAndFile("Provider startup did not settle; disconnect can be retried")
                        self.connectionLifecycle.finishTeardown(token, succeeded: false)
                        self.completeStopIfPossible()
                    } else {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                            self.stopTunnelWhenReady(token, manager: manager, deadline: deadline)
                        }
                    }
                }
            }
            return
        }
        #endif
        finishTunnelStop(token, manager: manager)
    }

    private func finishTunnelStop(_ token: UInt64, manager: NETunnelProviderManager) {
        guard connectionLifecycle.acceptsStop(token) else { return }
        if manager.connection.status != .disconnected && manager.connection.status != .invalid {
            Logger.network.noticeAndFile("[operation:\(token)] Calling stopVPNTunnel status=\(manager.connection.status.rawValue)")
            manager.connection.stopVPNTunnel()
        }
        connectionLifecycle.finishTeardown(token)
        completeStopIfPossible()
        guard connectionLifecycle.acceptsStop(token) else { return }
        let timeout = DispatchWorkItem { [weak self] in
            guard let self, self.connectionLifecycle.acceptsStop(token) else { return }
            // Only the system-state wait is timed out. Never overlap a pending
            // preferences write with another operation.
            self.connectionLifecycle.failStop(token)
            self.completeStopIfPossible()
        }
        tunnelStopTimeoutWorkItem = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + tunnelStopTimeout, execute: timeout)
    }


}
