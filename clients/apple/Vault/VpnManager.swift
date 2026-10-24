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
    private var connectInFlight: Bool { connectionLifecycle.isPreparing }

    private var diagnosticsSessionGeneration: UInt64 = 0
    private var appDiagnosticsCancellation: DiagnosticsCancellation?
    private var diagnosticsCancelledByUser = false
    private(set) var vpnStatus: VpnStatus {
        get { appData.vpnStatus }
        set {
            if newValue != appData.vpnStatus {
                diagnosticsSessionGeneration &+= 1
                appDiagnosticsCancellation?.cancel()
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
                vpnStatus = .disconnecting
                #if os(macOS)
                appData.connectionError = nil
                appData.isRecovering = false
                #endif
                return
            }
            stopResult = !connectionLifecycle.stopFailed
        }
        let oldStatus = self.vpnStatus

        switch manager.connection.status {
        case .disconnected:
            self.vpnStatus = .disconnected
        case .connecting:
            self.vpnStatus = .connecting
        case .connected:
            self.vpnStatus = .connected
        case .disconnecting:
            self.vpnStatus = .disconnecting
        case .invalid:
            // Configuration was removed or became unusable (e.g. the user
            // deleted the VPN in system settings) — reflect it as off.
            self.vpnStatus = .disconnected
        case .reasserting:
            // Network is re-asserting (e.g. Wi-Fi <-> cellular switch);
            // treat it as connecting so the UI doesn't show a fake "on".
            self.vpnStatus = .connecting
        @unknown default:
            break
        }

        updateSessionDetails(manager, previousStatus: oldStatus)

        if stopResult == nil, self.vpnStatus == .connected { connectionLifecycle.observedConnected() }
        let unexpectedDisconnect = stopResult == nil && self.vpnStatus == .disconnected && connectionLifecycle.observedDisconnected()
        #if os(macOS)
        self.appData.isRecovering = manager.connection.status == .reasserting
        #endif
        if self.vpnStatus == .connected {
            self.appData.connectionError = nil
        } else if self.vpnStatus == .disconnected {
            if unexpectedDisconnect {
                self.appData.connectionError = "Connection ended unexpectedly. Check your network and server configuration."
            }
        }
        if let stopResult { finishDisconnect(succeeded: stopResult) }
    }

    private func updateSessionDetails(_ manager: NEVPNManager, previousStatus oldStatus: VpnStatus) {
        if oldStatus != self.vpnStatus {
            // App-side record of tunnel state transitions; a connected ->
            // off transition the user did not initiate means the extension
            // died or the system stopped the tunnel.
            Logger.network.noticeAndFile(
                "VPN status: \(oldStatus) -> \(self.vpnStatus) (NEVPNStatus rawValue \(manager.connection.status.rawValue))"
            )
            if self.vpnStatus == .connected {
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
        let generation = diagnosticsSessionGeneration
        sendProviderCommand("status", timeout: 3, payload: Data()) { data in
            DispatchQueue.main.async {
                guard self.diagnosticsSessionGeneration == generation,
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

        NETunnelProviderManager.loadAllFromPreferences {
            [self] (managers, error) in
            DispatchQueue.main.async {
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

                self.observeVPNStatus(for: manager)

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

                manager.saveToPreferences { error in
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
                    manager.loadFromPreferences {
                        if $0 != nil {
                            Logger.network.error(
                                "loadFromPreferences \($0.debugDescription)"
                            )
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
        guard let token = connectionLifecycle.beginConnect() else {
            Logger.network.noticeAndFile("Ignoring connect while a connection operation is still active")
            return
        }
        appData.connectionError = nil
        #if os(macOS)
        appData.isRecovering = false
        #endif
        vpnStatus = .connecting
        Logger.network.noticeAndFile("connect() operation \(token)")
        #if os(macOS)
        systemExtensionManager.ensureActivated { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
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
                self.removeVpnStatusObservers()
                self.observeVPNStatus(for: manager)
                guard self.connectionLifecycle.markStarted(token) else { return }
                do {
                    // Saving an on-demand profile may already have started it.
                    if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                        try manager.connection.startVPNTunnel()
                    } else { self.updateVPNStatus(manager) }
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
        appData.isRecovering = false
        // Release only the activation waiter; a profile save must still finish.
        systemExtensionManager.cancelActivationWait()
        #endif
        vpnStatus = .disconnecting
        Logger.network.noticeAndFile("disconnect() operation \(token)")
        // A pending save may still create an enabled profile. Wait for its
        // callback before loading or disabling anything.
        advanceConnection()
    }

    private func failConnect(_ token: UInt64) {
        guard connectionLifecycle.failConnect(token) else { return }
        publishIdle()
        appData.connectionError = "Unable to connect. Check your network and server configuration."
    }

    private func publishIdle() {
        vpnStatus = .disconnected
        #if os(macOS)
        appData.isRecovering = false
        #endif
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
                self.removeVpnStatusObservers()
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
                    manager.saveToPreferences { error in
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

    /// Send a provider-message command and return the raw reply. The reply
    /// arrives on an unspecified queue; nil means the message channel itself
    /// failed (no manager, not a provider session, no response).
    private func sendProviderCommand(_ command: String, timeout: TimeInterval = 8, payload: Data? = nil, completion: @escaping (Data?) -> Void) {
        if !Thread.isMainThread {
            DispatchQueue.main.async { self.sendProviderCommand(command, timeout: timeout, payload: payload, completion: completion) }
            return
        }
        let replyLock = NSLock()
        var replied = false
        func reply(_ data: Data?) {
            replyLock.lock()
            let first = !replied
            replied = true
            replyLock.unlock()
            if first { completion(data) }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { reply(nil) }
        struct Command: Codable { var command: String }
        let send: (NETunnelProviderManager) -> Void = { manager in
            guard let session = manager.connection as? NETunnelProviderSession else {
                Logger.network.errorAndFile("Provider command '\(command)' failed: connection is not NETunnelProviderSession")
                reply(nil)
                return
            }
            guard let message = payload ?? (try? JSONEncoder().encode(Command(command: command))) else {
                reply(nil)
                return
            }
            do {
                try session.sendProviderMessage(message) { data in
                    reply(data)
                }
            } catch {
                Logger.network.errorAndFile("Provider command '\(command)' failed: \(error.localizedDescription)")
                reply(nil)
            }
        }
        if let manager = self.activeVPN {
            send(manager)
        } else {
            loadProviderManager { manager, _ in
                guard let manager = manager else {
                    Logger.network.errorAndFile("Provider command '\(command)' failed: no VPN manager")
                    reply(nil)
                    return
                }
                send(manager)
            }
        }
    }

    /// Ask the running provider to execute the connectivity probe suite.
    /// Provider checks (60s) then app checks (20s), with a 95s reply backstop.
    /// nil means the message channel itself failed.
    func requestDiagnostics(onProgress: ((DiagnosticsResult) -> Void)? = nil, completion: @escaping (DiagnosticsResult?) -> Void) {
        // The extension's own sockets bypass the tunnel, so only the app can
        // observe where the default route really sends user traffic. A
        // "Connected" tunnel whose routes never materialized is invisible to
        // every bound probe — check it here.
        guard appDiagnosticsCancellation == nil else {
            completion(DiagnosticsResult(summary: "INCOMPLETE - diagnostics already running", lines: []))
            return
        }
        diagnosticsCancelledByUser = false
        let diagnosticsStarted = ProcessInfo.processInfo.systemUptime
        let cancellation = DiagnosticsCancellation()
        appDiagnosticsCancellation = cancellation
        var progressTimer: DispatchSourceTimer?
        var pollingProvider = true
        let lock = NSLock()
        var finished = false
        func finish(_ reply: DiagnosticsResult?) {
            var result = reply
            result?.durationMs = max(0, Int(((ProcessInfo.processInfo.systemUptime - diagnosticsStarted) * 1000).rounded()))
            lock.lock()
            let first = !finished
            finished = true
            lock.unlock()
            if first {
                cancellation.cancel()
                DispatchQueue.main.async {
                    pollingProvider = false
                    progressTimer?.cancel()
                    progressTimer = nil
                    self.appDiagnosticsCancellation = nil
                    if self.diagnosticsCancelledByUser { result?.summary = "INCOMPLETE - diagnostics cancelled" }
                    if let result {
                        Logger.network.noticeAndFile("[probe] final summary: \(result.summary) duration=\(result.durationMs ?? 0)ms")
                        for line in result.lines where line.hasPrefix("[probe] route:") {
                            Logger.network.noticeAndFile(line)
                        }
                    } else {
                        Logger.network.errorAndFile("[probe] final summary: INCOMPLETE - provider returned no usable response")
                    }
                    completion(result)
                }
            }
        }
        let initialGeneration = diagnosticsSessionGeneration
        let initialConnection = activeVPN?.connection
        let initialConnectedDate = initialConnection?.connectedDate
        DispatchQueue.global().asyncAfter(deadline: .now() + 95) {
            finish(DiagnosticsResult(summary: "INCOMPLETE - diagnostics request timed out", lines: []))
        }
        queryProviderStatus { initialStatus in
            DispatchQueue.main.async {
                guard !cancellation.isCancelled, self.diagnosticsSessionGeneration == initialGeneration,
                    self.vpnStatus == .connected else {
                    finish(DiagnosticsResult(summary: "INCOMPLETE - tunnel session changed", lines: []))
                    return
                }
                let initialIP = initialStatus?.ip.isEmpty == false ? initialStatus?.ip : nil
                if let initialIP { self.config.ip = initialIP }
                let initialRouteAssessment = self.checkDefaultRoutes(assignedIP: initialIP)
                if let onProgress {
                    let timer = DispatchSource.makeTimerSource(queue: .main)
                    var inFlight = false
                    timer.schedule(deadline: .now() + 0.5, repeating: 0.75)
                    timer.setEventHandler {
                        guard !inFlight, !cancellation.isCancelled else { return }
                        inFlight = true
                        self.sendProviderCommand("diagnosticsProgress", timeout: 3) { data in
                            DispatchQueue.main.async {
                                inFlight = false
                                guard pollingProvider, !cancellation.isCancelled, let data,
                                    let progress = try? JSONDecoder().decode(DiagnosticsResult.self, from: data),
                                    progress.summary == "RUNNING" else { return }
                                onProgress(progress)
                            }
                        }
                    }
                    progressTimer = timer
                    timer.resume()
                }
                self.sendProviderCommand("diagnose", timeout: 70) { data in
                    guard let data, var result = try? JSONDecoder().decode(DiagnosticsResult.self, from: data) else {
                        finish(nil)
                        return
                    }
                    // Copy the provider snapshot before the app worker mutates the
                    // aggregate, and reject any late provider polling replies.
                    let providerProgress = DiagnosticsResult(summary: "RUNNING", lines: result.lines,
                        domains: result.domains, checks: result.checks, durationMs: result.durationMs,
                        activeCheck: "application", probes: result.probes)
                    DispatchQueue.main.async {
                        pollingProvider = false
                        progressTimer?.cancel()
                        progressTimer = nil
                        if !cancellation.isCancelled, providerProgress.checks != nil {
                            onProgress?(providerProgress)
                        }
                    }
                    DispatchQueue.global(qos: .utility).async {
                        if cancellation.isCancelled {
                            finish(DiagnosticsResult(summary: "INCOMPLETE - tunnel session changed", lines: []))
                            return
                        }
                        if let domains = result.domains, !result.summary.hasPrefix("INCOMPLETE - tunnel session changed") {
                            result.appendApplicationResult(TunnelDiagnostics.runApplicationChecks(domains: domains, cancellation: cancellation))
                        }
                        DispatchQueue.main.async {
                            self.queryProviderStatus { finalStatus in
                                let finalIP = finalStatus?.ip.isEmpty == false ? finalStatus?.ip : nil
                                let addressesChanged = initialIP != nil && finalIP != nil && initialIP != finalIP
                                if self.diagnosticsSessionGeneration != initialGeneration || self.vpnStatus != .connected || addressesChanged
                                    || (initialConnection != nil && self.activeVPN?.connection.connectedDate != initialConnectedDate) {
                                    result.summary = "INCOMPLETE - tunnel session changed; run diagnostics again"
                                } else {
                                    if let finalIP { self.config.ip = finalIP }
                                    var assessment = initialIP == nil
                                        ? self.checkDefaultRoutes(assignedIP: finalIP) : initialRouteAssessment
                                    if initialIP != nil && finalIP == nil {
                                        assessment.unavailable.append("Current tunnel addresses could not be confirmed after diagnostics")
                                    }
                                    result.appendRouteAssessment(assessment)
                                }
                                finish(result)
                            }
                        }
                    }
                }
            }
        }
    }

    func cancelDiagnostics() {
        guard appDiagnosticsCancellation != nil else { return }
        diagnosticsCancelledByUser = true
        appDiagnosticsCancellation?.cancel()
        sendProviderCommand("cancelDiagnostics", timeout: 3) { _ in }
    }

    /// Samples routes to public IPv4/IPv6 targets in the app process.
    /// Missing routes and address mismatches are reported separately.
    private func checkDefaultRoutes(assignedIP: String?) -> RouteCheck.Assessment {
        let routes = RouteCheck.defaultRouteLocalAddresses()
        Logger.network.noticeAndFile(
            "[probe] route check: default-route local addresses ipv4=\(routes.ipv4 ?? "none") ipv6=\(routes.ipv6 ?? "none"), current provider assigned=\(assignedIP ?? "unavailable")"
        )
        return RouteCheck.assess(routes: routes, assignedIP: assignedIP)
    }

    #if os(macOS)
    /// The extension's log is trapped inside a sandboxed root daemon's
    /// container; the app can only obtain it over the provider-message
    /// channel while the tunnel is up. Every successful fetch is cached next
    /// to the app's own log so Runtime Logs can still show the most recent
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
    #else
    /// iOS app and extension already share the same log file.
    func collectLogs() async -> String {
        await FileLogger.shared.readLogAsync() ?? ""
    }
    #endif

}
