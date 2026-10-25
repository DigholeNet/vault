//
//  PacketTunnelProvider.swift
//  VaultNetworkExtension
//
//
import Network
import NetworkExtension
import SystemConfiguration
import VaultCore
import os.log
#if os(iOS)
import Darwin
import UIKit
#endif

enum ConfigurationError: Error {
    case missingConfiguration
    case invalidConfiguration(String)
}

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var dns: [String] = ["1.1.1.1", "8.8.8.8"]
    /// Domains the on-demand diagnostics suite probes; overridable from the
    /// app's configure page via the "probeDomains" provider configuration.
    private var probeDomains: [String] = []
    /// Cancels the Rust transport executing the current provider-side probe.
    let diagnostics = ProviderDiagnostics()
    private var edge: Edge!
    private var pendingStart: PendingStart?
    private var startTimeoutWorkItem: DispatchWorkItem?
    private var settingsTimeoutWorkItem: DispatchWorkItem?
    /// Polls Rust traffic counters once per second. iOS reads shared defaults;
    /// macOS reads the same snapshot through provider IPC.
    private var statsTimer: DispatchSourceTimer?
    /// Logs an "alive" marker with the memory footprint every 30s. When the
    /// markers stop without a stopTunnel/sleep line, the process was killed
    /// or suspended without warning.
    private var aliveTimer: DispatchSourceTimer?
    private let sessionStart = Date()
    private var stopRequested = false
    private var sessionToken = UUID()
    /// Whether platform tunnel startup completed.
    private var startFinished = false
    private var startupBeganAt: TimeInterval?
    /// Diagnostic: counts startTunnel invocations per extension process.
    private static var startTunnelCallCount = 0
    private var superNodeIp: String = ""
    /// Tunnel MTU ceiling from the "mtu" provider configuration
    /// (Configure page); default is the built-in upper bound.
    private var mtuCap: Int = TunnelConstants.mtuUpperBound
    private var serverCandidates: [String] = []
    private var tunnelSettings = TunnelSettingsState()
    private var assignedIp: String { tunnelSettings.applied?.addresses ?? "" }
    private var pathMonitor: NWPathMonitor?
    private var lastNetworkPath: String?
    /// A unique identifier for this provider instance so repeated Console.app
    /// lines can be matched to the same session.
    private let sessionID = String(UUID().uuidString.prefix(8))

    override init() {
        super.init()
        FileLogger.shared.logSync("[session:\(sessionID)] Provider instance initialized pid=\(ProcessInfo.processInfo.processIdentifier)", level: "NOTICE")
    }

    func clearLogsIfNeeded(_ token: String?) throws {
        guard let token, !token.isEmpty,
            UserDefaults.standard.string(forKey: "lastClearedLogToken") != token else { return }
        try FileLogger.shared.clearLogs()
        UserDefaults.standard.set(token, forKey: "lastClearedLogToken")
    }

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let received = ProcessInfo.processInfo.systemUptime
        if let proto = protocolConfiguration as? NETunnelProviderProtocol {
            do { try clearLogsIfNeeded(proto.providerConfiguration?["clearLogsToken"] as? String) }
            catch { FileLogger.shared.logSync("Deferred log clear failed: \(error)", level: "ERROR") }
        }
        FileLogger.shared.logSync(
            "[session:\(sessionID)] startTunnel callback received pid=\(ProcessInfo.processInfo.processIdentifier)",
            level: "NOTICE"
        )
        DispatchQueue.main.async {
            let delayMs = Int(((ProcessInfo.processInfo.systemUptime - received) * 1000).rounded())
            Logger.network.noticeAndFile("[session:\(self.sessionID)] startTunnel main queue entered callbackToMainMs=\(delayMs)")
            self.startTunnelOnMain(options: options, completionHandler: completionHandler)
        }
    }

    private func startTunnelOnMain(
        options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void
    ) {
        // Duplicate system callbacks must not reset or fail the in-flight session.
        if let pending = pendingStart, pending.appendCompletion(completionHandler) {
            Logger.network.noticeAndFile("[session:\(sessionID)] Coalescing duplicate startTunnel")
            return
        }
        if startFinished, !stopRequested {
            completionHandler(nil)
            return
        }
        guard !Self.settingsRestartRequired else {
            completionHandler(NEVPNError(.connectionFailed))
            exitIfUnowned()
            return
        }
        guard claimStart() else {
            completionHandler(ConfigurationError.invalidConfiguration("start in progress"))
            return
        }
        sessionToken = UUID()
        startupBeganAt = ProcessInfo.processInfo.systemUptime
        let pending = PendingStart(completion: completionHandler)
        pendingStart = pending
        FileLogger.shared.processTag = "ne"
        // Route Rust core/bridge logs into the same shared file. Must happen
        // before the first Edge (RustEdge) is created so the logger picks it up.
        if let path = FileLogger.shared.currentLogPath {
            setLogFilePath(path: path)
        }
        // Rotate (not delete) the previous session's log: when the extension
        // process died abnormally, the truncated tail of vault.prev.log is
        // the key evidence.
        FileLogger.shared.rotateForNewSession()

        PacketTunnelProvider.startTunnelCallCount += 1
        Logger.network.noticeAndFile(
            "[session:\(self.sessionID)] startTunnel #\(PacketTunnelProvider.startTunnelCallCount) pid \(ProcessInfo.processInfo.processIdentifier) provider \(ObjectIdentifier(self).hashValue)"
        )
        self.startAliveMarker()
        self.stopRequested = false
        // Statistics are per tunnel session: reset them so a new session
        // (including one started after an app/extension restart) begins at
        // zero instead of accumulating persisted values forever.
        PacketStats.shared.reset()
        guard
            let protoConfig = protocolConfiguration as? NETunnelProviderProtocol
        else {
            Logger.network.error("Invalid protocol configuration type")
            finishStart(with: ConfigurationError.invalidConfiguration("protocol type"))
            return
        }

        guard let conf = protoConfig.providerConfiguration else {
            Logger.network.error("No provider configuration found")
            finishStart(with: ConfigurationError.missingConfiguration)
            return
        }

        guard let rawHost = conf["host"] as? String, !rawHost.isEmpty else {
            Logger.network.error("Missing or empty host")
            finishStart(with: ConfigurationError.invalidConfiguration("host"))
            return
        }
        // Accept "[::1]" style input by stripping URL-style brackets.
        let host =
            (rawHost.hasPrefix("[") && rawHost.hasSuffix("]"))
            ? String(rawHost.dropFirst().dropLast()) : rawHost

        guard let port = conf["port"] as? UInt16 else {
            Logger.network.error("Missing or invalid port")
            finishStart(with: ConfigurationError.invalidConfiguration("port"))
            return
        }

        // The password is persisted in the OS VPN providerConfiguration: on macOS the
        // provider is a system extension running outside the user's session,
        // so App Group UserDefaults are not shared with it.
        guard let password = conf["password"] as? String, !password.isEmpty else {
            Logger.network.error("Missing password")
            finishStart(with: ConfigurationError.invalidConfiguration("password"))
            return
        }

        guard let id = conf["id"] as? Data else {
            Logger.network.error("Missing id")
            finishStart(with: ConfigurationError.invalidConfiguration("id"))
            return
        }

        // DNS is optional, use default values
        if let dnsServers = conf["dns"] as? String, !dnsServers.isEmpty {
            self.dns = dnsServers.components(separatedBy: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        }

        // Probe domains for on-demand diagnostics are optional too.
        if let domains = conf["probeDomains"] as? String, !domains.isEmpty {
            let parsed = domains.components(separatedBy: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            if !parsed.isEmpty {
                self.probeDomains = parsed
            }
        }

        // Optional tunnel MTU cap (Configure page; empty = built-in bound).
        // clamp to [mtuLowerBound, mtuUpperBound] regardless of input.
        if let rawMtu = conf["mtu"] as? String, !rawMtu.isEmpty,
            let parsed = Int(rawMtu.trimmingCharacters(in: .whitespaces))
        {
            self.mtuCap = min(
                max(parsed, TunnelConstants.mtuLowerBound), TunnelConstants.mtuUpperBound
            )
        }

        // The system sometimes spawns a second provider instance for the
        // same tunnel while a previous one still holds a live session. Both
        // sessions share one peer id, so the supernode evicts the older one
        // and they would reject/reconnect each other forever — shut the old
        // session down before starting ours.
        if let previous = Self.activeProvider, previous !== self {
            Logger.network.noticeAndFile(
                "[session:\(self.sessionID)] Taking over tunnel from previous provider instance (session:\(previous.sessionID))"
            )
            previous.cleanupSession()
        }
        // Bound DNS resolution, handshake and settings application together.
        self.startTimeoutWorkItem?.cancel()
        let timeoutWorkItem = DispatchWorkItem { [weak self] in
            guard let self = self, !self.stopRequested,
                self.pendingStart === pending else { return }
            Logger.network.errorAndFile("[session:\(self.sessionID)] Tunnel start timed out")
            self.startFailed(reason: "start timed out")
        }
        self.startTimeoutWorkItem = timeoutWorkItem
        DispatchQueue.main.asyncAfter(
            deadline: .now() + TunnelConstants.startTimeout,
            execute: timeoutWorkItem
        )
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else {
                DispatchQueue.main.async {
                    if let completion = pending.takeCompletion() {
                        completion(EdgeError.connectionFailed)
                    }
                }
                return
            }
            let resolveStarted = ProcessInfo.processInfo.systemUptime
            Logger.network.noticeAndFile("[session:\(self.sessionID)] Resolving supernode hostname")
            let candidates = self.resolveAllAddresses(host)
            let resolveMs = Int(((ProcessInfo.processInfo.systemUptime - resolveStarted) * 1000).rounded())
            Logger.network.noticeAndFile("[session:\(self.sessionID)] Hostname resolution completed durationMs=\(resolveMs) candidates=\(candidates.count)")
            DispatchQueue.main.async {
                guard !self.stopRequested, self.pendingStart === pending,
                    pending.isPending else { return }
                guard !candidates.isEmpty else {
                    Logger.network.error("Failed to resolve hostname: \(host)")
                    self.startFailed(reason: "hostname resolution failed")
                    return
                }
                self.serverCandidates = candidates
                self.superNodeIp = candidates.first ?? host
                self.startEdge(
                    candidates: candidates,
                    host: host,
                    port: port,
                    password: password,
                    id: id
                )
            }
        }

    }

    /// Guards against overlapping startTunnel calls: each start owns
    /// exactly one Edge and a shared set of completion handlers. Process-wide so it
    /// also protects against the system creating multiple provider
    /// instances in the same extension process.
    private static weak var startOwner: PacketTunnelProvider?
    /// An unresponsive OS settings call can only be discarded with its process.
    /// Keep rejecting new starts if another live instance prevents safe exit.
    private static var settingsRestartRequired = false
    /// The provider instance owning the live tunnel session. The system may
    /// create a second provider instance in this process for the same
    /// tunnel; two live sessions share one peer id, so the supernode evicts
    /// the older one and the two would fight over the session forever.
    private static var activeProvider: PacketTunnelProvider?

    private func claimStart() -> Bool {
        dispatchPrecondition(condition: .onQueue(.main))
        guard Self.startOwner == nil else { return false }
        Self.startOwner = self
        return true
    }

    private func releaseStart() {
        dispatchPrecondition(condition: .onQueue(.main))
        if Self.startOwner === self { Self.startOwner = nil }
    }

    /// A superseded instance must never terminate its replacement's process.
    private func exitIfUnowned() {
        guard Self.activeProvider == nil, Self.startOwner == nil else {
            FileLogger.shared.logSync("[session:\(sessionID)] Skipping process exit activeProvider=\(Self.activeProvider?.sessionID ?? "none") startOwner=\(Self.startOwner?.sessionID ?? "none")", level: "NOTICE")
            return
        }
        FileLogger.shared.logSync(
            "[session:\(sessionID)] Exiting extension process pid=\(ProcessInfo.processInfo.processIdentifier); interfaces=\(FileLogger.tunnelInterfaceSummary()); rapid restart may be throttled by launchd",
            level: "NOTICE"
        )
        exit(0)
    }

    /// Start Edge with every resolved supernode address. The Rust core
    /// races the candidates Happy-Eyeballs style (300 ms stagger, first
    /// completed handshake wins) and retries failures within the platform
    /// startup deadline.
    private func startEdge(
        candidates: [String],
        host: String,
        port: UInt16,
        password: String,
        id: Data
    ) {
        diagnostics.cancel()
        Logger.network.noticeAndFile(
            "[session:\(self.sessionID)] Trying supernode addresses \(candidates)"
        )

        // Reported in the handshake so the supernode can log which
        // device and OS a peer is running.
        #if os(macOS)
        let platform = "macos"
        let reportedName = Host.current().localizedName ?? "Mac"
        #else
        let platform = "ios"
        let reportedName = deviceModelName(for: hardwareModelIdentifier())
        #endif
        let trimmedName = reportedName.trimmingCharacters(in: .whitespacesAndNewlines)
        let deviceName = trimmedName.isEmpty ? "unknown" : trimmedName

        let token = sessionToken
        do {
            let config = EdgeConfig(
                password: password,
                host: host,
                port: port
            )
            let edgeStarted = ProcessInfo.processInfo.systemUptime
            let edge = try Edge(
                config: config,
                id: id,
                hosts: candidates,
                deviceName: deviceName,
                platform: platform,
                onData: writePacketToTunnel,
                onIpAssigned: { [weak self] ipv4, mask, ipv6, prefix in
                    DispatchQueue.main.async {
                        guard let self, !self.stopRequested, self.sessionToken == token else { return }
                        self.applyAssignedIp(
                            ipv4: ipv4,
                            ipv4Mask: mask,
                            ipv6: ipv6,
                            ipv6PrefixLen: prefix
                        )
                    }
                }
            )
            self.edge = edge
            let edgeMs = Int(((ProcessInfo.processInfo.systemUptime - edgeStarted) * 1000).rounded())
            Logger.network.noticeAndFile("[session:\(self.sessionID)] Edge initialized durationMs=\(edgeMs); awaiting IP assignment")
        } catch {
            Logger.network.errorAndFile(
                "[session:\(self.sessionID)] Edge init failed: \(error.localizedDescription)"
            )
            self.startFailed(reason: "edge init failed")
            return
        }
    }

    /// Complete a failed platform startup. Rust owns transport retry policy.
    private func startFailed(reason: String) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !stopRequested, pendingStart?.isPending == true else { return }
        Logger.network.errorAndFile("[session:\(sessionID)] Start failed: \(reason)")
        finishStart(with: EdgeError.connectionFailed)
    }

    /// Invoke the pending startTunnel completion handler exactly once and
    /// cancel the handshake timeout.
    private func finishStart(with error: Error?) {
        guard let completion = self.pendingStart?.takeCompletion() else { return }
        self.pendingStart = nil
        let restart = error != nil && tunnelSettings.outstanding != nil
        if restart { Self.settingsRestartRequired = true }
        if let error {
            Logger.network.errorAndFile("[session:\(sessionID)] startTunnel failed: \(error.localizedDescription)")
            cleanupSession()
        } else {
            startTimeoutWorkItem?.cancel()
            startTimeoutWorkItem = nil
            releaseStart()
            startFinished = true
            Self.activeProvider = self
            startNetworkMonitoring()
            let now = ProcessInfo.processInfo.systemUptime
            let startupMs = Int(((now - (startupBeganAt ?? now)) * 1000).rounded())
            Logger.network.noticeAndFile("[session:\(sessionID)] startTunnel completed durationMs=\(startupMs)")
        }
        completion(error)
        if restart { exitIfUnowned() }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        DispatchQueue.main.async {
            self.stopTunnelOnMain(with: reason, completionHandler: completionHandler)
        }
    }

    private func stopTunnelOnMain(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Synchronous log: the process may be suspended or killed right
        // after the completion handler runs; an async write could lose the
        // line that explains why the tunnel went away.
        FileLogger.shared.logSync(
            "[session:\(self.sessionID)] stopTunnel called, reason: \(Self.describeStopReason(reason))(\(reason.rawValue)) startFinished=\(startFinished) startPending=\(pendingStart != nil) edgePresent=\(edge != nil) interfaces=\(FileLogger.tunnelInterfaceSummary())",
            level: "NOTICE"
        )
        cleanupSession()
        FileLogger.shared.logSync("[session:\(sessionID)] Tunnel stopped", level: "NOTICE")
        completionHandler()
        exitIfUnowned()
    }

    /// One cleanup path for startup failure, stop and provider replacement.
    private func cleanupSession() {
        stopRequested = true
        sessionToken = UUID()
        startFinished = false
        diagnostics.cancel()
        pathMonitor?.cancel()
        pathMonitor = nil
        lastNetworkPath = nil
        reasserting = false
        aliveTimer?.cancel()
        aliveTimer = nil
        statsTimer?.cancel()
        statsTimer = nil
        startTimeoutWorkItem?.cancel()
        startTimeoutWorkItem = nil
        settingsTimeoutWorkItem?.cancel()
        settingsTimeoutWorkItem = nil
        tunnelSettings.reset()
        let completion = pendingStart?.takeCompletion()
        pendingStart = nil
        releaseStart()
        if Self.activeProvider === self { Self.activeProvider = nil }
        let closing = edge
        edge = nil
        do { try closing?.close() }
        catch { Logger.network.errorAndFile("Failed to close Edge: \(error)") }
        completion?(NEVPNError(.connectionFailed))
    }

    /// Human-readable stop reason; the raw value is always logged too, so
    /// reasons missing here (platform-specific or newly added by Apple) are
    /// still identifiable.
    private static func describeStopReason(_ reason: NEProviderStopReason) -> String {
        switch reason {
        case .none: return "none"
        case .userInitiated: return "userInitiated"
        case .providerFailed: return "providerFailed"
        case .noNetworkAvailable: return "noNetworkAvailable"
        case .unrecoverableNetworkChange: return "unrecoverableNetworkChange"
        case .providerDisabled: return "providerDisabled"
        case .authenticationCanceled: return "authenticationCanceled"
        case .configurationFailed: return "configurationFailed"
        case .idleTimeout: return "idleTimeout"
        case .configurationDisabled: return "configurationDisabled"
        case .configurationRemoved: return "configurationRemoved"
        case .superceded: return "superceded"
        case .appUpdate: return "appUpdate"
        case .userLogout: return "userLogout"
        case .userSwitch: return "userSwitch"
        case .connectionFailed: return "connectionFailed"
        case .sleep: return "sleep"
        case .internalError: return "internalError"
        @unknown default: return "unknown"
        }
    }

    /// Logged so sleep/wake cycles (which suspend the process and make the
    /// heartbeat timers jump) are visible in the timeline. Synchronous
    /// writes: the process suspends as soon as sleep's handler returns.
    override func sleep(completionHandler: @escaping () -> Void) {
        FileLogger.shared.logSync(
            "[session:\(self.sessionID)] Provider going to sleep",
            level: "NOTICE"
        )
        completionHandler()
    }

    override func wake() {
        FileLogger.shared.logSync(
            "[session:\(self.sessionID)] Provider woke up",
            level: "NOTICE"
        )
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.edge != nil else { return }
            self.notifyNetworkChanged(reason: "wake")
        }
    }

    /// Keep path events on the main queue, alongside
    /// tunnel configuration completion. Ignore utun changes caused by us.
    private func startNetworkMonitoring() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self, !self.stopRequested else { return }
            let available = path.status == .satisfied
            let interfaces = path.availableInterfaces.filter {
                path.usesInterfaceType($0.type) && !$0.name.hasPrefix("utun")
            }.map { "\($0.name):\($0.index)" }.sorted().joined(separator: ",")
            let signature = "\(available)|\(interfaces)|v4=\(path.supportsIPv4)|v6=\(path.supportsIPv6)|\(path.gateways)"
            let previous = self.lastNetworkPath
            self.lastNetworkPath = signature
            guard available else {
                self.notifyNetworkChanged(reason: "network unavailable")
                return
            }
            // The first callback establishes the baseline; it is not a switch.
            if previous != nil && previous != signature {
                self.notifyNetworkChanged(reason: "network path changed")
            }
        }
        pathMonitor = monitor
        monitor.start(queue: .main)
    }

    /// Forward OS events; Rust debounces notifications and restarts transport.
    private func notifyNetworkChanged(reason: String) {
        guard !stopRequested, startFinished, let edge = edge else { return }
        diagnostics.cancel()
        do {
            Logger.network.noticeAndFile("[session:\(sessionID)] Network changed: \(reason)")
            try edge.reconnect()
        } catch {
            Logger.network.errorAndFile("Network change notification failed: \(error)")
        }
    }

    deinit {
        pathMonitor?.cancel()
        Logger.network.noticeAndFile("[session:\(sessionID)] Provider deinit interfaces=\(FileLogger.tunnelInterfaceSummary())")
    }

    private func applyAssignedIp(ipv4: String, ipv4Mask: String, ipv6: String, ipv6PrefixLen: Int32) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !stopRequested else { return }
        diagnostics.cancel()
        let configuration = TunnelConfiguration(ipv4: ipv4, mask: ipv4Mask,
            ipv6: ipv6, prefix: ipv6PrefixLen, mtu: TunnelNetworkSettings.mtu(cap: mtuCap, sessionID: sessionID))
        if let update = tunnelSettings.enqueue(configuration) { applySettings(update) }
    }

    private func applySettings(_ update: TunnelSettingsState.Update) {
        let configuration = update.configuration
        let settings = TunnelNetworkSettings.make(configuration, remoteAddress: superNodeIp,
            candidates: serverCandidates, dns: dns)
        Logger.network.noticeAndFile("[session:\(sessionID)] Applying tunnel settings revision=\(update.revision)")
        let token = sessionToken
        let timeout = DispatchWorkItem { [weak self] in
            guard let self, !self.stopRequested, self.sessionToken == token,
                self.tunnelSettings.outstanding == update else { return }
            Logger.network.errorAndFile("[session:\(self.sessionID)] OS settings request timed out; recycling provider process")
            Self.settingsRestartRequired = true
            let error = NEVPNError(.connectionFailed)
            if self.pendingStart?.isPending == true {
                self.finishStart(with: error)
            } else {
                self.cancelTunnelWithError(error)
                self.cleanupSession()
                self.exitIfUnowned()
            }
        }
        settingsTimeoutWorkItem = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + TunnelConstants.startTimeout, execute: timeout)
        setTunnelNetworkSettings(settings) { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                // Even after cleanup, the old completion must release its OS
                // request slot. Its result/error never belongs to the new session.
                if self.tunnelSettings.outstanding == update {
                    self.settingsTimeoutWorkItem?.cancel()
                    self.settingsTimeoutWorkItem = nil
                }
                let current = self.tunnelSettings.complete(update, succeeded: error == nil)
                guard !self.stopRequested else { return }
                guard current else {
                    if let next = self.tunnelSettings.next() { self.applySettings(next) }
                    return
                }
                if let error {
                    Logger.network.errorAndFile("Failed to set network settings: \(error)")
                    if self.pendingStart?.isPending == true { self.finishStart(with: error) }
                    else { self.cancelTunnelWithError(error) }
                    return
                }
                // Publish only the addresses that the OS successfully installed.
                UserDefaults(suiteName: kAppGroupIdentifier)?.set(configuration.addresses, forKey: "ip")
                if let next = self.tunnelSettings.next() {
                    self.applySettings(next)
                } else if self.pendingStart?.isPending == true {
                    self.finishStart(with: nil)
                    self.startStatsPolling()
                    self.readPacketFromTunnel()
                }
            }
        }
    }

    func diagnosticContext() -> AppleDiagnosticContext? {
        guard startFinished, !stopRequested, !tunnelSettings.isApplying,
            let configuration = tunnelSettings.applied,
            let connection = edge?.connectionStatus, connection.connected else { return nil }
        return AppleDiagnosticContext(provider: sessionID, generation: tunnelSettings.generation,
            ipv4: configuration.ipv4, mask: configuration.mask,
            ipv6: configuration.ipv6.isEmpty ? nil : configuration.ipv6, mtu: configuration.mtu,
            dns: dns, domains: probeDomains, connectionGeneration: connection.generation)
    }

    var providerStatus: ProviderStatus { ProviderStatus(ip: assignedIp, stats: PacketStats.shared.currentStats) }
    var providerStarted: Bool { !stopRequested && (pendingStart != nil || startFinished) }
    var messageState: String {
        "startFinished=\(startFinished) startPending=\(pendingStart != nil) stopRequested=\(stopRequested) "
          + "edgePresent=\(edge != nil) reasserting=\(reasserting) interfaces=\(FileLogger.tunnelInterfaceSummary())"
    }

    override func handleAppMessage(_ data: Data, completionHandler: ((Data?) -> Void)? = nil) {
        let message = ProviderMessage(data: data, session: sessionID, completion: completionHandler)
        DispatchQueue.main.async {
            message.trace(self.messageState, force: !self.startFinished || self.stopRequested)
            self.handleMessage(message)
        }
    }

    /// Log an "alive" marker (with the memory footprint) every 30s so the
    /// log can distinguish a live session, a suspension (markers pause,
    /// resume later) and a silent kill (markers stop, never resume). The
    /// timer ticks every 30s.
    private func startAliveMarker() {
        self.aliveTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + .seconds(30), repeating: .seconds(30))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            let age = Int(Date().timeIntervalSince(self.sessionStart))
            FileLogger.shared.log(
                "[session:\(self.sessionID)] alive: uptime \(age)s, memory \(String(format: "%.1f", Self.physFootprintMB())) MB",
                level: "DEBUG"
            )
        }
        timer.resume()
        self.aliveTimer = timer
    }

    /// Physical memory footprint of this process in MB (-1 if unavailable).
    private static func physFootprintMB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return -1 }
        return Double(info.phys_footprint) / 1_048_576
    }

    /// Poll the Rust core's traffic stats once per second and bridge them
    /// to the main app. vault-core owns the counters; per-packet counting
    /// on the Swift side would be redundant.
    private func startStatsPolling() {
        dispatchPrecondition(condition: .onQueue(.main))
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self = self, let edge = self.edge else { return }
            self.reasserting = self.tunnelSettings.isApplying || !edge.isConnected
            PacketStats.shared.update(from: edge.getTrafficStats())
        }
        timer.resume()
        statsTimer = timer
    }

    func writePacketToTunnel(packet: Data) {
        // Detect packet version from first byte (high 4 bits)
        let isIPv6 = !packet.isEmpty && ((packet[0] >> 4) == 6)
        let protocolFamily: Int32 = isIPv6 ? AF_INET6 : AF_INET
        self.packetFlow.writePackets(
            [packet],
            withProtocols: [NSNumber(value: protocolFamily)]
        )
    }

    private func readPacketFromTunnel() {
        dispatchPrecondition(condition: .onQueue(.main))
        guard let edge = self.edge else {
            return
        }
        self.packetFlow.readPackets {
            (packets: [Data], _: [NSNumber]) in
            for packet in packets {
                self.handlePacket(packet, edge)
            }
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.stopRequested, self.edge === edge else { return }
                self.readPacketFromTunnel()
            }
        }
    }

    private func handlePacket(_ packet: Data, _ edge: Edge) {
        do {
            try edge.writeData(data: packet)
        } catch {
            Logger.network.error("Write data to remote server error. \(error)")
        }
    }

    /// Resolve all addresses for platform route exclusions. Returns an
    /// empty array on failure. The caller installs exclusions on main.
    private func resolveAllAddresses(_ hostname: String) -> [String] {
        var hints = addrinfo(
            ai_flags: AI_ALL,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_DGRAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )

        var res: UnsafeMutablePointer<addrinfo>?
        let result = getaddrinfo(hostname, nil, &hints, &res)

        guard result == 0, let addresses = res else {
            Logger.network.error("Unable to resolve \(hostname): \(String(cString: gai_strerror(result)))")
            return []
        }
        defer { freeaddrinfo(res) }

        var ipv4Addresses: [String] = []
        var ipv6Addresses: [String] = []

        for addr in sequence(first: addresses, next: { $0.pointee.ai_next }) {
            guard let sa = addr.pointee.ai_addr else { continue }

            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                let ip = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    String(cString: inet_ntoa($0.pointee.sin_addr))
                }
                ipv4Addresses.append(ip)

            case AF_INET6:
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                _ = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { addr in
                    inet_ntop(AF_INET6, &addr.pointee.sin6_addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
                }
                let ip = String(cString: buffer)
                ipv6Addresses.append(ip)

            default:
                break
            }
        }

        // Hand every address to Rust; family preference and racing live there.
        // Deduplicate because getaddrinfo may return an address multiple times.
        var seen = Set<String>()
        return (ipv4Addresses + ipv6Addresses).filter {
            seen.insert($0).inserted
        }
    }
}
