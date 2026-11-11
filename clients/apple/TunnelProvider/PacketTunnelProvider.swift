//
//  PacketTunnelProvider.swift
//  VaultNetworkExtension
//
//
import Network
import NetworkExtension
import os.log
import SystemConfiguration
import VaultCore
#if os(iOS)
import Darwin
import UIKit
#endif

enum ConfigurationError: Error {
    case missingConfiguration
    case invalidConfiguration(String)
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var launchConfiguration: TunnelLaunchConfiguration?
    /// Domains the on-demand diagnostics suite probes; overridable from the
    /// app's configure page via the "probeDomains" provider configuration.
    private var probeDomains: [String] = []
    /// Cancels the Rust transport executing the current provider-side probe.
    let diagnostics = ProviderDiagnostics()
    private var edge: Edge!
    private var pendingStart: PendingStart?
    private var startTimeoutWorkItem: DispatchWorkItem?
    private var settingsTimeoutWorkItem: DispatchWorkItem?
    /// Polls Rust counters and publishes an in-memory status snapshot over IPC.
    private var statsTimer: DispatchSourceTimer?
    private var statsSession = PacketStats.Session()
    /// Replaced for each start; callbacks retain their own session's object.
    private var tunWriteMetrics = TunnelWriteMetrics()
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
        FileLogger.shared.logSync(
            "[session:\(sessionID)] Provider instance initialized pid=\(ProcessInfo.processInfo.processIdentifier)",
            level: "NOTICE"
        )
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
            do {
                try clearLogsIfNeeded(proto.providerConfiguration?["clearLogsToken"] as? String)
            } catch {
                FileLogger.shared.logSync("Deferred log clear failed: \(error)", level: "ERROR")
            }
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
            "[session:\(sessionID)] startTunnel #\(PacketTunnelProvider.startTunnelCallCount) "
                + "pid \(ProcessInfo.processInfo.processIdentifier) provider \(ObjectIdentifier(self).hashValue)"
        )
        startAliveMarker()
        stopRequested = false
        // Each provider session owns fresh counters; the app carries forward
        // the last observed totals when an on-demand restart replaces it.
        statsSession.begin()
        tunWriteMetrics = TunnelWriteMetrics()
        guard let launch = readLaunchConfiguration() else { return }
        launchConfiguration = launch
        probeDomains = launch.probeDomains
        mtuCap = launch.mtuCap

        // The system sometimes spawns a second provider instance for the
        // same tunnel while a previous one still holds a live session. Both
        // sessions share one peer id, so the supernode evicts the older one
        // and they would reject/reconnect each other forever — shut the old
        // session down before starting ours.
        if let previous = Self.activeProvider, previous !== self {
            Logger.network.noticeAndFile(
                "[session:\(sessionID)] Taking over tunnel from previous provider instance "
                    + "(session:\(previous.sessionID))"
            )
            previous.cleanupSession()
        }
        // Bound DNS resolution, handshake and settings application together.
        startTimeoutWorkItem?.cancel()
        let timeoutWorkItem = DispatchWorkItem { [weak self] in
            guard let self, !self.stopRequested, self.pendingStart === pending else { return }
            Logger.network.errorAndFile("[session:\(self.sessionID)] Tunnel start timed out")
            self.startFailed(reason: "start timed out")
        }
        startTimeoutWorkItem = timeoutWorkItem
        DispatchQueue.main.asyncAfter(
            deadline: .now() + TunnelConstants.startTimeout,
            execute: timeoutWorkItem
        )
        resolveAndStartEdge(launch, pending: pending)
    }

    private func readLaunchConfiguration() -> TunnelLaunchConfiguration? {
        guard let protoConfig = protocolConfiguration as? NETunnelProviderProtocol else {
            Logger.network.error("Invalid protocol configuration type")
            finishStart(with: ConfigurationError.invalidConfiguration("protocol type"))
            return nil
        }
        guard let configuration = protoConfig.providerConfiguration else {
            Logger.network.error("No provider configuration found")
            finishStart(with: ConfigurationError.missingConfiguration)
            return nil
        }
        do {
            return try TunnelLaunchConfiguration(providerConfiguration: configuration)
        } catch {
            Logger.network.errorAndFile("Invalid tunnel launch configuration: \(error)")
            finishStart(with: error)
            return nil
        }
    }

    private func resolveAndStartEdge(_ launch: TunnelLaunchConfiguration, pending: PendingStart) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else {
                DispatchQueue.main.async {
                    if let completion = pending.takeCompletion() {
                        completion(EdgeError.connectionFailed)
                    }
                }
                return
            }
            let resolveStarted = ProcessInfo.processInfo.systemUptime
            Logger.network.noticeAndFile("[session:\(self.sessionID)] Resolving supernode hostname")
            let candidates = self.resolveAllAddresses(launch.host)
            let resolveMs = Int(((ProcessInfo.processInfo.systemUptime - resolveStarted) * 1000).rounded())
            Logger.network.noticeAndFile(
                "[session:\(self.sessionID)] Hostname resolution completed "
                    + "durationMs=\(resolveMs) candidates=\(candidates.count)"
            )
            DispatchQueue.main.async {
                guard !self.stopRequested, self.pendingStart === pending, pending.isPending else { return }
                guard !candidates.isEmpty else {
                    Logger.network.error("Failed to resolve hostname: \(launch.host)")
                    self.startFailed(reason: "hostname resolution failed")
                    return
                }
                self.serverCandidates = candidates
                self.superNodeIp = candidates.first ?? launch.host
                self.startEdge(
                    candidates: candidates,
                    host: launch.host,
                    port: launch.port,
                    password: launch.password,
                    id: launch.peerID
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
            FileLogger.shared.logSync(
                "[session:\(sessionID)] Skipping process exit "
                    + "activeProvider=\(Self.activeProvider?.sessionID ?? "none") "
                    + "startOwner=\(Self.startOwner?.sessionID ?? "none")",
                level: "NOTICE"
            )
            return
        }
        FileLogger.shared.logSync(
            "[session:\(sessionID)] Exiting extension process "
                + "pid=\(ProcessInfo.processInfo.processIdentifier); "
                + "interfaces=\(FileLogger.tunnelInterfaceSummary()); "
                + "rapid restart may be throttled by launchd",
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
        let writeMetrics = tunWriteMetrics
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
                onPackets: { [weak self] packets in
                    self?.writePacketsToTunnel(packets, metrics: writeMetrics)
                },
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
            "[session:\(self.sessionID)] stopTunnel called, "
                + "reason: \(Self.describeStopReason(reason))(\(reason.rawValue)) "
                + "startFinished=\(startFinished) startPending=\(pendingStart != nil) "
                + "edgePresent=\(edge != nil) interfaces=\(FileLogger.tunnelInterfaceSummary())",
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
        statsSession.end()
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
        launchConfiguration = nil
        let completion = pendingStart?.takeCompletion()
        pendingStart = nil
        releaseStart()
        if Self.activeProvider === self { Self.activeProvider = nil }
        let closing = edge
        edge = nil
        do { try closing?.close() } catch { Logger.network.errorAndFile("Failed to close Edge: \(error)") }
        reportTunWriteMetrics(force: true)
        completion?(NEVPNError(.connectionFailed))
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
            if let path = self.pathMonitor?.currentPath { self.refreshMTU(path) }
            self.notifyNetworkChanged(reason: "wake")
        }
    }

    deinit {
        pathMonitor?.cancel()
        Logger.network.noticeAndFile("[session:\(sessionID)] Provider deinit interfaces=\(FileLogger.tunnelInterfaceSummary())")
    }
}

extension PacketTunnelProvider {
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
            self.refreshMTU(path)
            // The first callback establishes the baseline; it is not a switch.
            if previous != nil && previous != signature {
                self.notifyNetworkChanged(reason: "network path changed")
            }
        }
        pathMonitor = monitor
        monitor.start(queue: .main)
    }

    private func refreshMTU(_ path: Network.NWPath) {
        guard !stopRequested, startFinished, path.status == .satisfied,
              let mtu = TunnelNetworkSettings.mtu(cap: mtuCap, sessionID: sessionID, path: path),
              let update = tunnelSettings.updateMTU(mtu) else { return }
        diagnostics.cancel()
        applySettings(update)
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

    private func applyAssignedIp(ipv4: String, ipv4Mask: String, ipv6: String, ipv6PrefixLen: Int32) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !stopRequested else { return }
        diagnostics.cancel()
        let configuration = TunnelConfiguration(
            ipv4: ipv4,
            mask: ipv4Mask,
            ipv6: ipv6,
            prefix: ipv6PrefixLen,
            mtu: TunnelNetworkSettings.mtu(
                cap: mtuCap,
                sessionID: sessionID,
                path: pathMonitor?.currentPath
            ) ?? tunnelSettings.latestMTU ?? mtuCap,
            dns: launchConfiguration?.effectiveDNS(ipv4: !ipv4.isEmpty, ipv6: !ipv6.isEmpty) ?? []
        )
        if let update = tunnelSettings.enqueue(configuration) { applySettings(update) }
    }

    private func applySettings(_ update: TunnelSettingsState.Update) {
        let configuration = update.configuration
        let settings = TunnelNetworkSettings.make(
            configuration,
            remoteAddress: superNodeIp,
            candidates: serverCandidates,
            dns: configuration.dns
        )
        Logger.network.noticeAndFile("[session:\(sessionID)] Applying tunnel settings revision=\(update.revision)")
        let timeout = settingsTimeout(for: update, token: sessionToken)
        settingsTimeoutWorkItem = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + TunnelConstants.startTimeout, execute: timeout)
        setTunnelNetworkSettings(settings) { [weak self] error in
            DispatchQueue.main.async {
                self?.completeSettingsUpdate(update, error: error)
            }
        }
    }

    private func settingsTimeout(
        for update: TunnelSettingsState.Update, token: UUID
    ) -> DispatchWorkItem {
        DispatchWorkItem { [weak self] in
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
    }

    private func completeSettingsUpdate(_ update: TunnelSettingsState.Update, error: Error?) {
        // Even after cleanup, the old completion must release its OS
        // request slot. Its result/error never belongs to the new session.
        if tunnelSettings.outstanding == update {
            settingsTimeoutWorkItem?.cancel()
            settingsTimeoutWorkItem = nil
        }
        let current = tunnelSettings.complete(update, succeeded: error == nil)
        guard !stopRequested else { return }
        guard current else {
            if let next = tunnelSettings.next() { applySettings(next) }
            return
        }
        if let error {
            Logger.network.errorAndFile("Failed to set network settings: \(error)")
            if pendingStart?.isPending == true {
                finishStart(with: error)
            } else {
                cancelTunnelWithError(error)
            }
            return
        }
        Logger.network.noticeAndFile(
            "[session:\(sessionID)] Tunnel settings applied revision=\(update.revision) mtu=\(update.configuration.mtu)"
        )
        if let next = tunnelSettings.next() {
            applySettings(next)
        } else if pendingStart?.isPending == true {
            finishStart(with: nil)
            startStatsPolling()
            readPacketFromTunnel()
        }
    }

    func diagnosticContext() -> AppleDiagnosticContext? {
        guard startFinished, !stopRequested, !tunnelSettings.isApplying,
              let configuration = tunnelSettings.applied,
              let connection = edge?.connectionStatus, connection.connected else { return nil }
        return AppleDiagnosticContext(
            provider: sessionID,
            generation: tunnelSettings.generation,
            ipv4: configuration.ipv4,
            mask: configuration.mask,
            ipv6: configuration.ipv6.isEmpty ? nil : configuration.ipv6,
            mtu: configuration.mtu,
            dns: configuration.dns,
            domains: probeDomains,
            connectionGeneration: connection.generation
        )
    }

    var providerStatus: ProviderStatus? {
        guard startFinished, !stopRequested, Self.activeProvider === self else { return nil }
        return statsSession.status(ip: assignedIp, publicIp: edge?.connectionStatus.publicIp)
    }

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

    /// Poll the Rust core's traffic stats once per second and bridge them
    /// to the main app. TUN delivery measurements are separate from the
    /// Rust receive counters: healthy windows log every thirty seconds,
    /// while failed writes retain the five-second reporting cadence.
    private func startStatsPolling() {
        dispatchPrecondition(condition: .onQueue(.main))
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(1))
        timer.setEventHandler { [weak self] in
            guard let self = self, let edge = self.edge else { return }
            self.reasserting = self.tunnelSettings.isApplying || !edge.isConnected
            self.statsSession.update(PacketStats.Stats(edge.getTrafficStats()))
            self.reportTunWriteMetrics()
        }
        timer.resume()
        statsTimer = timer
    }

    private func reportTunWriteMetrics(force: Bool = false) {
        guard let report = tunWriteMetrics.takeReport(force: force) else { return }
        let elapsed = String(format: "%.3f", report.elapsedSeconds)
        let meanMs = String(format: "%.3f", report.meanDurationMilliseconds)
        let maxMs = String(format: "%.3f", report.maxDurationMilliseconds)
        let meanPackets = String(format: "%.2f", report.meanPacketsPerCall)
        let message = "[session:\(sessionID)] TUN write metrics elapsed_s=\(elapsed) "
            + "submitted_packets=\(report.submittedPackets) submitted_bytes=\(report.submittedBytes) "
            + "packets_per_call_avg=\(meanPackets) packets_per_call_max=\(report.maxPacketsPerCall) "
            + "write_mean_ms=\(meanMs) write_max_ms=\(maxMs)"
        if report.failedCalls > 0 {
            Logger.network.warningAndFile(
                message + " calls=\(report.calls) failed_calls=\(report.failedCalls) failed_packets=\(report.failedPackets)"
            )
        } else {
            Logger.network.noticeAndFile(message)
        }
    }

    private func writePacketsToTunnel(_ packets: [Data], metrics: TunnelWriteMetrics) {
        TunnelPacketWriter.write(packets, metrics: metrics) { packets, protocols in
            self.packetFlow.writePackets(packets, withProtocols: protocols)
        }
    }

    private func readPacketFromTunnel() {
        dispatchPrecondition(condition: .onQueue(.main))
        guard let edge = self.edge else {
            return
        }
        self.packetFlow.readPackets { (packets: [Data], _: [NSNumber]) in
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

}

extension PacketTunnelProvider {
    private static let stopReasonNames: [NEProviderStopReason: String] = [
        .none: "none",
        .userInitiated: "userInitiated",
        .providerFailed: "providerFailed",
        .noNetworkAvailable: "noNetworkAvailable",
        .unrecoverableNetworkChange: "unrecoverableNetworkChange",
        .providerDisabled: "providerDisabled",
        .authenticationCanceled: "authenticationCanceled",
        .configurationFailed: "configurationFailed",
        .idleTimeout: "idleTimeout",
        .configurationDisabled: "configurationDisabled",
        .configurationRemoved: "configurationRemoved",
        .superceded: "superceded",
        .appUpdate: "appUpdate",
        .userLogout: "userLogout",
        .userSwitch: "userSwitch",
        .connectionFailed: "connectionFailed",
        .sleep: "sleep",
        .internalError: "internalError"
    ]

    /// Human-readable stop reason; the raw value is always logged too, so
    /// reasons missing here (platform-specific or newly added by Apple) are
    /// still identifiable.
    static func describeStopReason(_ reason: NEProviderStopReason) -> String {
        stopReasonNames[reason] ?? "unknown"
    }
}

extension PacketTunnelProvider {
    /// Physical memory footprint of this process in MB (-1 if unavailable).
    static func physFootprintMB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kernelResult = withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }
        guard kernelResult == KERN_SUCCESS else { return -1 }
        return Double(info.phys_footprint) / 1_048_576
    }
}
