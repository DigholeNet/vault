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

enum TunnelConstants {
    /// Bytes of tunnel overhead added to every inner packet:
    /// 40 outer IPv6 header (worst case, even for IPv4 peers)
    /// + 8 outer UDP header
    /// + 8 packet counter (EXTRA_LEN in core/src/lib.rs)
    /// + 16 AEAD tag (TAG_LEN in core/src/lib.rs)
    /// + 1 message type header.
    /// Keep in sync with get_overhead() in core/src/device.rs.
    static let tunnelOverhead: Int = 73
    /// Upper bound for the tunnel MTU: 1500 (typical Ethernet link MTU)
    /// minus tunnelOverhead. Jumbo-frame links do not inflate the tunnel
    /// MTU beyond this. Also the fallback when the underlying link MTU
    /// cannot be probed.
    static let mtuUpperBound: Int = 1427
    /// Lower bound for the tunnel MTU: the IPv6 minimum link MTU. Below
    /// this the system cannot route IPv6 through the tunnel at all.
    static let mtuLowerBound: Int = 1280
    /// Overall backstop for a start sequence so the system VPN state
    /// cannot get stuck in .connecting. Slightly above the Rust handshake
    /// timeout (5s); with the typical two candidates (v6+v4) the core's
    /// race reports all-failed at 300ms stagger + 5s, just under this.
    static let startTimeout: TimeInterval = 6
    /// Match the core heartbeat timeout before publishing a recovery state.
    static let serverUnreachableTimeout: TimeInterval = 30
}

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var dns: [String] = ["1.1.1.1", "8.8.8.8"]
    /// Domains the on-demand diagnostics suite probes; overridable from the
    /// app's configure page via the "probeDomains" provider configuration.
    private var probeDomains: [String] = []
    /// Cancels the Rust transport executing the current provider-side probe.
    private var diagnosticsCancellation: DiagnosticsCancellation?
    private var diagnosticsRunID: String?
    private var edge: Edge!
    private var pendingStart: PendingStart?
    private var startTimeoutWorkItem: DispatchWorkItem?
    /// Polls Rust traffic counters once per second. iOS reads shared defaults;
    /// macOS reads the same snapshot through provider IPC.
    private var statsTimer: DispatchSourceTimer?
    /// Logs an "alive" marker with the memory footprint every 30s. When the
    /// markers stop without a stopTunnel/sleep line, the process was killed
    /// or suspended without warning.
    private var aliveTimer: DispatchSourceTimer?
    private let sessionStart = Date()
    private var stopRequested = false
    /// The server watchdog only applies once startTunnel succeeded.
    private var startFinished = false
    private var startupBeganAt: TimeInterval?
    /// Diagnostic: counts startTunnel invocations per extension process.
    private static var startTunnelCallCount = 0
    private var superNodeIp: String = ""
    /// Tunnel MTU ceiling from the "mtu" provider configuration
    /// (Configure page); default is the built-in upper bound.
    private var mtuCap: Int = TunnelConstants.mtuUpperBound
    private var excludedV4Addresses: [String] = []
    private var excludedV6Addresses: [String] = []
    /// Addresses assigned by the supernode ("ipv4" or "ipv4/ipv6"), served
    /// to the app via handleAppMessage.
    private var assignedIp: String = ""
    /// Netmask of the assigned IPv4; diagnostics derives the tunnel gateway
    /// address from it.
    private var assignedIPv4Mask: String?
    /// The tunnel MTU currently applied to the interface; diagnostics sweeps
    /// packet sizes up to it.
    private var appliedMtu: Int?
    private var pathMonitor: NWPathMonitor?
    private var lastNetworkPath: String?
    private var networkAvailable = true
    private var networkRecoveryWorkItem: DispatchWorkItem?
    private var networkConfigurationSequence: UInt64 = 0
    /// A unique identifier for this provider instance so repeated Console.app
    /// lines can be matched to the same session.
    private let sessionID = String(UUID().uuidString.prefix(8))

    override init() {
        super.init()
        FileLogger.shared.logSync("[session:\(sessionID)] Provider instance initialized pid=\(ProcessInfo.processInfo.processIdentifier)", level: "NOTICE")
    }

    private func clearLogsIfNeeded(_ token: String?) throws {
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
        guard claimStart() else {
            completionHandler(ConfigurationError.invalidConfiguration("start in progress"))
            return
        }
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
            previous.abandonSession()
        }
        // Bound DNS resolution, handshake and settings application together.
        self.startTimeoutWorkItem?.cancel()
        let timeoutWorkItem = DispatchWorkItem { [weak self] in
            guard let self = self, !self.stopRequested,
                self.pendingStart?.isPending == true else { return }
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
                self.excludedV4Addresses = candidates.filter { !$0.contains(":") }
                self.excludedV6Addresses = candidates.filter { $0.contains(":") }
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

    /// Delays the failure of startTunnel after repeated unsuccessful
    /// starts, throttling the On-Demand restart loop for a dead server.
    private var startBackoffWorkItem: DispatchWorkItem?
    /// Persisted so the backoff survives the process restart that follows
    /// every failed start cycle.
    private static let startFailCountKey = "consecutiveStartFailures"
    /// Guards against overlapping startTunnel calls: each start owns
    /// exactly one Edge and a shared set of completion handlers. Process-wide so it
    /// also protects against the system creating multiple provider
    /// instances in the same extension process.
    private static weak var startOwner: PacketTunnelProvider?
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
    /// completed handshake wins); the losers are aborted mid-handshake, so
    /// the supernode only ever sees the winning session. A fast failure
    /// from the core (all candidates failed, or network unreachable) fails
    /// the start after a throttling backoff instead of waiting for the
    /// backstop timeout.
    private func startEdge(
        candidates: [String],
        host: String,
        port: UInt16,
        password: String,
        id: Data
    ) {
        diagnosticsCancellation?.cancel()
        networkConfigurationSequence &+= 1
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
                        guard let self = self, !self.stopRequested else { return }
                        self.applyAssignedIp(
                            ipv4: ipv4,
                            ipv4Mask: mask,
                            ipv6: ipv6,
                            ipv6PrefixLen: prefix
                        )
                    }
                },
                onNetworkUnreachable: { [weak self] in
                    DispatchQueue.main.async {
                        self?.startFailed(reason: "network unreachable")
                    }
                },
                onHandshakeFailed: { [weak self] in
                    DispatchQueue.main.async {
                        self?.startFailed(reason: "handshake failed")
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

    /// The start failed (all candidates lost the race, network
    /// unreachable, backstop timeout). The system re-runs startTunnel
    /// immediately after a failure (On-Demand); back off so a dead server
    /// does not produce a tight reconnect loop. First failure stays fast.
    private func startFailed(reason: String) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !self.stopRequested, let pending = self.pendingStart,
            pending.scheduleFailure() else { return }
        let failures =
            UserDefaults.standard.integer(forKey: Self.startFailCountKey) + 1
        UserDefaults.standard.set(failures, forKey: Self.startFailCountKey)
        let backoff = min(Double(failures - 1) * 30, 120)
        Logger.network.errorAndFile(
            "[session:\(self.sessionID)] Start failed (\(reason), failure #\(failures)), failing start in \(Int(backoff))s"
        )
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, !self.stopRequested,
                self.pendingStart === pending else { return }
            self.finishStart(with: EdgeError.connectionFailed)
        }
        self.startBackoffWorkItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + backoff, execute: item)
    }

    /// Invoke the pending startTunnel completion handler exactly once and
    /// cancel the handshake timeout.
    private func finishStart(with error: Error?) {
        guard let completion = self.pendingStart?.takeCompletion() else { return }
        self.pendingStart = nil
        self.startTimeoutWorkItem?.cancel()
        self.startTimeoutWorkItem = nil
        self.startBackoffWorkItem?.cancel()
        self.startBackoffWorkItem = nil
        self.releaseStart()
        if let error = error {
            self.stopRequested = true
            self.networkConfigurationSequence &+= 1
            self.aliveTimer?.cancel()
            self.aliveTimer = nil
            Logger.network.errorAndFile(
                "[session:\(self.sessionID)] startTunnel failed: \(error.localizedDescription)"
            )
        } else {
            self.startFinished = true
            Self.activeProvider = self
            self.startNetworkMonitoring()
            UserDefaults.standard.set(0, forKey: Self.startFailCountKey)
            let now = ProcessInfo.processInfo.systemUptime
            let startupMs = Int(((now - (startupBeganAt ?? now)) * 1000).rounded())
            Logger.network.noticeAndFile("[session:\(self.sessionID)] startTunnel completed durationMs=\(startupMs)")
        }
        // On failure, tear down the Edge immediately instead of leaving the
        // core reconnecting with exponential backoff (1s up to 60s) until
        // the system calls stopTunnel.
        if error != nil, let edge = self.edge {
            try? edge.close()
            self.edge = nil
        }
        completion(error)
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
        self.diagnosticsCancellation?.cancel()
        self.stopRequested = true
        self.stopNetworkMonitoring()
        self.aliveTimer?.cancel()
        self.aliveTimer = nil
        self.statsTimer?.cancel()
        self.statsTimer = nil
        self.startTimeoutWorkItem?.cancel()
        self.startTimeoutWorkItem = nil
        self.startBackoffWorkItem?.cancel()
        self.startBackoffWorkItem = nil
        // Complete a pending startTunnel so the system does not treat the
        // extension as hung.
        if let completion = self.pendingStart?.takeCompletion() {
            self.pendingStart = nil
            completion(NEVPNError(.connectionFailed))
        }
        self.releaseStart()
        if Self.activeProvider === self {
            Self.activeProvider = nil
        }
        guard let edge = self.edge else {
            // Synchronous: exit(0) below does not give async file writes a
            // chance to flush.
            FileLogger.shared.logSync(
                "[session:\(self.sessionID)] Stop Tunnel successfully (no active session).",
                level: "NOTICE"
            )
            completionHandler()
            // The extension process otherwise lingers with stale
            // process-wide state (claimed starts, timers, statics). The
            // system relaunches it on the next startTunnel.
            exitIfUnowned()
            return
        }
        do {
            try edge.close()
        } catch {
            Logger.network.error("[Error] Stop edge error: \(error)")
        }
        // Always clear the reference even if close() throws, otherwise the
        // next startTunnel would fail forever with "Tunnel already started".
        self.edge = nil
        // Synchronous: exit(0) below does not give async file writes a
        // chance to flush.
        FileLogger.shared.logSync(
            "[session:\(self.sessionID)] Stop Tunnel successfully.",
            level: "NOTICE"
        )
        completionHandler()
        // Terminate the extension process so the next startTunnel gets a
        // clean process; the system relaunches it on demand.
        exitIfUnowned()

    }

    /// Shut down this instance's session without touching system tunnel
    /// state: when the system spawns a second provider for the same tunnel,
    /// the packet flow moves to the new instance ("IPC detached") and this
    /// one only owns a zombie Rust session whose heartbeats would otherwise
    /// keep fighting the new session at the server.
    private func abandonSession() {
        self.diagnosticsCancellation?.cancel()
        self.stopRequested = true
        self.stopNetworkMonitoring()
        self.aliveTimer?.cancel()
        self.aliveTimer = nil
        self.statsTimer?.cancel()
        self.statsTimer = nil
        self.startTimeoutWorkItem?.cancel()
        self.startTimeoutWorkItem = nil
        self.startBackoffWorkItem?.cancel()
        self.startBackoffWorkItem = nil
        if let edge = self.edge {
            try? edge.close()
            self.edge = nil
        }
        if Self.activeProvider === self {
            Self.activeProvider = nil
        }
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
            guard let self = self, let edge = self.edge,
                edge.getLastActivityAgeSecs() >= 10 else { return }
            self.scheduleNetworkRecovery(reason: "wake")
        }
    }

    /// Keep all path events and debounce work on the main queue, alongside
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
            self.networkAvailable = available
            guard available else {
                self.networkRecoveryWorkItem?.cancel()
                self.networkRecoveryWorkItem = nil
                self.reasserting = true
                return
            }
            // The first callback establishes the baseline; it is not a switch.
            if previous != nil && previous != signature {
                self.scheduleNetworkRecovery(reason: "network path changed")
            }
        }
        pathMonitor = monitor
        monitor.start(queue: .main)
    }

    private func scheduleNetworkRecovery(reason: String) {
        networkRecoveryWorkItem?.cancel()
        guard !stopRequested, startFinished, networkAvailable else { return }
        let item = DispatchWorkItem { [weak self] in
            guard let self = self, !self.stopRequested, self.networkAvailable,
                let edge = self.edge else { return }
            self.networkRecoveryWorkItem = nil
            self.diagnosticsCancellation?.cancel()
            self.networkConfigurationSequence &+= 1
            self.reasserting = true
            do {
                Logger.network.noticeAndFile("[session:\(self.sessionID)] Reconnecting: \(reason)")
                try edge.reconnect()
            } catch {
                Logger.network.errorAndFile("Network recovery request failed: \(error)")
            }
        }
        networkRecoveryWorkItem = item
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(750), execute: item)
    }

    private func stopNetworkMonitoring() {
        networkRecoveryWorkItem?.cancel()
        networkRecoveryWorkItem = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        lastNetworkPath = nil
        diagnosticsCancellation?.cancel()
        networkConfigurationSequence &+= 1
        reasserting = false
    }

    deinit {
        pathMonitor?.cancel()
        networkRecoveryWorkItem?.cancel()
        Logger.network.noticeAndFile("[session:\(sessionID)] Provider deinit interfaces=\(FileLogger.tunnelInterfaceSummary())")
    }

    /// MTU of the physical interface carrying the default route, or nil
    /// when it cannot be determined (no route, no matching interface, or
    /// ioctl failure). A UDP connect() transmits nothing; it only makes
    /// the kernel pick the egress interface and source address for the
    /// destination, which exposes the default route's interface.
    private func probeUnderlyingLinkMtu() -> Int? {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        // RFC 5737 TEST-NET-3, guaranteed unroutable: only the route
        // lookup matters, and it must not depend on a real host.
        var destination = sockaddr_in()
        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = in_port_t(80).bigEndian
        destination.sin_addr = in_addr(s_addr: inet_addr("203.0.113.1"))
        let connected = withUnsafePointer(to: &destination) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { return nil }

        var localAddress = sockaddr_storage()
        var localLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let gotName = withUnsafeMutablePointer(to: &localAddress) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &localLength)
            }
        }
        guard gotName == 0, Int32(localAddress.ss_family) == AF_INET else { return nil }
        let sourceAddress = withUnsafePointer(to: &localAddress) { ptr in
            ptr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                $0.pointee.sin_addr
            }
        }

        guard let interfaceName = Self.interfaceName(forAddress: sourceAddress)
        else { return nil }
        return Self.interfaceMtu(name: interfaceName, socket: fd)
    }

    /// Name of the interface owning the given local IPv4 address.
    private static func interfaceName(forAddress address: in_addr) -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }

        for interface in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard let ifaAddress = interface.pointee.ifa_addr,
                Int32(ifaAddress.pointee.sa_family) == AF_INET
            else { continue }
            let matches = ifaAddress.withMemoryRebound(
                to: sockaddr_in.self,
                capacity: 1
            ) {
                $0.pointee.sin_addr.s_addr == address.s_addr
            }
            if matches {
                return String(cString: interface.pointee.ifa_name)
            }
        }
        return nil
    }

    /// MTU of the named interface via SIOCGIFMTU. ifr_name is a fixed
    /// 16-byte char array (IFNAMSIZ) copied byte by byte because Swift
    /// imports it as a tuple.
    private static func interfaceMtu(name: String, socket fd: Int32) -> Int? {
        let nameBytes = Array(name.utf8CString)
        guard nameBytes.count <= Int(IFNAMSIZ) else { return nil }

        var request = ifreq()
        withUnsafeMutablePointer(to: &request.ifr_name) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(IFNAMSIZ)) { buffer in
                for index in 0..<nameBytes.count {
                    buffer[index] = nameBytes[index]
                }
            }
        }
        guard ioctl(fd, Self.siocGifMtu, &request) == 0 else { return nil }
        return Int(request.ifr_ifru.ifru_mtu)
    }

    /// sys/sockio.h defines SIOCGIFMTU via the _IOWR macro, which the
    /// Swift importer cannot expand ("structure not supported"), so the
    /// request value is computed from the same formula:
    /// IOC_INOUT | (sizeof(struct ifreq) & IOCPARM_MASK) << 16 | 'i' << 8 | 51.
    private static let siocGifMtu: UInt =
        0xC000_0000 /* IOC_INOUT = IOC_IN | IOC_OUT */
        | UInt(MemoryLayout<ifreq>.size & 0x1FFF) << 16
        | 0x69 << 8 /* 'i' */
        | 51

    /// Tunnel MTU: the underlying link MTU minus the tunnel overhead,
    /// clamped to [mtuLowerBound, mtuUpperBound] so PPPoE-class links
    /// shrink the tunnel while jumbo frames never inflate it. Falls back
    /// to the upper bound when the link MTU cannot be probed.
    /// mtuCap (Configure page, empty = mtuUpperBound) lowers the ceiling:
    /// on links that drop large outer packets, a smaller tunnel MTU keeps
    /// the UDP datagrams under the loss threshold.
    private func tunnelMtu() -> Int {
        guard let linkMtu = probeUnderlyingLinkMtu() else {
            Logger.network.warningAndFile(
                "[session:\(self.sessionID)] Underlying link MTU probe failed; using fallback \(self.mtuCap)"
            )
            return self.mtuCap
        }
        let mtu = min(
            max(linkMtu - TunnelConstants.tunnelOverhead, TunnelConstants.mtuLowerBound),
            self.mtuCap
        )
        Logger.network.noticeAndFile(
            "[session:\(self.sessionID)] Link MTU \(linkMtu) → tunnel MTU \(mtu) (cap \(self.mtuCap))"
        )
        return mtu
    }

    private func createNetworkSettings(
        superNodeIp: String,
        ipv4: String,
        ipv4Mask: String,
        ipv6: String,
        ipv6Prefixlen: Int32,
        dns: [String],
        _ excludesIpV4: [String]?,
        _ excludesIpV6: [String]?
    ) -> NEPacketTunnelNetworkSettings {

        let networkSettings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: superNodeIp
        )

        if !ipv4.isEmpty && !ipv4Mask.isEmpty {
            let ipv4Settings = NEIPv4Settings(
                addresses: [ipv4],
                subnetMasks: [ipv4Mask]
            )
            ipv4Settings.includedRoutes = [NEIPv4Route.default()]

            var excludedRoutes: [NEIPv4Route] = []
            if superNodeIp.contains(".") {
                excludedRoutes.append(
                    NEIPv4Route(
                        destinationAddress: superNodeIp,
                        subnetMask: "255.255.255.255"
                    )
                )

            }

            if let excludesIpV4 = excludesIpV4 {
                for ip in excludesIpV4 {
                    excludedRoutes.append(
                        NEIPv4Route(
                            destinationAddress: ip,
                            subnetMask: "255.255.255.255"
                        )
                    )
                }
            }

            ipv4Settings.excludedRoutes = excludedRoutes

            networkSettings.ipv4Settings = ipv4Settings
        }

        if !ipv6.isEmpty {
            // A /128 left public IPv6 unreachable on the tested macOS path.
            // Keep the /120 compatibility prefix; server allocation and the
            // explicit pool/default routes remain unchanged.
            let ipv6Settings = NEIPv6Settings(
                addresses: [ipv6], networkPrefixLengths: [NSNumber(value: 120)]
            )

            let ipv6Network = extractIpv6Network(ipv6, prefixLen: ipv6Prefixlen)
            Logger.network.notice("IPv6 network: \(ipv6Network, privacy: .public)/\(ipv6Prefixlen)  :  \(ipv6, privacy: .public)")

            // Keep the entire server pool reachable as well as public IPv6.
            ipv6Settings.includedRoutes = [
                NEIPv6Route(
                    destinationAddress: ipv6Network,
                    networkPrefixLength: NSNumber(value: ipv6Prefixlen)
                ),
                NEIPv6Route.default(),
            ]

            var excludedRoutesV6: [NEIPv6Route] = []

            if superNodeIp.contains(":") && superNodeIp != ipv6 {
                excludedRoutesV6.append(NEIPv6Route(
                    destinationAddress: superNodeIp,
                    networkPrefixLength: 128
                ))
            }

            if let excludesIpV6 = excludesIpV6 {
                for ip in excludesIpV6 {
                    excludedRoutesV6.append(
                        NEIPv6Route(
                            destinationAddress: ip,
                            networkPrefixLength: 128
                        )
                    )
                }
            }

            ipv6Settings.excludedRoutes = excludedRoutesV6
            networkSettings.ipv6Settings = ipv6Settings
            Logger.network.noticeAndFile(
                "IPv6 settings: interface=\(ipv6)/120 pool=\(ipv6Network)/\(ipv6Prefixlen) included=pool,::/0 excluded=\(excludedRoutesV6.map(\.destinationAddress).joined(separator: ","))"
            )

        }

        let dnsSettings = NEDNSSettings(servers: dns)

        networkSettings.dnsSettings = dnsSettings
        let mtu = tunnelMtu()
        networkSettings.mtu = NSNumber(value: mtu)
        self.appliedMtu = mtu

        return networkSettings
    }

    func extractIpv6Network(_ ipv6: String, prefixLen: Int32) -> String {
        guard let addr = IPv6Address(ipv6) else { return ipv6 }
        let raw = addr.rawValue  // 16 bytes

        let prefix = Int(prefixLen)
        guard prefix >= 0 && prefix <= 128 else { return ipv6 }

        var networkBytes = [UInt8](raw)
        let fullBytes = prefix / 8
        let remainingBits = prefix % 8

        // Zero out bits beyond the prefix length
        for byteIndex in fullBytes..<16 {
            if byteIndex == fullBytes && remainingBits > 0 {
                let mask = UInt8(0xFF) << (8 - remainingBits)
                networkBytes[byteIndex] &= mask
            } else {
                networkBytes[byteIndex] = 0
            }
        }

        guard let networkAddr = IPv6Address(Data(networkBytes)) else { return ipv6 }
        return networkAddr.debugDescription
    }

    private func applyAssignedIp(ipv4: String, ipv4Mask: String, ipv6: String, ipv6PrefixLen: Int32) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !stopRequested else { return }
        diagnosticsCancellation?.cancel()
        networkConfigurationSequence &+= 1
        let configurationSequence = networkConfigurationSequence

        var assigned = ipv4
        if !ipv6.isEmpty {
            assigned += "/" + ipv6
        }
        self.assignedIp = assigned
        self.assignedIPv4Mask = ipv4Mask.isEmpty ? nil : ipv4Mask
        Logger.network.noticeAndFile(
            "[session:\(self.sessionID)] onIpAssigned: \(assigned) mask \(ipv4Mask) v6prefix \(ipv6PrefixLen) startPending=\(self.pendingStart?.isPending == true)"
        )

        // Save assigned IP to shared UserDefaults so the main app can access
        // it. Only works on iOS, where the app extension shares the user's
        // App Group container; on macOS the system extension runs as root
        // and the app queries us via handleAppMessage instead.
        if let sharedDefaults = UserDefaults(suiteName: kAppGroupIdentifier) {
            sharedDefaults.set(assigned, forKey: "ip")
            Logger.network.notice("Saved assigned IP to shared UserDefaults: \(assigned, privacy: .public)")
        }

        let settings = createNetworkSettings(
            superNodeIp: superNodeIp,
            ipv4: ipv4,
            ipv4Mask: ipv4Mask,
            ipv6: ipv6,
            ipv6Prefixlen: ipv6PrefixLen,
            dns: dns,
            excludedV4Addresses.isEmpty ? nil : excludedV4Addresses,
            excludedV6Addresses.isEmpty ? nil : excludedV6Addresses
        )

        let settingsStarted = ProcessInfo.processInfo.systemUptime
        Logger.network.noticeAndFile("[session:\(self.sessionID)] Applying tunnel network settings sequence=\(configurationSequence)")
        setTunnelNetworkSettings(settings) { [weak self] error in
            // Serialize with the handshake-timeout work item on the main
            // queue so finishStart cannot race with it.
            DispatchQueue.main.async {
                guard let self = self, !self.stopRequested,
                    self.networkConfigurationSequence == configurationSequence else { return }

                let settingsMs = Int(((ProcessInfo.processInfo.systemUptime - settingsStarted) * 1000).rounded())
                Logger.network.noticeAndFile("[session:\(self.sessionID)] Network settings completed durationMs=\(settingsMs) sequence=\(configurationSequence) success=\(error == nil)")

                // Reconnect path: apply possibly-changed settings to the
                // live tunnel instead of leaving it routed at the old IP.
                guard self.pendingStart?.isPending == true else {
                    if let error = error {
                        Logger.network.errorAndFile(
                            "Failed to update network settings after reconnect: \(error)"
                        )
                        self.reasserting = true
                        self.cancelTunnelWithError(error)
                    } else {
                        self.reasserting = !self.networkAvailable
                        Logger.network.noticeAndFile(
                            "onIpAssigned (\(assigned)) after start; tunnel settings updated"
                        )
                    }
                    return
                }

                if let error = error {
                    Logger.network.errorAndFile("Failed to set network settings: \(error)")
                    self.finishStart(with: error)
                } else {
                    Logger.network.noticeAndFile("Tunnel configured successfully")
                    self.finishStart(with: nil)
                    self.startStatsPolling()
                    self.readPacketFromTunnel()
                }
            }
        }
    }

    /// Serves the app's status queries (assigned IP + traffic counters).
    /// Required on macOS where the system extension runs outside the user's
    /// session and App Group UserDefaults are not shared with the app.
    /// Diagnostic commands return live context or one Rust probe result;
    /// the app drives the shared engine and aggregates its typed snapshots.
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        let envelope = try? JSONDecoder().decode(ProviderCommandEnvelope.self, from: messageData)
        let commandName = envelope?.command ?? (messageData.isEmpty ? "status" : "legacy-status")
        let requestID = envelope?.requestID ?? "legacy"
        let received = ProcessInfo.processInfo.systemUptime
        let prefix = "[session:\(sessionID)] [request:\(requestID)] command=\(commandName) providerPID=\(ProcessInfo.processInfo.processIdentifier)"
        DispatchQueue.main.async {
            if envelope?.trace == true || !self.startFinished || self.stopRequested {
                Logger.network.noticeAndFile("\(prefix) received startFinished=\(self.startFinished) startPending=\(self.pendingStart != nil) stopRequested=\(self.stopRequested) edgePresent=\(self.edge != nil) reasserting=\(self.reasserting) interfaces=\(FileLogger.tunnelInterfaceSummary())")
            }
        }
        let tracedCompletion: ((Data?) -> Void)? = completionHandler.map { completion in
            { data in
                if envelope?.trace == true {
                    let elapsed = Int((ProcessInfo.processInfo.systemUptime - received) * 1000)
                    Logger.network.noticeAndFile("\(prefix) reply bytes=\(data?.count ?? 0) durationMs=\(elapsed)")
                }
                completion(data)
            }
        }
        if let command = envelope {
            switch command.command {
            case "clearLogs":
                DispatchQueue.main.async {
                    guard let token = command.token, !token.isEmpty else { tracedCompletion?(Data([0])); return }
                    do {
                        try self.clearLogsIfNeeded(token)
                        tracedCompletion?(Data([1]))
                    } catch { tracedCompletion?(Data([0])) }
                }
            case "startupStatus":
                DispatchQueue.main.async {
                    let started = !self.stopRequested && (self.pendingStart != nil || self.startFinished)
                    tracedCompletion?(Data([started ? 1 : 0]))
                }
            case "diagnosticContext":
                DispatchQueue.main.async {
                    guard self.startFinished, !self.stopRequested, !self.reasserting else { tracedCompletion?(nil); return }
                    let addresses = self.assignedIp.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
                    let context = AppleDiagnosticContext(provider: self.sessionID, generation: self.networkConfigurationSequence,
                        ipv4: addresses.first ?? "", mask: self.assignedIPv4Mask ?? "",
                        ipv6: addresses.count > 1 ? addresses[1] : nil, mtu: self.appliedMtu ?? 1427,
                        dns: self.dns, domains: self.probeDomains)
                    tracedCompletion?(try? JSONEncoder().encode(context))
                }
            case "diagnosticProbe":
                guard let payload = command.payload, let request = try? JSONDecoder().decode(AppleProbeRequest.self, from: payload)
                else { tracedCompletion?(nil); return }
                runDiagnosticProbe(request, completionHandler: tracedCompletion)
            case "cancelDiagnostics":
                DispatchQueue.main.async {
                    if command.token == self.diagnosticsRunID { self.diagnosticsCancellation?.cancel() }
                    tracedCompletion?(Data())
                }
            case "logs":
                // The macOS system extension is a sandboxed root daemon: its
                // container is unreadable to the app, and writing into the
                // app's container is sandbox-denied. Serving the log over
                // this channel is the only way Runtime Logs can show it. Keep
                // the reply bounded — the tail is what matters.
                let log = FileLogger.shared.readLog() ?? ""
                tracedCompletion?(String(log.suffix(512 * 1024)).data(using: .utf8))
            default:
                tracedCompletion?(nil)
            }
            return
        }
        DispatchQueue.main.async {
            let status = ProviderStatus(
                ip: self.assignedIp,
                stats: PacketStats.shared.currentStats
            )
            tracedCompletion?(try? JSONEncoder().encode(status))
        }
    }

    /// Executes one Rust-selected probe. The app owns the engine and performs
    /// application-route requests itself; the provider never owns a second plan.
    private func runDiagnosticProbe(_ request: AppleProbeRequest, completionHandler: ((Data?) -> Void)?) {
        DispatchQueue.main.async {
            guard self.startFinished, !self.stopRequested, !self.reasserting,
                request.provider == self.sessionID, request.generation == self.networkConfigurationSequence,
                request.timeout.isFinite, request.timeout > 0, request.timeout <= 6,
                self.diagnosticsCancellation == nil || self.diagnosticsCancellation?.isCancelled == true
                else { completionHandler?(nil); return }
            switch request.operation {
            case .route: completionHandler?(nil); return
            case .dns, .tcp, .https:
                guard request.tunnel else { completionHandler?(nil); return }
            case .ping:
                guard !request.tunnel else { completionHandler?(nil); return }
            }
            let cancellation = DiagnosticsCancellation()
            self.diagnosticsCancellation = cancellation
            self.diagnosticsRunID = request.run
            let ipv4 = self.assignedIp.split(separator: "/").first.map(String.init)
            DispatchQueue.global(qos: .utility).async {
                let response = RustDiagnostics.execute(request, tunnelIPv4: ipv4, cancellation: cancellation)
                DispatchQueue.main.async {
                    let current = self.diagnosticsCancellation === cancellation
                        && !cancellation.isCancelled && !self.stopRequested && !self.reasserting
                        && self.networkConfigurationSequence == request.generation
                    if self.diagnosticsCancellation === cancellation {
                        self.diagnosticsCancellation = nil
                        self.diagnosticsRunID = nil
                    }
                    completionHandler?(current ? try? JSONEncoder().encode(AppleProbeReply(request: request, response: response)) : nil)
                }
            }
        }
    }

    /// Log an "alive" marker (with the memory footprint) every 30s so the
    /// log can distinguish a live session, a suspension (markers pause,
    /// resume later) and a silent kill (markers stop, never resume). The
    /// timer ticks every 5s; the server watchdog runs on every tick.
    private func startAliveMarker() {
        self.aliveTimer?.cancel()
        var tick = 0
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + .seconds(5), repeating: .seconds(5))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            // Leave the tunnel alive while the core retries. Cancelling after
            // 15s used to preempt its 30s heartbeat timeout and break recovery.
            if !self.stopRequested, self.startFinished, !self.reasserting,
                let edge = self.edge,
                edge.getLastActivityAgeSecs() > UInt64(TunnelConstants.serverUnreachableTimeout)
            {
                self.reasserting = true
                Logger.network.warningAndFile(
                    "[session:\(self.sessionID)] Server unreachable; waiting for automatic recovery"
                )
            }
            tick += 1
            if tick % 6 == 0 {
                let age = Int(Date().timeIntervalSince(self.sessionStart))
                FileLogger.shared.log(
                    "[session:\(self.sessionID)] alive: uptime \(age)s, memory \(String(format: "%.1f", Self.physFootprintMB())) MB",
                    level: "DEBUG"
                )
            }
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
        // Filter out IPv6 multicast traffic (ff00::/8)
        if isIPv6MulticastPacket(packet) {
            return
        }

        do {
            try edge.writeData(data: packet)
        } catch {
            Logger.network.error("Write data to remote server error. \(error)")
        }
    }

    /// Check if packet is IPv6 multicast (destination starts with ff00::/8)
    private func isIPv6MulticastPacket(_ packet: Data) -> Bool {
        guard packet.count >= 40 else { return false }  // IPv6 header is 40 bytes

        let version = (packet[0] & 0xF0) >> 4
        guard version == 6 else { return false }

        // Check if destination address (bytes 24-39) starts with 0xff (multicast)
        return packet[24] == 0xFF
    }

    /// Resolve all addresses for the supernode host, IPv6 first. Returns an
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

        // Prefer IPv6 and hand every resolved address to the core, which
        // races them Happy-Eyeballs style. Deduplicate — getaddrinfo may
        // return the same address multiple times.
        var seen = Set<String>()
        return (ipv6Addresses + ipv4Addresses).filter {
            seen.insert($0).inserted
        }
    }
}

#if os(iOS)
private func hardwareModelIdentifier() -> String {
    #if targetEnvironment(simulator)
    if let identifier = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] {
        return identifier
    }
    #endif

    var systemInfo = utsname()
    guard uname(&systemInfo) == 0 else {
        return UIDevice.current.model
    }
    return withUnsafeBytes(of: &systemInfo.machine) { buffer in
        guard let baseAddress = buffer.baseAddress else {
            return UIDevice.current.model
        }
        return String(cString: baseAddress.assumingMemoryBound(to: CChar.self))
    }
}

private func deviceModelName(for identifier: String) -> String {
    let modelNames = [
        "iPhone11,2": "iPhone XS",
        "iPhone11,4": "iPhone XS Max",
        "iPhone11,6": "iPhone XS Max",
        "iPhone11,8": "iPhone XR",
        "iPhone12,1": "iPhone 11",
        "iPhone12,3": "iPhone 11 Pro",
        "iPhone12,5": "iPhone 11 Pro Max",
        "iPhone12,8": "iPhone SE (2nd generation)",
        "iPhone13,1": "iPhone 12 mini",
        "iPhone13,2": "iPhone 12",
        "iPhone13,3": "iPhone 12 Pro",
        "iPhone13,4": "iPhone 12 Pro Max",
        "iPhone14,2": "iPhone 13 Pro",
        "iPhone14,3": "iPhone 13 Pro Max",
        "iPhone14,4": "iPhone 13 mini",
        "iPhone14,5": "iPhone 13",
        "iPhone14,6": "iPhone SE (3rd generation)",
        "iPhone14,7": "iPhone 14",
        "iPhone14,8": "iPhone 14 Plus",
        "iPhone15,2": "iPhone 14 Pro",
        "iPhone15,3": "iPhone 14 Pro Max",
        "iPhone15,4": "iPhone 15",
        "iPhone15,5": "iPhone 15 Plus",
        "iPhone16,1": "iPhone 15 Pro",
        "iPhone16,2": "iPhone 15 Pro Max",
        "iPhone17,1": "iPhone 16 Pro",
        "iPhone17,2": "iPhone 16 Pro Max",
        "iPhone17,3": "iPhone 16",
        "iPhone17,4": "iPhone 16 Plus",
        "iPhone17,5": "iPhone 16e",
        "iPhone18,1": "iPhone 17 Pro",
        "iPhone18,2": "iPhone 17 Pro Max",
        "iPhone18,3": "iPhone 17",
        "iPhone18,4": "iPhone Air",
        "iPhone18,5": "iPhone 17e",
        "i386": "iPhone Simulator",
        "x86_64": "iPhone Simulator",
        "arm64": "iPhone Simulator",
    ]
    return modelNames[identifier] ?? identifier
}
#endif
