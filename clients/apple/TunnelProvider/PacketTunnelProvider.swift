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
    /// + 8 nonce (EXTRA_LEN in core/src/lib.rs)
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
    /// Fail a start attempt fast when the server does not answer. Slightly
    /// above the Rust handshake timeout (5s).
    static let startTimeout: TimeInterval = 6
    /// Server outage tolerance after a successful start before the tunnel
    /// is cancelled so traffic goes direct (a dead server blackholes it).
    static let serverUnreachableTimeout: TimeInterval = 15
}

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var dns: [String] = ["1.1.1.1", "8.8.8.8"]
    private var edge: Edge!
    private var startCompletion: ((Error?) -> Void)?
    private var startTimeoutWorkItem: DispatchWorkItem?
    /// Polls the Rust core's traffic counters once per second and publishes
    /// them to the main app via `PacketStats` (App Group UserDefaults).
    private var statsTimer: DispatchSourceTimer?
    /// Logs an "alive" marker with the memory footprint every 30s. When the
    /// markers stop without a stopTunnel/sleep line, the process was killed
    /// or suspended without warning.
    private var aliveTimer: DispatchSourceTimer?
    private let sessionStart = Date()
    private var stopRequested = false
    /// The server watchdog only applies once startTunnel succeeded.
    private var startFinished = false
    /// Diagnostic: counts startTunnel invocations per extension process.
    private static var startTunnelCallCount = 0
    private var superNodeIp: String = ""
    private var excludedV4Addresses: [String] = []
    private var excludedV6Addresses: [String] = []
    /// Addresses assigned by the supernode ("ipv4" or "ipv4/ipv6"), served
    /// to the app via handleAppMessage.
    private var assignedIp: String = ""
    /// A unique identifier for this provider instance so repeated Console.app
    /// lines can be matched to the same session.
    private let sessionID = String(UUID().uuidString.prefix(8))

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
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
            completionHandler(
                ConfigurationError.invalidConfiguration("protocol type")
            )
            return
        }

        guard let conf = protoConfig.providerConfiguration else {
            Logger.network.error("No provider configuration found")
            completionHandler(ConfigurationError.missingConfiguration)
            return
        }

        guard let rawHost = conf["host"] as? String, !rawHost.isEmpty else {
            Logger.network.error("Missing or empty host")
            completionHandler(ConfigurationError.invalidConfiguration("host"))
            return
        }
        // Accept "[::1]" style input by stripping URL-style brackets.
        let host =
            (rawHost.hasPrefix("[") && rawHost.hasSuffix("]"))
            ? String(rawHost.dropFirst().dropLast()) : rawHost

        guard let port = conf["port"] as? UInt16 else {
            Logger.network.error("Missing or invalid port")
            completionHandler(ConfigurationError.invalidConfiguration("port"))
            return
        }

        // The password travels in providerConfiguration: on macOS the
        // provider is a system extension running outside the user's session,
        // so App Group UserDefaults are not shared with it.
        guard let password = conf["password"] as? String, !password.isEmpty else {
            Logger.network.error("Missing password")
            completionHandler(
                ConfigurationError.invalidConfiguration("password")
            )
            return
        }

        guard let id = conf["id"] as? Data else {
            Logger.network.error("Missing id")
            completionHandler(ConfigurationError.invalidConfiguration("id"))
            return
        }

        // DNS is optional, use default values
        if let dnsServers = conf["dns"] as? String, !dnsServers.isEmpty {
            self.dns = dnsServers.components(separatedBy: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }

        // Resolve the supernode address on a background queue so a slow
        // DNS lookup does not block startTunnel.
        guard Self.claimStart() else {
            Logger.network.error(
                "startTunnel rejected: another start is in progress (pid \(ProcessInfo.processInfo.processIdentifier), provider \(ObjectIdentifier(self).hashValue, privacy: .public))"
            )
            completionHandler(
                ConfigurationError.invalidConfiguration("start in progress")
            )
            return
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
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else {
                Self.releaseStart()
                completionHandler(EdgeError.connectionFailed)
                return
            }
            let candidates = self.resolveAllAddresses(host)
            DispatchQueue.main.async {
                guard !candidates.isEmpty else {
                    Logger.network.error("Failed to resolve hostname: \(host)")
                    Self.releaseStart()
                    completionHandler(EdgeError.connectionFailed)
                    return
                }
                self.startContext = StartContext(
                    host: host,
                    port: port,
                    password: password,
                    id: id,
                    completionHandler: completionHandler
                )
                self.startCandidates = candidates
                self.startNextCandidate()
            }
        }

    }

    /// Everything needed to (re)start Edge with another supernode address.
    private struct StartContext {
        let host: String
        let port: UInt16
        let password: String
        let id: Data
        let completionHandler: (Error?) -> Void
    }
    private var startContext: StartContext?
    private var startCandidates: [String] = []
    /// Delays the failure of startTunnel after repeated unsuccessful
    /// starts, throttling the On-Demand restart loop for a dead server.
    private var startBackoffWorkItem: DispatchWorkItem?
    /// Persisted so the backoff survives the process restart that follows
    /// every failed start cycle.
    private static let startFailCountKey = "consecutiveStartFailures"
    /// Guards against overlapping startTunnel calls: each attempt owns
    /// exactly one Edge and one completion handler; overlapping starts
    /// would clobber them and lose completion handlers. Process-wide so it
    /// also protects against the system creating multiple provider
    /// instances in the same extension process.
    private static let startLock = NSLock()
    private static var processStartInFlight = false
    /// The provider instance owning the live tunnel session. The system may
    /// create a second provider instance in this process for the same
    /// tunnel; two live sessions share one peer id, so the supernode evicts
    /// the older one and the two would fight over the session forever.
    private static var activeProvider: PacketTunnelProvider?

    private static func claimStart() -> Bool {
        startLock.lock()
        defer { startLock.unlock() }
        if processStartInFlight { return false }
        processStartInFlight = true
        return true
    }

    private static func releaseStart() {
        startLock.lock()
        processStartInFlight = false
        startLock.unlock()
    }

    /// Start Edge with the next resolved supernode address. Used for the
    /// first attempt and by the handshake-timeout handler so a failure on
    /// one address family (e.g. IPv6 unreachable) falls back to the other.
    private func startNextCandidate() {
        guard let context = self.startContext, !self.startCandidates.isEmpty
        else {
            let failures =
                UserDefaults.standard.integer(forKey: Self.startFailCountKey) + 1
            UserDefaults.standard.set(failures, forKey: Self.startFailCountKey)
            // The system re-runs startTunnel immediately after a failure
            // (On-Demand); back off so a dead server does not produce a
            // tight reconnect loop. First failure stays fast.
            let backoff = min(Double(failures - 1) * 30, 120)
            Logger.network.errorAndFile(
                "[session:\(self.sessionID)] No more supernode candidates (failure #\(failures)), failing start in \(Int(backoff))s"
            )
            let item = DispatchWorkItem { [weak self] in
                self?.finishStart(with: EdgeError.connectionFailed)
            }
            self.startBackoffWorkItem = item
            DispatchQueue.main.asyncAfter(deadline: .now() + backoff, execute: item)
            return
        }
        let superNodeIp = self.startCandidates.removeFirst()
        Logger.network.noticeAndFile(
            "[session:\(self.sessionID)] Trying supernode address \(superNodeIp)"
        )
        // Clean up a previous failed attempt, if any.
        if let edge = self.edge {
            try? edge.close()
            self.edge = nil
        }
        // Drop any stale completion from the previous attempt so the
        // error paths below can invoke context.completionHandler directly
        // without risking a double-call.
        self.startCompletion = nil
        self.startEdge(
            superNodeIp: superNodeIp,
            host: context.host,
            port: context.port,
            password: context.password,
            id: context.id,
            completionHandler: context.completionHandler
        )
    }

    private func startEdge(
        superNodeIp: String,
        host: String,
        port: UInt16,
        password: String,
        id: Data,
        completionHandler: @escaping (Error?) -> Void
    ) {
        self.superNodeIp = superNodeIp

        guard !self.stopRequested else {
            Logger.network.error("Tunnel was stopped while starting")
            Self.releaseStart()
            completionHandler(EdgeError.connectionFailed)
            return
        }

        guard self.edge == nil else {
            Logger.network.error("Tunnel already started")
            Self.releaseStart()
            completionHandler(
                ConfigurationError.invalidConfiguration("Tunnel already started")
            )
            return
        }

        do {
            let config = EdgeConfig(
                password: password,
                host: host,
                port: port
            )

            // Reported in the handshake so the supernode can log which
            // device and OS a peer is running.
            #if os(macOS)
            let platform = "macos"
            let reportedName = Host.current().localizedName ?? "Mac"
            #else
            let platform = "ios"
            let reportedName = UIDevice.current.name
            #endif
            let trimmedName = reportedName.trimmingCharacters(in: .whitespacesAndNewlines)
            let deviceName = trimmedName.isEmpty ? "unknown" : trimmedName

            self.edge = try Edge(
                config: config,
                id: id,
                superNodeIp: superNodeIp,
                deviceName: deviceName,
                platform: platform,
                onData: writePacketToTunnel,
                onIpAssigned: onIpAssigned,
                pendingCompletion: completionHandler
            )
            Logger.network.noticeAndFile("[session:\(self.sessionID)] Init edge successfully")

            self.startCompletion = completionHandler

            // If the handshake does not complete in time, try the next
            // resolved address (falling back to the other address family);
            // only fail when no candidates remain. Without any failure path
            // the system VPN state would be stuck in .connecting.
            let timeoutWorkItem = DispatchWorkItem { [weak self] in
                guard let self = self else { return }
                Logger.network.errorAndFile("[session:\(self.sessionID)] Tunnel handshake timed out")
                self.startNextCandidate()
            }
            self.startTimeoutWorkItem = timeoutWorkItem
            DispatchQueue.main.asyncAfter(
                deadline: .now() + TunnelConstants.startTimeout,
                execute: timeoutWorkItem
            )

        } catch {
            Logger.network.errorAndFile(
                "[session:\(self.sessionID)] Edge init failed: \(error.localizedDescription)"
            )
            Self.releaseStart()
            completionHandler(error)
        }

    }

    /// Invoke the pending startTunnel completion handler exactly once and
    /// cancel the handshake timeout.
    private func finishStart(with error: Error?) {
        self.startTimeoutWorkItem?.cancel()
        self.startTimeoutWorkItem = nil
        self.startBackoffWorkItem?.cancel()
        self.startBackoffWorkItem = nil
        self.startContext = nil
        self.startCandidates = []
        Self.releaseStart()
        if let error = error {
            Logger.network.errorAndFile(
                "[session:\(self.sessionID)] startTunnel failed: \(error.localizedDescription)"
            )
        } else {
            self.startFinished = true
            Self.activeProvider = self
            UserDefaults.standard.set(0, forKey: Self.startFailCountKey)
            Logger.network.noticeAndFile("[session:\(self.sessionID)] startTunnel completed")
        }
        // On failure, tear down the Edge immediately instead of leaving it
        // handshaking every 10s until the system calls stopTunnel.
        if error != nil, let edge = self.edge {
            try? edge.close()
            self.edge = nil
        }
        guard let completion = self.startCompletion else {
            Logger.network.warningAndFile(
                "[session:\(self.sessionID)] finishStart with no pending completion (already stopped?)"
            )
            return
        }
        self.startCompletion = nil
        completion(error)
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        // Synchronous log: the process may be suspended or killed right
        // after the completion handler runs; an async write could lose the
        // line that explains why the tunnel went away.
        FileLogger.shared.logSync(
            "[session:\(self.sessionID)] stopTunnel called, reason: \(Self.describeStopReason(reason))(\(reason.rawValue))",
            level: "NOTICE"
        )
        self.stopRequested = true
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
        if let pendingStart = self.startCompletion {
            self.startCompletion = nil
            pendingStart(NEVPNError(.connectionFailed))
        }
        self.startContext = nil
        self.startCandidates = []
        Self.releaseStart()
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
            exit(0)
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
        exit(0)

    }

    /// Shut down this instance's session without touching system tunnel
    /// state: when the system spawns a second provider for the same tunnel,
    /// the packet flow moves to the new instance ("IPC detached") and this
    /// one only owns a zombie Rust session whose heartbeats would otherwise
    /// keep fighting the new session at the server.
    private func abandonSession() {
        self.stopRequested = true
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
    }

    deinit {
        Logger.network.noticeAndFile("[session:\(sessionID)] Provider deinit (process likely exiting)")
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
    private func tunnelMtu() -> Int {
        guard let linkMtu = probeUnderlyingLinkMtu() else {
            Logger.network.warningAndFile(
                "[session:\(self.sessionID)] Underlying link MTU probe failed; using fallback \(TunnelConstants.mtuUpperBound)"
            )
            return TunnelConstants.mtuUpperBound
        }
        let mtu = min(
            max(linkMtu - TunnelConstants.tunnelOverhead, TunnelConstants.mtuLowerBound),
            TunnelConstants.mtuUpperBound
        )
        Logger.network.noticeAndFile(
            "[session:\(self.sessionID)] Link MTU \(linkMtu) → tunnel MTU \(mtu)"
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
            let ipv6Settings = NEIPv6Settings(addresses: [ipv6], networkPrefixLengths: [NSNumber(value: 128)] )// Client uses /128

            let ipv6Network = extractIpv6Network(ipv6, prefixLen: ipv6Prefixlen)
            Logger.network.notice("IPv6 network: \(ipv6Network, privacy: .public)/\(ipv6Prefixlen)  :  \(ipv6, privacy: .public)")

            // NEIPv6Route.default() alone does not materialize a route on
            // macOS when the interface address is /128 (observed: address
            // present on utun, but no default/pool route in the table).
            // Declare the pool route explicitly so VPN-internal v6 traffic
            // always enters the tunnel.
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

        }

        let dnsSettings = NEDNSSettings(servers: dns)

        networkSettings.dnsSettings = dnsSettings
        networkSettings.mtu = NSNumber(value: tunnelMtu())

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

    func onIpAssigned(ipv4: String, ipv4Mask: String, ipv6: String, ipv6PrefixLen: Int32) {

        var assigned = ipv4
        if !ipv6.isEmpty {
            assigned += "/" + ipv6
        }
        self.assignedIp = assigned
        Logger.network.noticeAndFile(
            "[session:\(self.sessionID)] onIpAssigned: \(assigned) mask \(ipv4Mask) v6prefix \(ipv6PrefixLen) startPending=\(self.startCompletion != nil)"
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

        setTunnelNetworkSettings(settings) { [weak self] error in
            // Serialize with the handshake-timeout work item on the main
            // queue so finishStart cannot race with it.
            DispatchQueue.main.async {
                guard let self = self else { return }

                // Reconnect path: apply possibly-changed settings to the
                // live tunnel instead of leaving it routed at the old IP.
                guard self.startCompletion != nil else {
                    if let error = error {
                        Logger.network.errorAndFile(
                            "Failed to update network settings after reconnect: \(error)"
                        )
                    } else {
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
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        let status = ProviderStatus(
            ip: assignedIp,
            stats: PacketStats.shared.currentStats
        )
        completionHandler?(try? JSONEncoder().encode(status))
    }

    /// Log an "alive" marker (with the memory footprint) every 30s so the
    /// log can distinguish a live session, a suspension (markers pause,
    /// resume later) and a silent kill (markers stop, never resume). The
    /// timer ticks every 5s; the server watchdog runs on every tick.
    private func startAliveMarker() {
        self.aliveTimer?.cancel()
        var tick = 0
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + .seconds(5), repeating: .seconds(5))
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            // Server watchdog: a dead server blackholes all traffic via the
            // installed default route; cancel so traffic goes direct and
            // On-Demand retries. Liveness = last authenticated packet
            // (pong or data) seen by the Rust core.
            if self.startFinished,
                let edge = self.edge,
                edge.getLastActivityAgeSecs() > UInt64(TunnelConstants.serverUnreachableTimeout)
            {
                Logger.network.errorAndFile(
                    "[session:\(self.sessionID)] Server unreachable for >\(Int(TunnelConstants.serverUnreachableTimeout))s; cancelling tunnel so traffic goes direct"
                )
                self.cancelTunnelWithError(NEVPNError(.connectionFailed))
                return
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
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
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

        guard let edge = self.edge else {
            return
        }
        self.packetFlow.readPackets {
            (packets: [Data], _: [NSNumber]) in
            for packet in packets {
                self.handlePacket(packet, edge)
            }
            self.readPacketFromTunnel()
        }
    }

    private func handlePacket(_ packet: Data, _ edge: Edge) {
        // Filter out IPv6 multicast traffic (ff02::/16 and other multicast ranges)
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
    /// empty array on failure. As a side effect, records every resolved
    /// address in excludedV4/V6Addresses for route exclusion.
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

        self.excludedV4Addresses = ipv4Addresses
        self.excludedV6Addresses = ipv6Addresses
        // Prefer IPv6 but keep every resolved address so a failed attempt
        // can fall back to the other address family. Deduplicate —
        // getaddrinfo may return the same address multiple times.
        var seen = Set<String>()
        return (ipv6Addresses + ipv4Addresses).filter {
            seen.insert($0).inserted
        }
    }
}
