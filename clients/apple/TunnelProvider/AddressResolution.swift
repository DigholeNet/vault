// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import Network
import NetworkExtension
import os.log
import VaultCore

extension PacketTunnelProvider {
    /// Resolve and order all addresses with the same core policy used by reconnects.
    func resolveAllAddresses(_ hostname: String, port: UInt16) -> [String] {
        do {
            return try resolveServerCandidates(host: hostname, port: Int32(port))
        } catch {
            Logger.network.error("Unable to resolve \(hostname): \(error.localizedDescription)")
            return []
        }
    }
}

/// The provider owns path events, while the resolver takes immutable snapshots on Rust workers.
final class PhysicalPath: @unchecked Sendable {
    struct Snapshot: Equatable, Sendable {
        let index: UInt32
        let signature: String
        let generation: UInt64
        let gatewayIPv4: String?
        let lanAddresses: [String]
    }

    private let lock = NSLock()
    private var state = Snapshot(index: 0, signature: "", generation: 0, gatewayIPv4: nil, lanAddresses: [])

    var snapshot: Snapshot { lock.withLock { state } }

    @discardableResult
    func update(index: UInt32, signature: String, gatewayIPv4: String? = nil,
                lanAddresses: [String] = [], force: Bool = false) -> Bool {
        lock.withLock {
            guard force || state.index != index || state.signature != signature
                    || state.gatewayIPv4 != gatewayIPv4 || state.lanAddresses != lanAddresses else { return false }
            state = Snapshot(index: index, signature: signature,
                             generation: state.generation &+ 1, gatewayIPv4: gatewayIPv4,
                             lanAddresses: lanAddresses)
            return true
        }
    }

    static func addresses(on name: String) -> (hosts: [String], cidrs: [String]) {
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0, let interfaces else { return ([], []) }
        defer { freeifaddrs(interfaces) }

        var hosts: [String] = []
        var cidrs: [String] = []
        var entry: UnsafeMutablePointer<ifaddrs>? = interfaces
        while let current = entry {
            let item = current.pointee
            entry = item.ifa_next
            guard String(cString: item.ifa_name) == name, let address = item.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET)
                    || address.pointee.sa_family == UInt8(AF_INET6) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len),
                           &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let numeric = String(cString: host)
                hosts.append(numeric)
                if let mask = item.ifa_netmask,
                   let prefix = prefixLength(mask, family: address.pointee.sa_family) {
                    cidrs.append("\(numeric)/\(prefix)")
                }
            }
        }
        return (hosts.sorted(), cidrs.sorted())
    }

    private static func prefixLength(_ mask: UnsafePointer<sockaddr>, family: UInt8) -> Int? {
        func contiguousPrefix<T>(_ address: T) -> Int? {
            withUnsafeBytes(of: address) { bytes in
                let prefix = bytes.prefix(while: { $0 == .max }).count
                let tail = bytes.dropFirst(prefix)
                guard let partial = tail.first else { return prefix * 8 }
                let highBits = (~partial).leadingZeroBitCount
                guard partial.nonzeroBitCount == highBits,
                      tail.dropFirst().allSatisfy({ $0 == 0 }) else { return nil }
                return prefix * 8 + highBits
            }
        }
        if family == UInt8(AF_INET) {
            return mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                contiguousPrefix($0.pointee.sin_addr)
            }
        }
        return mask.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
            contiguousPrefix($0.pointee.sin6_addr)
        }
    }
}

final class RoutePreparation: @unchecked Sendable {
    let path: PhysicalPath.Snapshot
    let addresses: [String]
    private let semaphore = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var result: Bool?

    init(path: PhysicalPath.Snapshot, addresses: [String]) {
        self.path = path
        self.addresses = addresses
    }

    var isPending: Bool { lock.withLock { result == nil } }

    func finish(_ succeeded: Bool) {
        lock.withLock {
            guard result == nil else { return }
            result = succeeded
            semaphore.signal()
        }
    }

    func wait() -> Bool {
        if semaphore.wait(timeout: .now() + 3) == .timedOut {
            finish(false)
        }
        return lock.withLock { result == true }
    }
}

extension PacketTunnelProvider {
    /// Path events run alongside tunnel configuration on the main queue.
    func startNetworkMonitoring() {
        guard pathMonitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in self?.updatePhysicalPath(path) }
        pathMonitor = monitor
        monitor.start(queue: .main)
    }

    func updatePhysicalPath(_ path: Network.NWPath?, force: Bool = false, refreshMTUOnUnchangedPath: Bool = true) {
        guard !stopRequested else { return }
        let interface = path.flatMap { path in
            guard path.status == .satisfied else { return nil as Network.NWInterface? }
            return path.availableInterfaces.first {
                path.usesInterfaceType($0.type) && !$0.name.hasPrefix("utun") && $0.type != .loopback
            }
        }
        let addresses = interface.map { PhysicalPath.addresses(on: $0.name) }
        let signature = interface.map {
            "\($0.name)|\(addresses?.hosts ?? [])|\(path?.supportsIPv4 ?? false)|"
                + "\(path?.supportsIPv6 ?? false)|\(path?.gateways.map { String(describing: $0) }.sorted() ?? [])"
        } ?? ""
        let gatewayIPv4: String?
        let lanCapable = interface?.type == .wifi || interface?.type == .wiredEthernet
        if lanCapable {
            gatewayIPv4 = path?.gateways.compactMap { endpoint in
                if case let .hostPort(host, _) = endpoint, case let .ipv4(address) = host {
                    return String(describing: address)
                }
                return nil
            }.first
        } else {
            gatewayIPv4 = nil
        }
        let changed = physicalPath.update(index: UInt32(clamping: interface?.index ?? 0),
                                          signature: signature, gatewayIPv4: gatewayIPv4,
                                          lanAddresses: lanCapable ? addresses?.cidrs ?? [] : [], force: force)
        if changed {
            Logger.network.noticeAndFile("Physical network generation changed interface=\(interface?.name ?? "unavailable")")
            notifyNetworkChanged()
        }
        if let path, changed || refreshMTUOnUnchangedPath { refreshMTU(path) }
    }

    /// Run DNS on the Rust blocking worker. The returned generation also
    /// identifies the physical interface used to bind every racing socket.
    func resolveTransport(host: String, port: UInt16) -> MobileTransport? {
        let snapshot = physicalPath.snapshot
        guard snapshot.index != 0 else { return nil }
        let candidates = resolveAllAddresses(host, port: port)
        guard physicalPath.snapshot == snapshot else { return nil }
        let preparation = RoutePreparation(path: snapshot, addresses: candidates)
        DispatchQueue.main.async { [weak self] in
            guard let self, !self.stopRequested, self.physicalPath.snapshot == snapshot,
                  preparation.isPending else {
                preparation.finish(false)
                return
            }
            self.routePreparation?.finish(false)
            self.routePreparation = preparation
            self.advanceRoutePreparation()
        }
        guard preparation.wait(), physicalPath.snapshot == snapshot else { return nil }
        return MobileTransport(addresses: candidates, network: UInt64(snapshot.index),
                               generation: snapshot.generation, gatewayIpv4: snapshot.gatewayIPv4,
                               lanAddresses: snapshot.lanAddresses)
    }

    func advanceRoutePreparation() {
        guard let preparation = routePreparation, !clearingRouteSettings,
              tunnelSettings.outstanding == nil else { return }
        guard preparation.isPending, physicalPath.snapshot == preparation.path, !stopRequested else {
            preparation.finish(false)
            routePreparation = nil
            return
        }
        if preparation.addresses.isEmpty {
            if tunnelSettings.applied == nil {
                preparation.finish(false)
                routePreparation = nil
            } else {
                withdrawRoutesForResolution(preparation)
            }
            return
        }
        if let applied = tunnelSettings.applied, applied.serverCandidates != preparation.addresses {
            let configuration = TunnelConfiguration(
                ipv4: applied.ipv4, mask: applied.mask, ipv6: applied.ipv6,
                prefix: applied.prefix, mtu: applied.mtu, dns: applied.dns,
                serverCandidates: preparation.addresses
            )
            if let update = tunnelSettings.enqueue(configuration) {
                applyingPreparation = (update.revision, preparation)
                applySettings(update)
            }
            return
        }
        preparation.finish(true)
        routePreparation = nil
    }

    func completeRoutePreparation(_ update: TunnelSettingsState.Update, error: Error?) -> Bool {
        guard let applyingPreparation, applyingPreparation.revision == update.revision else { return false }
        self.applyingPreparation = nil
        if error != nil {
            applyingPreparation.request.finish(false)
            if routePreparation === applyingPreparation.request { routePreparation = nil }
        }
        advanceRoutePreparation()
        if let next = tunnelSettings.next() { applySettings(next) }
        return true
    }

    /// If the resolver relied on the disconnected TUN, remove its settings
    /// before retrying. This OS call shares the settings application's slot.
    private func withdrawRoutesForResolution(_ preparation: RoutePreparation) {
        clearingRouteSettings = true
        let token = sessionToken
        let timeout = DispatchWorkItem { [weak self] in
            guard let self, self.sessionToken == token, self.clearingRouteSettings else { return }
            preparation.finish(false)
            self.recycleAfterSettingsTimeout()
        }
        settingsTimeoutWorkItem = timeout
        DispatchQueue.main.asyncAfter(deadline: .now() + TunnelConstants.startTimeout, execute: timeout)
        setTunnelNetworkSettings(nil) { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                self.clearingRouteSettings = false
                guard !self.stopRequested, self.sessionToken == token else {
                    preparation.finish(false)
                    return
                }
                self.settingsTimeoutWorkItem?.cancel()
                self.settingsTimeoutWorkItem = nil
                if error == nil {
                    self.tunnelSettings.reset()
                    self.edge?.setPeerMTU(0)
                    let current = self.physicalPath.snapshot
                    self.physicalPath.update(index: current.index, signature: current.signature,
                                             gatewayIPv4: current.gatewayIPv4,
                                             lanAddresses: current.lanAddresses, force: true)
                    self.notifyNetworkChanged()
                } else if let error {
                    Logger.network.errorAndFile("Could not clear routes for resolution: \(error)")
                }
                preparation.finish(false)
                if self.routePreparation === preparation { self.routePreparation = nil }
                self.advanceRoutePreparation()
            }
        }
    }
}
