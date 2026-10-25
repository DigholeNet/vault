// SPDX-License-Identifier: MIT
import Network
import NetworkExtension
import VaultCore
import os.log

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
    /// Platform startup deadline; transport attempts and backoff remain in Rust.
    static let startTimeout: TimeInterval = 30
}

enum TunnelNetworkSettings {
    /// MTU of the physical interface carrying the default route, or nil
    /// when it cannot be determined (no route, no matching interface, or
    /// ioctl failure). A UDP connect() transmits nothing; it only makes
    /// the kernel pick the egress interface and source address for the
    /// destination, which exposes the default route's interface.
    private static func probeUnderlyingLinkMtu() -> Int? {
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
    static func mtu(cap: Int, sessionID: String) -> Int {
        guard let linkMtu = probeUnderlyingLinkMtu() else {
            Logger.network.warningAndFile(
                "[session:\(sessionID)] Underlying link MTU probe failed; using fallback \(cap)"
            )
            return cap
        }
        let mtu = min(
            max(linkMtu - TunnelConstants.tunnelOverhead, TunnelConstants.mtuLowerBound),
            cap
        )
        Logger.network.noticeAndFile(
            "[session:\(sessionID)] Link MTU \(linkMtu) → tunnel MTU \(mtu) (cap \(cap))"
        )
        return mtu
    }

    static func make(_ configuration: TunnelConfiguration, remoteAddress: String,
        candidates: [String], dns: [String]) -> NEPacketTunnelNetworkSettings {
        let superNodeIp = remoteAddress
        let excludedV4Addresses = candidates.filter { !$0.contains(":") }
        let excludedV6Addresses = candidates.filter { $0.contains(":") }
        let ipv4 = configuration.ipv4
        let ipv4Mask = configuration.mask
        let ipv6 = configuration.ipv6
        let ipv6Prefixlen = configuration.prefix
        let networkSettings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: superNodeIp
        )

        if !ipv4.isEmpty && !ipv4Mask.isEmpty {
            let ipv4Settings = NEIPv4Settings(
                addresses: [ipv4],
                subnetMasks: [ipv4Mask]
            )
            ipv4Settings.includedRoutes = [NEIPv4Route.default()]

            let excludedRoutes = excludedV4Addresses.map {
                NEIPv4Route(destinationAddress: $0, subnetMask: "255.255.255.255")
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

            let excludedRoutesV6 = excludedV6Addresses.map {
                NEIPv6Route(destinationAddress: $0, networkPrefixLength: 128)
            }
            ipv6Settings.excludedRoutes = excludedRoutesV6
            networkSettings.ipv6Settings = ipv6Settings
            Logger.network.noticeAndFile(
                "IPv6 settings: interface=\(ipv6)/120 pool=\(ipv6Network)/\(ipv6Prefixlen) included=pool,::/0 excluded=\(excludedRoutesV6.map(\.destinationAddress).joined(separator: ","))"
            )

        }

        let dnsSettings = NEDNSSettings(servers: dns)

        networkSettings.dnsSettings = dnsSettings
        networkSettings.mtu = NSNumber(value: configuration.mtu)

        return networkSettings
    }

    private static func extractIpv6Network(_ ipv6: String, prefixLen: Int32) -> String {
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

}
