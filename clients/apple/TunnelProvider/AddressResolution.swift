// SPDX-License-Identifier: MIT
import Darwin
import Foundation
import os.log
import VaultCore

extension PacketTunnelProvider {
    /// Resolve all addresses for platform route exclusions. Returns an
    /// empty array on failure. The caller installs exclusions on main.
    func resolveAllAddresses(_ hostname: String) -> [String] {
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
            guard let socketAddress = addr.pointee.ai_addr else { continue }

            switch Int32(socketAddress.pointee.sa_family) {
            case AF_INET:
                let ip = socketAddress.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    String(cString: inet_ntoa($0.pointee.sin_addr))
                }
                ipv4Addresses.append(ip)

            case AF_INET6:
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                _ = socketAddress.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { addr in
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
