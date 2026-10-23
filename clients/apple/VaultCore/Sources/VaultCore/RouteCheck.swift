//
//  RouteCheck.swift
//  VaultCore
//
//
//  App-side routing check for diagnostics. The network extension's own
//  sockets bypass the tunnel, so only the app process can observe which
//  interface the system default route really selects for user traffic.
//
//  Technique: connect() on a UDP socket sends no packets; getsockname then
//  returns the local address the routing table picked — the tunnel address
//  when the default route enters the tunnel, a physical LAN address when
//  the VPN is "connected" but its routes never materialized (a failure mode
//  observed on macOS: Connected state, no utun default route, all traffic
//  bypassing the tunnel).
//

import Foundation

public enum RouteCheck {

    /// Local addresses the default routes select for IPv4/IPv6 traffic.
    /// nil means no route exists for that family at all.
    public static func defaultRouteLocalAddresses() -> (ipv4: String?, ipv6: String?) {
        (
            probe(family: AF_INET, address: "1.1.1.1", port: 53),
            probe(family: AF_INET6, address: "2606:4700:4700::1111", port: 53)
        )
    }

    private static func probe(family: Int32, address: String, port: UInt16) -> String? {
        let fd = socket(family, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var storage = sockaddr_storage()
        let addrLen: socklen_t
        if family == AF_INET6 {
            addrLen = socklen_t(MemoryLayout<sockaddr_in6>.size)
            let rc = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in6()
                    sin.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    sin.pointee.sin6_family = sa_family_t(AF_INET6)
                    sin.pointee.sin6_port = port.bigEndian
                    return inet_pton(AF_INET6, address, &sin.pointee.sin6_addr)
                }
            }
            guard rc == 1 else { return nil }
        } else {
            addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let rc = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in()
                    sin.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    sin.pointee.sin_family = sa_family_t(AF_INET)
                    sin.pointee.sin_port = port.bigEndian
                    return inet_pton(AF_INET, address, &sin.pointee.sin_addr)
                }
            }
            guard rc == 1 else { return nil }
        }

        let connected = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(fd, sa, addrLen)
            }
        }
        guard connected == 0 else { return nil }

        var local = sockaddr_storage()
        var localLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let got = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getsockname(fd, sa, &localLen)
            }
        }
        guard got == 0 else { return nil }

        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if family == AF_INET6 {
            return withUnsafePointer(to: &local) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin in
                    var addr = sin.pointee.sin6_addr
                    inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                    return String(cString: buf)
                }
            }
        }
        return withUnsafePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                var addr = sin.pointee.sin_addr
                inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
                return String(cString: buf)
            }
        }
    }
}
