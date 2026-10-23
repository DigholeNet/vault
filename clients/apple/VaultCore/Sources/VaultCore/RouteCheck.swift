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

    public struct Assessment: Sendable {
        public var issues: [String] = []
        public var unavailable: [String] = []
    }

    /// `assignedIP` must come from the live provider, never a persisted cache.
    /// Missing metadata cannot establish a route mismatch or an IPv6 bypass.
    public static func assess(
        routes: (ipv4: String?, ipv6: String?), assignedIP: String?
    ) -> Assessment {
        var result = Assessment()
        guard let assignedIP, !assignedIP.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            result.unavailable.append("Current tunnel addresses unavailable; route check incomplete")
            return result
        }
        let parts = assignedIP.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else {
            result.unavailable.append("Tunnel address metadata invalid; route check incomplete")
            return result
        }
        let ipv4 = parts.first.map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) } ?? ""
        let ipv6 = parts.count > 1 ? String(parts[1]).trimmingCharacters(in: .whitespacesAndNewlines) : ""
        let validV4 = isAddress(ipv4, family: AF_INET)
        let validV6 = isAddress(ipv6, family: AF_INET6)
        if validV4 {
            if let route = routes.ipv4 {
                if !sameAddress(route, ipv4) {
                    result.issues.append("IPv4 route to 1.1.1.1 selects \(route); expected tunnel address \(ipv4)")
                }
            } else {
                result.unavailable.append("IPv4 route unavailable; cannot verify tunnel routing")
            }
        } else {
            result.unavailable.append("Tunnel IPv4 address unavailable; route check incomplete")
        }
        if validV6 {
            if let route = routes.ipv6 {
                if !sameAddress(route, ipv6) {
                    result.issues.append("IPv6 route selects \(route); expected tunnel address \(ipv6)")
                }
            } else {
                result.unavailable.append("IPv6 route unavailable; cannot verify tunnel routing")
            }
        } else if !ipv6.isEmpty {
            result.unavailable.append("Tunnel IPv6 address invalid; route check incomplete")
        } else if validV4, let route = routes.ipv6 {
            // Only a valid, live IPv4-only assignment supports this inference.
            result.issues.append("IPv6 route selects \(route) but the current provider reports no tunnel IPv6 address; possible IPv6 bypass")
        }
        return result
    }

    private static func isAddress(_ address: String, family: Int32) -> Bool {
        var bytes = in6_addr()
        return inet_pton(family, address, &bytes) == 1
    }

    /// Local addresses the default routes select for IPv4/IPv6 traffic.
    /// nil means the socket probe could not determine a local address.
    public static func defaultRouteLocalAddresses() -> (ipv4: String?, ipv6: String?) {
        (
            probe(family: AF_INET, address: "1.1.1.1", port: 53),
            probe(family: AF_INET6, address: "2606:4700:4700::1111", port: 53)
        )
    }

    public static func sameAddress(_ lhs: String?, _ rhs: String?) -> Bool {
        guard let lhs, let rhs else { return false }
        for family in [AF_INET, AF_INET6] {
            var a = in6_addr()
            var b = in6_addr()
            if inet_pton(family, lhs, &a) == 1, inet_pton(family, rhs, &b) == 1 {
                return withUnsafeBytes(of: a) { aa in
                    withUnsafeBytes(of: b) { bb in aa.elementsEqual(bb) }
                }
            }
        }
        return false
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

extension DiagnosticsResult {
    public mutating func appendRouteAssessment(_ assessment: RouteCheck.Assessment) {
        if !assessment.issues.isEmpty {
            if summary.hasPrefix("OK") { summary = "PROBLEMS FOUND (route check)" }
            summary += "; " + assessment.issues.joined(separator: "; ")
        }
        if !assessment.unavailable.isEmpty {
            if summary.hasPrefix("OK") { summary = "INCOMPLETE (route check)" }
            else if !summary.contains("INCOMPLETE") { summary += "; INCOMPLETE (route check)" }
            summary += "; " + assessment.unavailable.joined(separator: "; ")
        }
        lines.append(contentsOf: (assessment.issues + assessment.unavailable).map { "[probe] route: \($0)" })
    }
}
