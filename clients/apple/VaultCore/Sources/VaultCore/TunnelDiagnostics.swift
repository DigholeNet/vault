//
//  TunnelDiagnostics.swift
//  VaultCore
//
//
//  Active probing for the "VPN is on and ping works, but web pages do not
//  load" class of failures. The provider's own sockets bypass the tunnel by
//  default, so every probe pins itself to an interface explicitly: the utun
//  interface (tunnel path, via IP_BOUND_IF / NWParameters.requiredInterface)
//  and the physical interface (direct path, as a control group). Every step
//  appends a "[probe]" line to the shared file log so a failing session can
//  be diagnosed after the fact from View Logs.
//
//  The suite is synchronous and meant to run on a background queue; each
//  probe has its own timeout and the whole suite gives up past a total
//  budget so a wedged path cannot stall the caller forever.
//

import Foundation
import Network
import Security
import os.log

public struct DiagnosticsResult: Codable, Sendable {
    public var summary: String
    public var lines: [String]

    public init(summary: String, lines: [String]) {
        self.summary = summary
        self.lines = lines
    }
}

public enum TunnelDiagnostics {

    /// Domains probed when the user has not configured any: one neutral
    /// control reachable everywhere, plus two typically blocked sites.
    public static let defaultProbeDomains = ["www.google.com", "github.com", "t.co"]

    private static let totalBudget: TimeInterval = 60
    private static let dnsTimeout: TimeInterval = 3
    private static let icmpTimeout: TimeInterval = 2
    private static let tcpTimeout: TimeInterval = 4
    private static let httpsTimeout: TimeInterval = 6
    /// IP packet sizes for the MTU sweep: a small baseline, ~1200, and the
    /// actual tunnel MTU — probing above the configured MTU cap would just
    /// EMSGSIZE on the utun interface.
    static func mtuSweepSizes(tunnelMtu: Int?) -> [Int] {
        let mtu = tunnelMtu ?? 1427
        return Array(Set([64, min(1200, mtu), mtu])).sorted()
    }

    private struct Context {
        let startedAt: Date
        let tunnelName: String
        let tunnelIndex: UInt32
        let tunnelNWInterface: NWInterface?
        let physicalName: String?
        let physicalIndex: UInt32?
        let physicalNWInterface: NWInterface?
        /// The supernode's own endpoint, used as the physical-path control:
        /// it must answer on the physical link whenever the tunnel is up,
        /// so a failed control connect really means the link is sick.
        /// (Using a probe domain as the control misfires for domains that
        /// are blocked on the direct path.)
        var controlEndpoint: (host: String, port: UInt16)?
        var mtuSizes: [Int] = mtuSweepSizes(tunnelMtu: nil)
        var lines: [String] = []
        var suspects: [String] = []
        var stageSummaries: [String] = []
        var failures = 0
        var overBudget: Bool { Date().timeIntervalSince(startedAt) > totalBudget }
    }

    /// Runs the full probe suite. `tunnelIPv4` is the address the supernode
    /// assigned to the utun interface (used to locate the interface).
    public static func run(
        dnsServers: [String], tunnelIPv4: String, tunnelIPv4Mask: String?, domains: [String],
        controlEndpoint: (host: String, port: UInt16)? = nil, tunnelMtu: Int? = nil
    ) -> DiagnosticsResult {
        let start = Date()
        let header = "[probe] ==== diagnostics start ===="
        log(header)

        guard var ctx = discoverInterfaces(tunnelIPv4: tunnelIPv4) else {
            let line = "[probe] abort: tunnel interface carrying \(tunnelIPv4) not found"
            log(line)
            return DiagnosticsResult(summary: "tunnel interface not found", lines: [header, line])
        }
        ctx.controlEndpoint = controlEndpoint
        ctx.mtuSizes = mtuSweepSizes(tunnelMtu: tunnelMtu)
        ctx.lines.append(header)
        log(
            &ctx,
            "[probe] interfaces: tunnel=\(ctx.tunnelName)(idx \(ctx.tunnelIndex))"
                + " physical=\(ctx.physicalName ?? "none")(idx \(ctx.physicalIndex ?? 0))"
        )

        let resolver = dnsServers.first ?? "1.1.1.1"
        let targets = domains.isEmpty ? defaultProbeDomains : domains
        log(&ctx, "[probe] targets: \(targets.joined(separator: ", ")); resolver \(resolver)")

        let gateway = tunnelIPv4Mask.flatMap { gatewayAddress(ip: tunnelIPv4, mask: $0) }
        icmpSweep(&ctx, resolver: resolver, gateway: gateway)
        let answers = dnsSweep(&ctx, resolver: resolver, domains: targets)
        tcpSweep(&ctx, domains: targets, answers: answers)
        httpsSweep(&ctx, domains: targets, answers: answers)

        let summary = summarize(ctx: ctx, answers: answers)
        log(&ctx, "[probe] summary: \(summary)")
        let footer = "[probe] ==== diagnostics done in \(String(format: "%.1f", Date().timeIntervalSince(start)))s ===="
        log(footer)
        return DiagnosticsResult(summary: summary, lines: ctx.lines + [footer])
    }

    // MARK: - Suite steps

    /// ICMP echo at increasing packet sizes with DF set: small packets
    /// getting through while large ones vanish is the classic MTU black hole
    /// behind "ping works but TLS hangs".
    ///
    /// Two targets, two different meanings:
    /// - the tunnel gateway (the supernode's own TUN address) — the reply is
    ///   generated by the supernode kernel and travels back through the
    ///   tunnel at full size, so this measures the tunnel path itself and
    ///   needs no ICMP forwarding to the internet;
    /// - the resolver — this additionally exercises the supernode's ICMP
    ///   forwarding/NAT, which is not required for TCP/UDP and may legitimately
    ///   be missing.
    ///
    /// Tunnel-side ICMP probes are deliberately NOT bound to the utun
    /// interface: unlike TCP/UDP, an ICMP datagram socket bound with
    /// IP_BOUND_IF never matches its replies on macOS. The extension follows
    /// the system routing table, and the tunnel owns the default route while
    /// it is up, so unbound echo requests take the tunnel — the same path
    /// system ping takes. The physical control below still binds.
    private static func icmpSweep(_ ctx: inout Context, resolver: String, gateway: String?) {
        var tunnelOkSizes: Int?
        if let gateway {
            let results = pingSizes(&ctx, host: gateway, ifIndex: 0)
            let ok = okSizeCount(results, sizes: ctx.mtuSizes)
            log(&ctx, "[probe] icmp via tunnel to gateway \(gateway): \(detail(of: results, sizes: ctx.mtuSizes))")
            if ok == 0 {
                // The gateway is the supernode's own address; it should
                // always answer. Without it the tunnel MTU cannot be
                // measured, but TCP/UDP may still be fine.
                ctx.suspects.append("tunnel gateway \(gateway) did not answer ICMP; tunnel MTU unmeasured")
            } else {
                tunnelOkSizes = ok
                ctx.stageSummaries.append("icmp-mtu \(ok)/\(ctx.mtuSizes.count) sizes ok (gateway)")
                if results[ctx.mtuSizes.first!]?.hasPrefix("ok") == true,
                    let largest = ctx.mtuSizes.last, results[largest]?.hasPrefix("lost") == true
                {
                    ctx.failures += 1
                    ctx.suspects.append("MTU black hole on tunnel path")
                }
            }
        }

        let results = pingSizes(&ctx, host: resolver, ifIndex: 0)
        let ok = okSizeCount(results, sizes: ctx.mtuSizes)
        log(&ctx, "[probe] icmp via tunnel to \(resolver): \(detail(of: results, sizes: ctx.mtuSizes))")
        if tunnelOkSizes == nil {
            ctx.stageSummaries.append("icmp-mtu \(ok)/\(ctx.mtuSizes.count) sizes ok")
        }
        if ok == 0, tunnelOkSizes != nil {
            // ICMP to the tunnel's own gateway works, only forwarded ICMP is
            // missing: informational, not a failure — TCP/UDP are unaffected.
            log(&ctx, "[probe] note: supernode does not forward ICMP to the internet (gateway answers, \(resolver) does not)")
        } else if ok > 0, ok < ctx.mtuSizes.count,
            results[ctx.mtuSizes.first!]?.hasPrefix("ok") == true,
            let largest = ctx.mtuSizes.last, results[largest]?.hasPrefix("lost") == true
        {
            ctx.failures += 1
            ctx.suspects.append("MTU black hole on tunnel path")
        } else if ok == 0, tunnelOkSizes == nil {
            ctx.failures += 1
            ctx.suspects.append("ICMP via tunnel fully broken")
        }

        // Physical-path control: ping the supernode itself (it answers the
        // tunnel heartbeat over the physical link, so it must be reachable
        // there whenever the tunnel is up). Bursts at two sizes quantify
        // link quality: the tunnel's UDP transport has no retransmission,
        // so physical loss becomes inner TCP loss — a link that drops large
        // packets is exactly "ping works, HTTPS stalls".
        if let physIndex = ctx.physicalIndex, let control = ctx.controlEndpoint {
            var rtts: [Int] = []
            var smallLost = 0
            var largeLost = 0
            for seq in 0..<10 {
                switch icmpPing(
                    host: control.host, ifIndex: physIndex,
                    totalSize: 64, sequence: UInt16(100 + seq), timeout: icmpTimeout
                ) {
                case .success(let rtt): rtts.append(Int(rtt * 1000))
                case .failure: smallLost += 1
                }
            }
            for seq in 0..<5 {
                if ctx.overBudget { break }
                switch icmpPing(
                    host: control.host, ifIndex: physIndex,
                    totalSize: 1400, sequence: UInt16(200 + seq), timeout: icmpTimeout
                ) {
                case .success(let rtt): rtts.append(Int(rtt * 1000))
                case .failure: largeLost += 1
                }
            }
            let rttDesc = rtts.isEmpty ? "-" : "\(rtts.min() ?? 0)/\(rtts.reduce(0, +) / rtts.count)ms"
            log(
                &ctx,
                "[probe] icmp control supernode(\(control.host)) via physical: "
                    + "64B lost \(smallLost)/10, 1400B lost \(largeLost)/5, rtt min/avg \(rttDesc)"
            )
            ctx.stageSummaries.append(
                "physical-link loss \(smallLost * 10)% small / \(largeLost * 20)% large"
            )
            if smallLost == 10 {
                ctx.failures += 1
                ctx.suspects.append("physical link unhealthy (supernode unreachable on physical path)")
            } else if smallLost >= 2 || largeLost >= 2 {
                ctx.failures += 1
                ctx.suspects.append(
                    "physical link to supernode is lossy (\(smallLost * 10)% small, \(largeLost * 20)% large); tunnel has no retransmission, so HTTPS stalls under this loss"
                )
            }
        }
    }

    /// Two echo requests per size; returns "ok rtt=…"/"lost" per size.
    /// ifIndex 0 means unbound (follow the routing table) — required for
    /// tunnel-side ICMP; see icmpSweep.
    private static func pingSizes(
        _ ctx: inout Context, host: String, ifIndex: UInt32
    ) -> [Int: String] {
        var results: [Int: String] = [:]
        for size in ctx.mtuSizes {
            if ctx.overBudget {
                log(&ctx, "[probe] icmp: skipped remaining sizes (time budget)")
                break
            }
            var ok = 0
            var rtts: [Int] = []
            for seq in 0..<2 {
                switch icmpPing(
                    host: host, ifIndex: ifIndex,
                    totalSize: size, sequence: UInt16(seq), timeout: icmpTimeout
                ) {
                case .success(let rtt):
                    ok += 1
                    rtts.append(Int(rtt * 1000))
                case .failure:
                    break
                }
            }
            results[size] = ok > 0 ? "ok rtt=\(rtts.first ?? 0)ms (\(ok)/2)" : "lost (0/2)"
        }
        return results
    }

    private static func okSizeCount(_ results: [Int: String], sizes: [Int]) -> Int {
        sizes.filter { results[$0]?.hasPrefix("ok") == true }.count
    }

    private static func detail(of results: [Int: String], sizes: [Int]) -> String {
        sizes.map { "size=\($0) \(results[$0] ?? "skipped")" }.joined(separator: "; ")
    }

    /// The tunnel gateway: the supernode allocates the first pool address
    /// (network + 1) for its own TUN device before any client.
    static func gatewayAddress(ip: String, mask: String) -> String? {
        var ipAddr = in_addr()
        var maskAddr = in_addr()
        guard inet_pton(AF_INET, ip, &ipAddr) == 1, inet_pton(AF_INET, mask, &maskAddr) == 1
        else { return nil }
        let ipValue = UInt32(bigEndian: ipAddr.s_addr)
        let maskValue = UInt32(bigEndian: maskAddr.s_addr)
        guard maskValue != 0 else { return nil }
        var gateway = in_addr(s_addr: ((ipValue & maskValue) + 1).bigEndian)
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &gateway, &buf, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buf)
    }

    /// Resolves each domain twice: through the tunnel and through the
    /// physical interface. Identical answers on both paths for a blocked
    /// domain mean the tunnel DNS leaked or the upstream is poisoned.
    private static func dnsSweep(_ ctx: inout Context, resolver: String, domains: [String]) -> [String: [String]] {
        var answers: [String: [String]] = [:]
        var tunnelOk = 0
        var tunnelFail = 0
        for domain in domains {
            if ctx.overBudget {
                log(&ctx, "[probe] dns: skipped remaining domains (time budget)")
                break
            }
            let tunnel = dnsQuery(server: resolver, domain: domain, ifIndex: ctx.tunnelIndex)
            let direct: Result<[String], ProbeError>? = ctx.physicalIndex.map {
                dnsQuery(server: resolver, domain: domain, ifIndex: $0)
            }
            let tunnelDesc = describe(tunnel)
            let directDesc = direct.map(describe) ?? "n/a"
            log(&ctx, "[probe] dns \(domain): tunnel=\(tunnelDesc) direct=\(directDesc)")
            if case .success(let ips) = tunnel, !ips.isEmpty {
                tunnelOk += 1
                answers[domain] = ips
                if case .success(let directIps) = direct, Set(ips) == Set(directIps) {
                    ctx.suspects.append("dns \(domain): tunnel answer identical to direct path (leak or poisoned upstream)")
                }
            } else {
                tunnelFail += 1
            }
        }
        ctx.stageSummaries.append("dns \(tunnelOk)/\(tunnelOk + tunnelFail) resolved")
        ctx.failures += tunnelFail
        if tunnelFail == domains.count, !domains.isEmpty {
            ctx.suspects.append("tunnel DNS unreachable")
        }
        return answers
    }

    /// TCP connect to port 443 of the tunnel-resolved addresses, plus one
    /// control connect over the physical interface to prove the underlying
    /// link itself is healthy.
    private static func tcpSweep(_ ctx: inout Context, domains: [String], answers: [String: [String]]) {
        var ok = 0
        var fail = 0
        for domain in domains {
            guard let ips = answers[domain], !ips.isEmpty else {
                log(&ctx, "[probe] tcp \(domain): skipped (no tunnel DNS answer)")
                continue
            }
            for ip in ips.prefix(2) {
                if ctx.overBudget {
                    log(&ctx, "[probe] tcp: skipped remaining (time budget)")
                    break
                }
                switch tcpConnect(ip: ip, port: 443, ifIndex: ctx.tunnelIndex, timeout: tcpTimeout) {
                case .success(let t):
                    ok += 1
                    log(&ctx, "[probe] tcp \(domain)(\(ip):443) via tunnel: ok \(Int(t * 1000))ms")
                case .failure(let why):
                    fail += 1
                    log(&ctx, "[probe] tcp \(domain)(\(ip):443) via tunnel: fail \(why)")
                }
            }
        }
        ctx.stageSummaries.append("tcp \(ok)/\(ok + fail) ok")
        ctx.failures += fail
        if fail > 0, ok == 0 {
            ctx.suspects.append("TCP via tunnel unreachable")
        }
    }

    /// Full TLS handshake + HTTP/1.1 request through the tunnel: this is the
    /// exact exchange that fails when "the page does not load". The peer
    /// certificate subject is logged to expose interception.
    private static func httpsSweep(_ ctx: inout Context, domains: [String], answers: [String: [String]]) {
        guard let iface = ctx.tunnelNWInterface else {
            log(&ctx, "[probe] https: skipped (no tunnel NWInterface)")
            return
        }
        var ok = 0
        var fail = 0
        for domain in domains {
            guard answers[domain]?.isEmpty == false else {
                log(&ctx, "[probe] https \(domain): skipped (no tunnel DNS answer)")
                continue
            }
            if ctx.overBudget {
                log(&ctx, "[probe] https: skipped remaining (time budget)")
                break
            }
            switch httpsGet(host: domain, interface: iface, timeout: httpsTimeout) {
            case .success(let r):
                ok += 1
                log(
                    &ctx,
                    "[probe] https \(domain) via tunnel: ok \(r.http)"
                        + " tls=\(String(format: "%.2f", r.tlsTime))s cert=\"\(r.cert)\""
                )
            case .failure(let why):
                fail += 1
                log(&ctx, "[probe] https \(domain) via tunnel: fail \(why)")
            }
        }
        if fail > 0, ok == 0 {
            ctx.suspects.append("TLS via tunnel broken (handshake or first response failed)")
        }
        ctx.stageSummaries.append("https \(ok)/\(ok + fail) ok")
        ctx.failures += fail
    }

    private static func summarize(ctx: Context, answers: [String: [String]]) -> String {
        let stages = ctx.stageSummaries.joined(separator: ", ")
        if ctx.failures == 0, ctx.suspects.isEmpty {
            return "OK - all checks passed (\(stages))"
        }
        var parts = ["PROBLEMS FOUND (\(stages))"]
        parts.append(contentsOf: ctx.suspects.map { "suspect: \($0)" })
        return parts.joined(separator: "; ")
    }

    // MARK: - Interface discovery

    private static func discoverInterfaces(tunnelIPv4: String) -> Context? {
        guard let tunnel = interfaceIndex(forTunnelIPv4: tunnelIPv4) else { return nil }
        let path = pathSnapshot()
        let physical = path?.availableInterfaces.first {
            $0.type == .wifi || $0.type == .wiredEthernet
        } ?? path?.availableInterfaces.first { !$0.name.hasPrefix("utun") }
        let tunnelNW = path?.availableInterfaces.first { $0.name == tunnel.name }
        return Context(
            startedAt: Date(),
            tunnelName: tunnel.name,
            tunnelIndex: tunnel.index,
            tunnelNWInterface: tunnelNW,
            physicalName: physical?.name,
            physicalIndex: physical.flatMap { let i = if_nametoindex($0.name); return i == 0 ? nil : i },
            physicalNWInterface: physical
        )
    }

    /// Finds the utun interface that currently owns the assigned tunnel IPv4.
    private static func interfaceIndex(forTunnelIPv4 address: String) -> (name: String, index: UInt32)? {
        var iflist: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&iflist) == 0, let first = iflist else { return nil }
        defer { freeifaddrs(iflist) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cursor?.pointee {
            if let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) {
                let name = String(cString: ifa.ifa_name)
                if name.hasPrefix("utun"), ipv4String(addr) == address {
                    let index = if_nametoindex(name)
                    if index != 0 { return (name, index) }
                }
            }
            cursor = ifa.ifa_next
        }
        return nil
    }

    private static func ipv4String(_ addr: UnsafePointer<sockaddr>) -> String {
        addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
            var a = sin.pointee.sin_addr
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
            return String(cString: buf)
        }
    }

    private static func pathSnapshot() -> NWPath? {
        let monitor = NWPathMonitor()
        let sem = DispatchSemaphore(value: 0)
        let queue = DispatchQueue(label: "net.dighole.vault.probe.pathmon")
        var path: NWPath?
        monitor.pathUpdateHandler = { p in
            path = p
            monitor.pathUpdateHandler = nil
            sem.signal()
        }
        monitor.start(queue: queue)
        _ = sem.wait(timeout: .now() + 3)
        monitor.cancel()
        return path
    }

    // MARK: - DNS probe

    private static func dnsQuery(server: String, domain: String, ifIndex: UInt32) -> Result<[String], ProbeError> {
        let id = UInt16.random(in: 0...UInt16.max)
        guard let query = DNSPacket.buildQuery(domain: domain, id: id) else {
            return .failure(ProbeError("bad domain"))
        }
        let exchange = udpExchange(server: server, port: 53, payload: query, ifIndex: ifIndex, timeout: dnsTimeout)
        switch exchange {
        case .failure(let why):
            return .failure(why)
        case .success(let data):
            guard let answers = DNSPacket.parseAnswers(data, expectedID: id) else {
                return .failure(ProbeError("unparseable response"))
            }
            return .success(answers)
        }
    }

    private static func describe(_ result: Result<[String], ProbeError>) -> String {
        switch result {
        case .success(let ips): return ips.isEmpty ? "[] (no A records)" : "[\(ips.joined(separator: ", "))]"
        case .failure(let why): return why.description
        }
    }

    private static func udpExchange(
        server: String, port: UInt16, payload: Data, ifIndex: UInt32, timeout: TimeInterval
    ) -> Result<Data, ProbeError> {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return .failure(ProbeError("socket: \(errnoString())")) }
        defer { close(fd) }
        guard bindToInterface(fd, index: ifIndex) else { return .failure(ProbeError("bind-if: \(errnoString())")) }
        guard setReceiveTimeout(fd, timeout: timeout) else { return .failure(ProbeError("rcvtimeo: \(errnoString())")) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, server, &addr.sin_addr) == 1 else { return .failure(ProbeError("bad server ip")) }

        let sent = payload.withUnsafeBytes { buf in
            withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, buf.baseAddress, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == payload.count else { return .failure(ProbeError("sendto: \(errnoString())")) }

        var buffer = [UInt8](repeating: 0, count: 4096)
        let n = recv(fd, &buffer, buffer.count, 0)
        guard n > 0 else {
            return .failure(ProbeError(errno == EAGAIN || errno == EWOULDBLOCK ? "timeout" : "recv: \(errnoString())"))
        }
        return .success(Data(buffer[0..<n]))
    }

    // MARK: - ICMP probe

    private static func icmpPing(
        host: String, ifIndex: UInt32, totalSize: Int, sequence: UInt16, timeout: TimeInterval
    ) -> Result<TimeInterval, ProbeError> {
        let isV6 = host.contains(":")
        // IPv6 headers are 40 bytes, IPv4 20.
        let payloadLen = totalSize - (isV6 ? 40 : 20) - 8
        guard payloadLen >= 0 else { return .failure(ProbeError("size too small")) }

        let fd = socket(isV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, isV6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP)
        guard fd >= 0 else { return .failure(ProbeError("socket: \(errnoString())")) }
        defer { close(fd) }
        // ifIndex 0 = unbound (follow the routing table). Tunnel-side ICMP
        // must stay unbound: an ICMP datagram socket bound with IP_BOUND_IF
        // never matches its replies on macOS.
        if ifIndex != 0 {
            guard bindToInterface(fd, index: ifIndex, family: isV6 ? AF_INET6 : AF_INET) else {
                return .failure(ProbeError("bind-if: \(errnoString())"))
            }
        }
        // DF: the point of the sweep is to see whether full-size packets survive.
        var one: Int32 = 1
        if !isV6 {
            setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &one, socklen_t(MemoryLayout<Int32>.size))
        }
        guard setReceiveTimeout(fd, timeout: timeout) else { return .failure(ProbeError("rcvtimeo: \(errnoString())")) }

        var message = [UInt8](repeating: 0, count: 8 + payloadLen)
        message[0] = isV6 ? 128 : 8 // echo request
        message[1] = 0
        // SOCK_DGRAM ping sockets: the kernel assigns the identifier (bytes
        // 4-5) per socket and demultiplexes replies by it — anything we
        // write there is overwritten. The sequence number (bytes 6-7) is
        // the only field that survives the round trip, so it carries the
        // matching marker.
        message[6] = UInt8(sequence >> 8)
        message[7] = UInt8(sequence & 0xff)
        for i in 8..<message.count { message[i] = UInt8((i - 8) % 251) }
        if !isV6 {
            // ICMPv4 needs a userland checksum; for ICMPv6 datagram sockets
            // the kernel computes it (it covers the pseudo-header).
            let checksum = icmpChecksum(message)
            message[2] = UInt8(checksum >> 8)
            message[3] = UInt8(checksum & 0xff)
        }

        var storage = sockaddr_storage()
        let addrLen: socklen_t
        if isV6 {
            addrLen = socklen_t(MemoryLayout<sockaddr_in6>.size)
            let rc = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in6()
                    sin.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    sin.pointee.sin6_family = sa_family_t(AF_INET6)
                    return inet_pton(AF_INET6, host, &sin.pointee.sin6_addr)
                }
            }
            guard rc == 1 else { return .failure(ProbeError("bad host ip")) }
        } else {
            addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let rc = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in()
                    sin.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    sin.pointee.sin_family = sa_family_t(AF_INET)
                    return inet_pton(AF_INET, host, &sin.pointee.sin_addr)
                }
            }
            guard rc == 1 else { return .failure(ProbeError("bad host ip")) }
        }

        let start = Date()
        let sent = message.withUnsafeBytes { buf in
            withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, buf.baseAddress, buf.count, 0, sa, addrLen)
                }
            }
        }
        guard sent == message.count else { return .failure(ProbeError("sendto: \(errnoString())")) }

        let replyType: UInt8 = isV6 ? 129 : 0
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = recv(fd, &buffer, buffer.count, 0)
            guard n > 0 else {
                return .failure(ProbeError(errno == EAGAIN || errno == EWOULDBLOCK ? "timeout" : "recv: \(errnoString())"))
            }
            if n >= 8, buffer[0] == replyType,
                buffer[6] == UInt8(sequence >> 8), buffer[7] == UInt8(sequence & 0xff)
            {
                return .success(Date().timeIntervalSince(start))
            }
            if Date().timeIntervalSince(start) > timeout { return .failure(ProbeError("timeout")) }
        }
    }

    static func icmpChecksum(_ data: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < data.count {
            sum &+= UInt32(data[i]) << 8 | UInt32(data[i + 1])
            i += 2
        }
        if i < data.count { sum &+= UInt32(data[i]) << 8 }
        while (sum >> 16) != 0 { sum = (sum & 0xffff) &+ (sum >> 16) }
        return ~UInt16(truncatingIfNeeded: sum)
    }

    // MARK: - TCP probe

    private static func tcpConnect(ip: String, port: UInt16, ifIndex: UInt32, timeout: TimeInterval) -> Result<TimeInterval, ProbeError> {
        var storage = sockaddr_storage()
        let addrLen: socklen_t
        let family: Int32
        if ip.contains(":") {
            family = AF_INET6
            addrLen = socklen_t(MemoryLayout<sockaddr_in6>.size)
            let rc = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in6()
                    sin.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    sin.pointee.sin6_family = sa_family_t(AF_INET6)
                    sin.pointee.sin6_port = port.bigEndian
                    return inet_pton(AF_INET6, ip, &sin.pointee.sin6_addr)
                }
            }
            guard rc == 1 else { return .failure(ProbeError("bad ip")) }
        } else {
            family = AF_INET
            addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let rc = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in()
                    sin.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    sin.pointee.sin_family = sa_family_t(AF_INET)
                    sin.pointee.sin_port = port.bigEndian
                    return inet_pton(AF_INET, ip, &sin.pointee.sin_addr)
                }
            }
            guard rc == 1 else { return .failure(ProbeError("bad ip")) }
        }

        let fd = socket(family, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return .failure(ProbeError("socket: \(errnoString())")) }
        defer { close(fd) }
        guard bindToInterface(fd, index: ifIndex, family: family) else {
            return .failure(ProbeError("bind-if: \(errnoString())"))
        }

        let flags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let start = Date()
        let rc = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(fd, sa, addrLen)
            }
        }
        if rc == 0 { return .success(Date().timeIntervalSince(start)) }
        guard errno == EINPROGRESS else { return .failure(ProbeError("connect: \(errnoString())")) }

        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let prc = poll(&pfd, 1, Int32(timeout * 1000))
        guard prc > 0 else { return .failure(ProbeError(prc == 0 ? "timeout" : "poll: \(errnoString())")) }

        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len)
        guard soError == 0 else { return .failure(ProbeError("connect: \(String(cString: strerror(soError)))")) }
        return .success(Date().timeIntervalSince(start))
    }

    // MARK: - HTTPS probe

    private static func httpsGet(
        host: String, interface: NWInterface, timeout: TimeInterval
    ) -> Result<(http: String, tlsTime: TimeInterval, cert: String), ProbeError> {
        let tls = NWProtocolTLS.Options()
        let params = NWParameters(tls: tls)
        params.requiredInterface = interface
        let connection = NWConnection(host: NWEndpoint.Host(host), port: 443, using: params)

        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var outcome: Result<(http: String, tlsTime: TimeInterval, cert: String), ProbeError>?

        func finish(_ result: Result<(http: String, tlsTime: TimeInterval, cert: String), ProbeError>) {
            lock.lock()
            let fresh = outcome == nil
            if fresh { outcome = result }
            lock.unlock()
            if fresh { semaphore.signal() }
        }

        let start = Date()
        var tlsTime: TimeInterval = 0
        var cert = ""

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                tlsTime = Date().timeIntervalSince(start)
                cert = peerCertSummary(connection) ?? ""
                let request = "GET / HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
                connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
                    if let error {
                        finish(.failure(ProbeError("send: \(error.localizedDescription)")))
                        return
                    }
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, _, error in
                        if let data, !data.isEmpty {
                            let text = String(decoding: data, as: UTF8.self)
                            let line = text.components(separatedBy: "\r\n").first ?? text
                            finish(.success((http: line, tlsTime: tlsTime, cert: cert)))
                        } else {
                            finish(.failure(ProbeError("recv: \(error?.localizedDescription ?? "no data")")))
                        }
                    }
                })
            case .failed(let error):
                finish(.failure(ProbeError("connection: \(error.localizedDescription)")))
            case .waiting(let error):
                if Date().timeIntervalSince(start) > timeout {
                    finish(.failure(ProbeError("waiting: \(error.localizedDescription)")))
                }
            default:
                break
            }
        }
        connection.start(queue: DispatchQueue(label: "net.dighole.vault.probe.https"))

        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            finish(.failure(ProbeError("timeout")))
        }
        _ = semaphore.wait(timeout: .now() + timeout + 1)
        connection.cancel()
        lock.lock()
        defer { lock.unlock() }
        return outcome ?? .failure(ProbeError("timeout"))
    }

    private static func peerCertSummary(_ connection: NWConnection) -> String? {
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata
        else { return nil }
        let secMetadata = metadata.securityProtocolMetadata
        var subject: String?
        sec_protocol_metadata_access_peer_certificate_chain(secMetadata) { certificate in
            if subject == nil {
                subject = SecCertificateCopySubjectSummary(sec_certificate_copy_ref(certificate).takeRetainedValue()) as String?
            }
        }
        return subject
    }

    // MARK: - Socket helpers

    private static func bindToInterface(_ fd: Int32, index: UInt32, family: Int32 = AF_INET) -> Bool {
        var value = index
        if family == AF_INET6 {
            return setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &value, socklen_t(MemoryLayout<UInt32>.size)) == 0
        }
        return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &value, socklen_t(MemoryLayout<UInt32>.size)) == 0
    }

    private static func setReceiveTimeout(_ fd: Int32, timeout: TimeInterval) -> Bool {
        var tv = timeval(
            tv_sec: Int(timeout),
            tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000)
        )
        return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size)) == 0
    }

    private static func errnoString() -> String {
        String(cString: strerror(errno))
    }

    private static func log(_ line: String) {
        Logger.network.noticeAndFile(line)
    }

    private static func log(_ ctx: inout Context, _ line: String) {
        ctx.lines.append(line)
        log(line)
    }
}

// MARK: - DNS packet codec (kept pure for unit tests)

/// Probe failure reason. ExpressibleByStringLiteral so the probe code can
/// keep writing `.failure(ProbeError("..."))`.
struct ProbeError: Error, CustomStringConvertible, ExpressibleByStringLiteral {
    let description: String
    init(_ description: String) { self.description = description }
    init(stringLiteral value: String) { self.description = value }
}

/// Minimal DNS wire codec: builds a single-question A query and extracts the
/// A records from a response, following compression pointers when skipping
/// names. Unknown record types are skipped via their rdlength.
struct DNSPacket {

    static func buildQuery(domain: String, id: UInt16) -> Data? {
        var data = Data()
        data.append(contentsOf: [UInt8(id >> 8), UInt8(id & 0xff)])
        data.append(contentsOf: [0x01, 0x00]) // RD
        data.append(contentsOf: [0x00, 0x01]) // QDCOUNT
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let labels = domain.split(separator: ".", omittingEmptySubsequences: true)
        guard !labels.isEmpty else { return nil }
        var nameLength = 1
        for label in labels {
            guard label.count <= 63, label.allSatisfy({ $0.isASCII }) else { return nil }
            nameLength += label.count + 1
            guard nameLength <= 255 else { return nil }
            data.append(UInt8(label.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(0)
        data.append(contentsOf: [0x00, 0x01]) // QTYPE A
        data.append(contentsOf: [0x00, 0x01]) // QCLASS IN
        return data
    }

    /// Returns the A records in the response; an empty array when the answer
    /// is valid but holds no A records (e.g. CNAME-only chains we did not
    /// follow); nil when the packet is malformed or carries an error rcode.
    static func parseAnswers(_ data: Data, expectedID: UInt16) -> [String]? {
        guard data.count >= 12 else { return nil }
        func u16(_ offset: Int) -> UInt16 {
            UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        }
        guard u16(0) == expectedID else { return nil }
        let flags = u16(2)
        guard flags & 0x8000 != 0 else { return nil } // QR
        guard flags & 0x000f == 0 else { return nil } // rcode NOERROR only
        let qdcount = Int(u16(4))
        let ancount = Int(u16(6))

        var offset = 12
        for _ in 0..<qdcount {
            guard let next = skipName(data, offset) else { return nil }
            offset = next + 4 // qtype + qclass
            guard offset <= data.count else { return nil }
        }

        var answers: [String] = []
        for _ in 0..<ancount {
            guard let nameEnd = skipName(data, offset) else { return nil }
            guard nameEnd + 10 <= data.count else { return nil }
            let type = u16(nameEnd)
            let rdlength = Int(u16(nameEnd + 8))
            let rdata = nameEnd + 10
            guard rdata + rdlength <= data.count else { return nil }
            if type == 1, rdlength == 4 {
                answers.append("\(data[rdata]).\(data[rdata + 1]).\(data[rdata + 2]).\(data[rdata + 3])")
            }
            offset = rdata + rdlength
        }
        return answers
    }

    /// Skips a (possibly compressed) domain name; returns the offset just
    /// past it. Compression pointers terminate the name at their own offset.
    private static func skipName(_ data: Data, _ start: Int) -> Int? {
        var offset = start
        while true {
            guard offset < data.count else { return nil }
            let length = Int(data[offset])
            if length == 0 { return offset + 1 }
            if length & 0xc0 == 0xc0 {
                guard offset + 1 < data.count else { return nil }
                return offset + 2
            }
            guard length & 0xc0 == 0 else { return nil }
            offset += length + 1
        }
    }
}
