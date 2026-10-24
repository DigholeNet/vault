//
//  TunnelDiagnostics.swift
//  VaultCore
//
//
//  Provider DNS/TCP/HTTPS probes bind to the tunnel interface. Separate
//  app-process HTTPS checks use the system resolver and default routing.
//  Optional unbound ICMP samples are observations, not path/loss verdicts.
//  All steps are recorded in the shared file log with a [probe] prefix.
//
//  The suite is synchronous and meant to run on a background queue; each
//  probe has its own timeout and the whole suite gives up past a total
//  budget so a wedged path cannot stall the caller forever.
//

import Foundation
import Network
import Security
import os.log

public final class DiagnosticsCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    public init() {}
    public func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }
    public var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

public struct DiagnosticsCheck: Codable, Sendable, Identifiable {
    public enum State: String, Codable, Sendable { case passed, failed, incomplete }
    public var id: String
    public var passed: Int
    public var attempted: Int
    public var state: State
    /// Mean duration of the sampled requests, in milliseconds.
    public var durationMs: Int
    public var sampleCount: Int?

    public init(id: String, passed: Int, attempted: Int, state: State, durationMs: Int, sampleCount: Int? = nil) {
        self.id = id
        self.passed = passed
        self.attempted = attempted
        self.state = state
        self.durationMs = durationMs
        self.sampleCount = sampleCount
    }

    public static func ping(id: String, probes: [DiagnosticsProbe]) -> DiagnosticsCheck {
        let samples = probes.filter { $0.stage == id }
        let replies = samples.filter(\.succeeded)
        let average = replies.isEmpty ? 0 : Int((replies.reduce(0.0) { $0 + Double($1.durationMs) } / Double(replies.count)).rounded())
        return DiagnosticsCheck(id: id, passed: replies.count, attempted: samples.count,
            state: samples.count == 2 && replies.count == 2 ? .passed : .incomplete,
            durationMs: average, sampleCount: replies.count)
    }

    public static func measured(id: String, passed: Int, attempted: Int, state: State, probes: [DiagnosticsProbe]) -> DiagnosticsCheck {
        let samples = probes.filter { $0.stage == id }
        let average = samples.isEmpty ? 0 : Int((samples.reduce(0.0) { $0 + Double($1.durationMs) } / Double(samples.count)).rounded())
        return DiagnosticsCheck(id: id, passed: passed, attempted: attempted, state: state,
            durationMs: average, sampleCount: samples.count)
    }
}

public struct DiagnosticsProbe: Codable, Sendable, Identifiable {
    public var id: String
    public var stage: String
    public var domain: String
    public var durationMs: Int
    public var succeeded: Bool
    public var detail: String
    public var tlsDurationMs: Int?

    public init(stage: String, domain: String, durationMs: Int, succeeded: Bool, detail: String, tlsDurationMs: Int? = nil) {
        self.id = UUID().uuidString
        self.stage = stage
        self.domain = domain
        self.durationMs = durationMs
        self.succeeded = succeeded
        self.detail = detail
        self.tlsDurationMs = tlsDurationMs
    }
}

public struct DiagnosticsResult: Codable, Sendable {
    public var summary: String
    public var lines: [String]
    public var domains: [String]?
    public var checks: [DiagnosticsCheck]?
    public var durationMs: Int?
    public var activeCheck: String?
    public var probes: [DiagnosticsProbe]?

    public init(summary: String, lines: [String], domains: [String]? = nil, checks: [DiagnosticsCheck]? = nil, durationMs: Int? = nil, activeCheck: String? = nil, probes: [DiagnosticsProbe]? = nil) {
        self.summary = summary
        self.lines = lines
        self.domains = domains
        self.checks = checks
        self.durationMs = durationMs
        self.activeCheck = activeCheck
        self.probes = probes
    }
    public mutating func appendApplicationResult(_ result: DiagnosticsResult) {
        lines.append(contentsOf: result.lines)
        checks = (checks ?? []) + (result.checks ?? [])
        probes = (probes ?? []) + (result.probes ?? [])
        if let elapsed = result.durationMs { durationMs = (durationMs ?? 0) + elapsed }
        if summary.hasPrefix("OK"), !result.summary.hasPrefix("OK") {
            summary = result.summary
        } else {
            summary += "; " + result.summary
        }
    }

}

public enum TunnelDiagnostics {

    /// Default HTTPS targets; availability depends on the user's network.
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

    struct Context {
        let startedAt: TimeInterval
        let cancellation: DiagnosticsCancellation
        let tunnelName: String
        let tunnelIndex: UInt32
        let tunnelNWInterface: NWInterface?
        var mtuSizes: [Int] = mtuSweepSizes(tunnelMtu: nil)
        var lines: [String] = []
        var checks: [DiagnosticsCheck] = []
        var probes: [DiagnosticsProbe] = []
        var suspects: [String] = []
        var stageSummaries: [String] = []
        var failures = 0
        var remaining: TimeInterval {
            let now = ProcessInfo.processInfo.systemUptime
            return max(0, min(startedAt + totalBudget, phaseDeadline ?? (startedAt + totalBudget)) - now)
        }
        var overBudget: Bool { remaining <= 0 || cancellation.isCancelled }
        var phaseDeadline: TimeInterval?
        var incomplete = false
        var httpsCompleted = 0
        func timeout(_ limit: TimeInterval) -> TimeInterval { max(0.001, min(limit, remaining)) }
    }

    /// Runs the full probe suite. `tunnelIPv4` is the address the supernode
    /// assigned to the utun interface (used to locate the interface).
    public static func run(
        dnsServers: [String], tunnelIPv4: String, tunnelIPv4Mask: String?, domains: [String],
        tunnelMtu: Int? = nil, tunnelIPv6: String? = nil,
        cancellation: DiagnosticsCancellation = DiagnosticsCancellation(),
        onProgress: ((DiagnosticsResult) -> Void)? = nil
    ) -> DiagnosticsResult {
        let start = ProcessInfo.processInfo.systemUptime
        let header = "[probe] ==== diagnostics start ===="
        log(header)

        guard var ctx = discoverInterfaces(tunnelIPv4: tunnelIPv4, cancellation: cancellation, startedAt: start) else {
            let line = "[probe] abort: tunnel interface carrying \(tunnelIPv4) not found"
            log(line)
            return DiagnosticsResult(summary: "tunnel interface not found", lines: [header, line])
        }
        ctx.mtuSizes = mtuSweepSizes(tunnelMtu: tunnelMtu)
        ctx.lines.append(header)
        log(
            &ctx,
            "[probe] interfaces: tunnel=\(ctx.tunnelName)(idx \(ctx.tunnelIndex))"
        )

        let resolver = dnsServers.first ?? "1.1.1.1"
        var seen = Set<String>()
        let targets = (domains.isEmpty ? defaultProbeDomains : domains).filter {
            seen.insert($0).inserted
        }
        log(&ctx, "[probe] targets: \(targets.joined(separator: ", ")); resolver \(resolver)")

        let gateway = tunnelIPv4Mask.flatMap { gatewayAddress(ip: tunnelIPv4, mask: $0) }
        // Reserve a separate window for each family so broken IPv4 cannot
        // consume the IPv6 budget. Optional MTU observations run afterwards.
        ctx.phaseDeadline = start + 25
        let answers = dnsSweep(
            &ctx, resolvers: dnsServers.isEmpty ? [resolver] : dnsServers, domains: targets)
        onProgress?(progress(ctx, domains: targets, active: "tcp"))
        let tcpTargets = tcpSweep(&ctx, domains: targets, answers: answers)
        onProgress?(progress(ctx, domains: targets, active: "https"))
        httpsSweep(&ctx, domains: targets, targets: tcpTargets)
        if ctx.httpsCompleted != tcpTargets.count { ctx.incomplete = true }

        ctx.phaseDeadline = start + 50
        onProgress?(progress(ctx, domains: targets, active: "dns6"))
        if let tunnelIPv6, !tunnelIPv6.isEmpty {
            log(&ctx, "[probe] IPv6 tunnel address: \(tunnelIPv6)")
            let answers6 = dnsSweep(&ctx, resolvers: dnsServers.isEmpty ? [resolver] : dnsServers,
                domains: targets, type: .aaaa)
            onProgress?(progress(ctx, domains: targets, active: "tcp6"))
            let tcpTargets6 = tcpSweep(&ctx, domains: targets, answers: answers6, stage: "tcp6")
            onProgress?(progress(ctx, domains: targets, active: "https6"))
            httpsSweep(&ctx, domains: targets, targets: tcpTargets6, stage: "https6")
        } else {
            ctx.incomplete = true
            log(&ctx, "[probe] IPv6 checks not measured: no server-assigned IPv6 address")
            for id in ["dns6", "tcp6", "https6"] {
                ctx.checks.append(DiagnosticsCheck.measured(id: id, passed: 0, attempted: 0,
                    state: .incomplete, probes: ctx.probes))
            }
        }
        ctx.phaseDeadline = nil
        onProgress?(progress(ctx, domains: targets, active: "icmp"))
        // Optional observations must not invalidate completed required checks.
        var summary = summarize(ctx: ctx)
        if !ctx.overBudget { icmpSweep(&ctx, gateway: gateway) }
        if cancellation.isCancelled { summary = "INCOMPLETE - tunnel session changed" }
        log(&ctx, "[probe] summary: \(summary)")
        let footer =
            "[probe] ==== diagnostics done in \(String(format: "%.1f", (ProcessInfo.processInfo.systemUptime - start)))s ===="
        log(footer)
        return DiagnosticsResult(summary: summary, lines: ctx.lines + [footer], domains: targets, checks: ctx.checks, durationMs: elapsedMs(since: start), probes: ctx.probes)
    }

    private static func progress(_ ctx: Context, domains: [String], active: String) -> DiagnosticsResult {
        DiagnosticsResult(summary: "RUNNING", lines: ctx.lines, domains: domains, checks: ctx.checks,
            durationMs: elapsedMs(since: ctx.startedAt), activeCheck: active, probes: ctx.probes)
    }

    private static func elapsedMs(since start: TimeInterval) -> Int {
        max(0, Int(((ProcessInfo.processInfo.systemUptime - start) * 1000).rounded()))
    }

    /// Call from the app process on a background queue. Unbound connections
    /// exercise the system resolver and the route actually used by apps.
    /// This is separate from the provider's fixed-IP IPv4 checks.
    public static func runApplicationChecks(domains: [String], cancellation: DiagnosticsCancellation = DiagnosticsCancellation(),
        onProgress: ((DiagnosticsResult) -> Void)? = nil) -> DiagnosticsResult {
        let start = ProcessInfo.processInfo.systemUptime
        var lines: [String] = []
        var probes: [DiagnosticsProbe] = []
        var failures = 0
        var attempted = 0
        for domain in domains {
            let remaining = 16 - (ProcessInfo.processInfo.systemUptime - start)
            if remaining <= 0 || cancellation.isCancelled { break }
            attempted += 1
            let probeStart = ProcessInfo.processInfo.systemUptime
            let result: Result<(http: String, tlsTime: TimeInterval, cert: String), ProbeError> =
                DNSPacket.buildQuery(domain: domain, id: 0) == nil
                ? .failure(ProbeError("invalid probe domain"))
                : httpsGet(host: domain, timeout: min(httpsTimeout, remaining))
            let line: String
            switch result {
            case .success(let response):
                probes.append(DiagnosticsProbe(
                    stage: "application", domain: domain, durationMs: elapsedMs(since: probeStart),
                    succeeded: true, detail: response.http,
                    tlsDurationMs: Int((response.tlsTime * 1000).rounded())))
                line = "[probe] app system-DNS/default-route HTTPS \(domain): \(response.http)"
            case .failure(let error):
                failures += 1
                probes.append(DiagnosticsProbe(stage: "application", domain: domain, durationMs: elapsedMs(since: probeStart), succeeded: false, detail: error.description))
                line = "[probe] app system-DNS/default-route HTTPS \(domain): failed \(error)"
            }
            let timedLine = line + " duration=\(elapsedMs(since: probeStart))ms"
            lines.append(timedLine)
            log(timedLine)
        }
        let summary: String
        if cancellation.isCancelled {
            summary = "INCOMPLETE - tunnel session changed"
        } else if attempted != domains.count || domains.isEmpty {
            summary = "INCOMPLETE - app HTTPS checks \(attempted - failures)/\(attempted) passed"
        } else if failures > 0 {
            summary =
                "PROBLEMS FOUND - app HTTPS checks \(attempted - failures)/\(attempted) passed; see per-domain results"
        } else {
            summary = "OK - app system-DNS/default-route HTTPS \(attempted)/\(attempted) passed"
        }
        let state: DiagnosticsCheck.State = cancellation.isCancelled || attempted != domains.count || domains.isEmpty
            ? .incomplete : (failures > 0 ? .failed : .passed)
        var checks = [DiagnosticsCheck.measured(id: "application", passed: attempted - failures,
            attempted: attempted, state: state, probes: probes)]
        // Ping runs in the app process so unbound ICMP follows application
        // routes, rather than the provider's default tunnel bypass.
        for (stage, host) in [("ping", "1.1.1.1"), ("ping6", "2606:4700:4700::1111")] {
            onProgress?(DiagnosticsResult(summary: "RUNNING", lines: lines, checks: checks,
                durationMs: elapsedMs(since: start), activeCheck: stage, probes: probes))
            for sequence in 0..<2 {
                let remaining = 24 - (ProcessInfo.processInfo.systemUptime - start)
                guard remaining > 0, !cancellation.isCancelled else { break }
                let probeStart = ProcessInfo.processInfo.systemUptime
                let outcome = icmpPing(host: host, ifIndex: 0, totalSize: 64,
                    sequence: UInt16(sequence), timeout: min(icmpTimeout, remaining))
                let detail: String
                let succeeded: Bool
                switch outcome {
                case .success(let rtt):
                    succeeded = true
                    detail = "\(host) seq=\(sequence) reply rtt=\(Int((rtt * 1000).rounded()))ms"
                case .failure(let error):
                    succeeded = false
                    detail = "\(host) seq=\(sequence) no reply: \(error)"
                }
                let line = "[probe] app \(stage) default-route: \(detail)"
                lines.append(line)
                log(line)
                probes.append(DiagnosticsProbe(stage: stage, domain: host, durationMs: elapsedMs(since: probeStart),
                    succeeded: succeeded, detail: detail))
            }
            checks.append(DiagnosticsCheck.ping(id: stage, probes: probes))
        }
        let note = "[probe] Ping is informational: ICMP may be filtered; no reply alone does not establish a VPN failure."
        lines.append(note)
        log(note)
        return DiagnosticsResult(summary: cancellation.isCancelled ? "INCOMPLETE - tunnel session changed" : summary,
            lines: lines, checks: checks, durationMs: elapsedMs(since: start), probes: probes)
    }

    // MARK: - Suite steps

    /// Optional unbound ICMP observations. They cannot establish tunnel path
    /// selection or transport loss, so they never change the verdict.
    private static func icmpSweep(_ ctx: inout Context, gateway: String?) {
        guard let gateway, !ctx.overBudget else { return }
        let results = pingSizes(&ctx, host: gateway, ifIndex: 0)
        log(
            &ctx,
            "[probe] icmp gateway \(gateway), unbound/path unverified: \(detail(of: results, sizes: ctx.mtuSizes))"
        )
        log(
            &ctx,
            "[probe] note: ICMP is informational; no reply does not establish packet loss or an MTU fault. Physical UDP transport quality is not measured."
        )
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
                if ctx.overBudget { break }
                switch icmpPing(
                    host: host, ifIndex: ifIndex,
                    totalSize: size, sequence: UInt16(seq), timeout: ctx.timeout(icmpTimeout)
                ) {
                case .success(let rtt):
                    ok += 1
                    rtts.append(Int(rtt * 1000))
                case .failure(let error):
                    results[size] = "unavailable: \(error)"
                }
            }
            if ok == 0 {
                if size == ctx.mtuSizes.first {
                    log(&ctx, "[probe] icmp: baseline unavailable; skipping larger packets")
                    break
                }
                continue
            }
            results[size] = "ok rtt=\(rtts.first ?? 0)ms (\(ok)/2)"
        }
        return results
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

    /// Resolves through the tunnel, falling back across configured resolvers.
    /// Answer equality is never evidence of leakage or poisoning.
    private static func dnsSweep(_ ctx: inout Context, resolvers: [String], domains: [String], type: DNSPacket.RecordType = .a)
        -> [String: [String]]
    {
        let stage = type == .aaaa ? "dns6" : "dns"
        var answers: [String: [String]] = [:]
        var attempted = 0
        for domain in domains {
            if ctx.overBudget {
                ctx.incomplete = true
                break
            }
            attempted += 1
            for resolver in resolvers {
                if ctx.overBudget {
                    ctx.incomplete = true
                    break
                }
                let probeStart = ProcessInfo.processInfo.systemUptime
                let result = dnsQuery(
                    server: resolver, domain: domain, ifIndex: ctx.tunnelIndex,
                    timeout: ctx.timeout(dnsTimeout), type: type)
                log(&ctx, "[probe] \(stage) \(domain) server=\(resolver): \(describe(result, type: type)) duration=\(elapsedMs(since: probeStart))ms")
                let succeeded: Bool
                if case .success(let ips) = result { succeeded = type == .aaaa || !ips.isEmpty } else { succeeded = false }
                ctx.probes.append(DiagnosticsProbe(stage: stage, domain: domain, durationMs: elapsedMs(since: probeStart), succeeded: succeeded, detail: "\(resolver): \(describe(result, type: type))"))
                if case .success(let ips) = result, type == .aaaa || !ips.isEmpty {
                    answers[domain] = ips
                    break
                }
            }
            if answers[domain] == nil, !ctx.overBudget {
                ctx.failures += 1
                ctx.suspects.append("DNS \(type == .aaaa ? "AAAA" : "A") lookup failed for \(domain); see resolver results")
            }
        }
        ctx.checks.append(DiagnosticsCheck.measured(id: stage, passed: answers.count, attempted: attempted,
            state: attempted != domains.count || ctx.overBudget ? .incomplete : (answers.count == attempted ? .passed : .failed),
            probes: ctx.probes))
        ctx.stageSummaries.append("\(stage) \(answers.count)/\(attempted) resolved")
        return answers
    }

    /// TCP connect to port 443 of tunnel-resolved addresses for one family.
    private static func tcpSweep(_ ctx: inout Context, domains: [String], answers: [String: [String]], stage: String = "tcp")
        -> [String: String]
    {
        var selected: [String: String] = [:]
        var failedDomains = 0
        for domain in domains {
            guard let ips = answers[domain], !ips.isEmpty else {
                log(&ctx, "[probe] \(stage) \(domain): skipped (no tunnel DNS answer)")
                continue
            }
            for ip in ips.prefix(2) {
                if ctx.overBudget {
                    ctx.incomplete = true
                    break
                }
                let probeStart = ProcessInfo.processInfo.systemUptime
                switch tcpConnect(
                    ip: ip, port: 443, ifIndex: ctx.tunnelIndex, timeout: ctx.timeout(tcpTimeout))
                {
                case .success(let t):
                    selected[domain] = ip
                    ctx.probes.append(DiagnosticsProbe(stage: stage, domain: domain, durationMs: Int((t * 1000).rounded()), succeeded: true, detail: "\(ip):443"))
                    log(&ctx, "[probe] \(stage) \(domain)(\(ip):443) via tunnel: ok \(Int(t * 1000))ms")
                case .failure(let why):
                    ctx.probes.append(DiagnosticsProbe(stage: stage, domain: domain, durationMs: elapsedMs(since: probeStart), succeeded: false, detail: "\(ip):443 · \(why)"))
                    log(&ctx, "[probe] \(stage) \(domain)(\(ip):443) via tunnel: fail \(why) duration=\(elapsedMs(since: probeStart))ms")
                }
                if selected[domain] != nil { break }
            }
            if selected[domain] == nil, !ctx.overBudget {
                failedDomains += 1
                ctx.suspects.append("TCP candidates failed for \(domain)")
            }
        }
        ctx.checks.append(DiagnosticsCheck.measured(id: stage, passed: selected.count, attempted: selected.count + failedDomains,
            state: ctx.overBudget || selected.count + failedDomains == 0 ? .incomplete : (failedDomains > 0 ? .failed : .passed),
            probes: ctx.probes))
        ctx.stageSummaries.append("\(stage) \(selected.count)/\(selected.count + failedDomains) domains ok")
        ctx.failures += failedDomains
        return selected
    }

    /// Full TLS handshake + HTTP/1.1 request through the tunnel: this is the
    /// exact exchange that fails when "the page does not load". The peer
    /// certificate subject is logged to expose interception.
    private static func httpsSweep(_ ctx: inout Context, domains: [String], targets: [String: String], stage: String = "https")
    {
        guard let iface = ctx.tunnelNWInterface else {
            ctx.checks.append(DiagnosticsCheck.measured(id: stage, passed: 0, attempted: 0, state: .incomplete, probes: ctx.probes))
            log(&ctx, "[probe] \(stage): skipped (no tunnel NWInterface)")
            ctx.incomplete = true
            return
        }
        var ok = 0
        var fail = 0
        for domain in domains {
            guard let ip = targets[domain] else {
                log(&ctx, "[probe] \(stage) \(domain): skipped (no successful TCP target)")
                continue
            }
            if ctx.overBudget {
                log(&ctx, "[probe] \(stage): skipped remaining (time budget)")
                break
            }
            ctx.httpsCompleted += 1
            let probeStart = ProcessInfo.processInfo.systemUptime
            switch httpsGet(host: domain, ip: ip, interface: iface, timeout: ctx.timeout(httpsTimeout)) {
            case .success(let r):
                ok += 1
                ctx.probes.append(DiagnosticsProbe(
                    stage: stage, domain: domain, durationMs: elapsedMs(since: probeStart),
                    succeeded: true, detail: "\(r.http) · \(r.cert)",
                    tlsDurationMs: Int((r.tlsTime * 1000).rounded())))
                log(
                    &ctx,
                    "[probe] \(stage) \(domain)(\(ip):443) via tunnel: ok \(r.http)"
                        + " duration=\(elapsedMs(since: probeStart))ms tls=\(Int((r.tlsTime * 1000).rounded()))ms cert=\"\(r.cert)\""
                )
            case .failure(let why):
                fail += 1
                ctx.probes.append(DiagnosticsProbe(stage: stage, domain: domain, durationMs: elapsedMs(since: probeStart), succeeded: false, detail: why.description))
                log(&ctx, "[probe] \(stage) \(domain) via tunnel: fail \(why) duration=\(elapsedMs(since: probeStart))ms")
            }
        }
        if fail > 0, ok == 0 {
            ctx.suspects.append("HTTPS sample failed on tested tunnel targets; see per-domain errors")
        }
        ctx.checks.append(DiagnosticsCheck.measured(id: stage, passed: ok, attempted: ok + fail,
            state: ctx.overBudget || targets.isEmpty || ok + fail != targets.count ? .incomplete : (fail > 0 ? .failed : .passed),
            probes: ctx.probes))
        if targets.isEmpty || ok + fail != targets.count { ctx.incomplete = true }
        ctx.stageSummaries.append("\(stage) \(ok)/\(ok + fail) ok")
        ctx.failures += fail
    }

    static func summarize(ctx: Context) -> String {
        let stages = ctx.stageSummaries.joined(separator: ", ")
        if ctx.cancellation.isCancelled { return "INCOMPLETE - tunnel session changed (\(stages))" }
        if ctx.incomplete || ctx.overBudget {
            let prefix = ctx.failures > 0 ? "PROBLEMS FOUND; INCOMPLETE" : "INCOMPLETE"
            return "\(prefix) - some checks were not completed (\(stages)); "
                + ctx.suspects.joined(separator: "; ")
        }
        if ctx.failures == 0, ctx.suspects.isEmpty {
            return "OK - required IPv4/IPv6 checks passed (\(stages))"
        }
        var parts = ["PROBLEMS FOUND (\(stages))"]
        parts.append(contentsOf: ctx.suspects.map { "suspect: \($0)" })
        return parts.joined(separator: "; ")
    }

}

extension TunnelDiagnostics {
    // MARK: - Interface discovery

    private static func discoverInterfaces(tunnelIPv4: String, cancellation: DiagnosticsCancellation, startedAt: TimeInterval)
        -> Context?
    {
        guard let tunnel = interfaceIndex(forTunnelIPv4: tunnelIPv4) else { return nil }
        let path = pathSnapshot()
        let tunnelNW = path?.availableInterfaces.first { $0.name == tunnel.name }
        return Context(
            startedAt: startedAt,
            cancellation: cancellation,
            tunnelName: tunnel.name,
            tunnelIndex: tunnel.index,
            tunnelNWInterface: tunnelNW
        )
    }

    /// Finds the utun interface that currently owns the assigned tunnel IPv4.
    private static func interfaceIndex(forTunnelIPv4 address: String) -> (
        name: String, index: UInt32
    )? {
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
        return queue.sync {
            monitor.pathUpdateHandler = nil
            return path
        }
    }

    // MARK: - DNS probe

    private static func dnsQuery(
        server: String, domain: String, ifIndex: UInt32, timeout: TimeInterval, type: DNSPacket.RecordType = .a
    ) -> Result<[String], ProbeError> {
        let id = UInt16.random(in: 0...UInt16.max)
        guard let query = DNSPacket.buildQuery(domain: domain, id: id, type: type) else {
            return .failure(ProbeError("bad domain"))
        }
        let exchange = udpExchange(
            server: server, port: 53, payload: query, ifIndex: ifIndex, timeout: timeout)
        switch exchange {
        case .failure(let why):
            return .failure(why)
        case .success(let data):
            if data.count >= 4 {
                let code = data[3] & 0x0f
                if code != 0 { return .failure(ProbeError("DNS response rcode=\(code)")) }
                if data[2] & 0x02 != 0 {
                    return .failure(ProbeError("DNS response truncated; TCP fallback unavailable"))
                }
            }
            guard let answers = DNSPacket.parseAnswers(data, expectedID: id, type: type) else {
                return .failure(ProbeError("unparseable response"))
            }
            return .success(answers)
        }
    }

    private static func describe(_ result: Result<[String], ProbeError>, type: DNSPacket.RecordType = .a) -> String {
        switch result {
        case .success(let ips):
            return ips.isEmpty ? "[] (no \(type == .aaaa ? "AAAA" : "A") records)" : "[\(ips.joined(separator: ", "))]"
        case .failure(let why): return why.description
        }
    }

    private static func udpExchange(
        server: String, port: UInt16, payload: Data, ifIndex: UInt32, timeout: TimeInterval
    ) -> Result<Data, ProbeError> {
        let family = server.contains(":") ? AF_INET6 : AF_INET
        let fd = socket(family, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return .failure(ProbeError("socket: \(errnoString())")) }
        defer { close(fd) }
        guard bindToInterface(fd, index: ifIndex, family: family) else {
            return .failure(ProbeError("bind-if: \(errnoString())"))
        }
        guard setReceiveTimeout(fd, timeout: timeout) else {
            return .failure(ProbeError("rcvtimeo: \(errnoString())"))
        }
        var storage = sockaddr_storage()
        let length: socklen_t
        if family == AF_INET6 {
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            let valid = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) {
                    $0.pointee.sin6_len = UInt8(length)
                    $0.pointee.sin6_family = sa_family_t(family)
                    $0.pointee.sin6_port = port.bigEndian
                    return inet_pton(family, server, &$0.pointee.sin6_addr)
                }
            }
            guard valid == 1 else { return .failure(ProbeError("bad server ip")) }
        } else {
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let valid = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                    $0.pointee.sin_len = UInt8(length)
                    $0.pointee.sin_family = sa_family_t(family)
                    $0.pointee.sin_port = port.bigEndian
                    return inet_pton(family, server, &$0.pointee.sin_addr)
                }
            }
            guard valid == 1 else { return .failure(ProbeError("bad server ip")) }
        }
        let connected = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, length) }
        }
        guard connected == 0 else { return .failure(ProbeError("connect: \(errnoString())")) }
        let sent = payload.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
        guard sent == payload.count else { return .failure(ProbeError("send: \(errnoString())")) }

        var buffer = [UInt8](repeating: 0, count: 4096)
        let n = recv(fd, &buffer, buffer.count, 0)
        guard n > 0 else {
            return .failure(
                ProbeError(errno == EAGAIN || errno == EWOULDBLOCK ? "timeout" : "recv: \(errnoString())"))
        }
        return .success(Data(buffer[0..<n]))
    }

    // MARK: - ICMP probe

    static func icmpPing(
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
        guard setReceiveTimeout(fd, timeout: timeout) else {
            return .failure(ProbeError("rcvtimeo: \(errnoString())"))
        }

        var message = [UInt8](repeating: 0, count: 8 + payloadLen)
        message[0] = isV6 ? 128 : 8  // echo request
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

        let start = ProcessInfo.processInfo.systemUptime
        let sent = message.withUnsafeBytes { buf in
            withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(fd, buf.baseAddress, buf.count, 0, sa, addrLen)
                }
            }
        }
        guard sent == message.count else { return .failure(ProbeError("sendto: \(errnoString())")) }

        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let remaining = timeout - (ProcessInfo.processInfo.systemUptime - start)
            guard remaining > 0 else { return .failure(ProbeError("timeout")) }
            guard setReceiveTimeout(fd, timeout: remaining) else {
                return .failure(ProbeError("rcvtimeo: \(errnoString())"))
            }
            let n = recv(fd, &buffer, buffer.count, 0)
            guard n > 0 else {
                return .failure(
                    ProbeError(errno == EAGAIN || errno == EWOULDBLOCK ? "timeout" : "recv: \(errnoString())")
                )
            }
            if matchesEchoReply(buffer, length: n, isIPv6: isV6, sequence: sequence) {
                return .success((ProcessInfo.processInfo.systemUptime - start))
            }
            if (ProcessInfo.processInfo.systemUptime - start) > timeout { return .failure(ProbeError("timeout")) }
        }
    }

    static func matchesEchoReply(_ bytes: [UInt8], length: Int, isIPv6: Bool, sequence: UInt16) -> Bool {
        guard length <= bytes.count, length >= 8 else { return false }
        var offset = 0
        // Darwin may include an IP header on an ICMP datagram receive.
        if !isIPv6, bytes[0] >> 4 == 4 {
            offset = Int(bytes[0] & 0x0f) * 4
            guard offset >= 20 else { return false }
        } else if isIPv6, bytes[0] >> 4 == 6 { offset = 40 }
        guard length >= offset + 8 else { return false }
        return bytes[offset] == (isIPv6 ? 129 : 0) && bytes[offset + 1] == 0
            && bytes[offset + 6] == UInt8(sequence >> 8)
            && bytes[offset + 7] == UInt8(sequence & 0xff)
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

    private static func tcpConnect(ip: String, port: UInt16, ifIndex: UInt32, timeout: TimeInterval)
        -> Result<TimeInterval, ProbeError>
    {
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
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            return .failure(ProbeError("nonblocking: \(errnoString())"))
        }

        let start = ProcessInfo.processInfo.systemUptime
        let rc = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(fd, sa, addrLen)
            }
        }
        if rc == 0 { return .success((ProcessInfo.processInfo.systemUptime - start)) }
        guard errno == EINPROGRESS else { return .failure(ProbeError("connect: \(errnoString())")) }

        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let prc = poll(&pfd, 1, Int32(timeout * 1000))
        guard prc > 0 else {
            return .failure(ProbeError(prc == 0 ? "timeout" : "poll: \(errnoString())"))
        }

        var soError: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 else {
            return .failure(ProbeError("socket status: \(errnoString())"))
        }
        guard soError == 0 else {
            return .failure(ProbeError("connect: \(String(cString: strerror(soError)))"))
        }
        return .success((ProcessInfo.processInfo.systemUptime - start))
    }

    // MARK: - HTTPS probe

    private static func httpsGet(
        host: String, ip: String? = nil, interface: NWInterface? = nil, timeout: TimeInterval
    ) -> Result<(http: String, tlsTime: TimeInterval, cert: String), ProbeError> {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)
        sec_protocol_options_set_verify_block(
            tls.securityProtocolOptions,
            { _, trust, complete in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                let policy = SecPolicyCreateSSL(true, host as CFString)
                guard SecTrustSetPolicies(secTrust, policy) == errSecSuccess else {
                    complete(false)
                    return
                }
                complete(SecTrustEvaluateWithError(secTrust, nil))
            }, DispatchQueue(label: "net.dighole.vault.probe.trust"))
        let params = NWParameters(tls: tls)
        params.requiredInterface = interface
        let connection = NWConnection(host: NWEndpoint.Host(ip ?? host), port: 443, using: params)

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

        let start = ProcessInfo.processInfo.systemUptime
        var tlsTime: TimeInterval = 0
        var cert = ""
        var response = Data()
        func receiveMore() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: min(8192, 65536 - response.count)) {
                data, _, complete, error in
                if let data { response.append(data) }
                if let error {
                    finish(.failure(ProbeError("recv: \(error.localizedDescription)")))
                    return
                }
                if response.count >= 65536 || complete {
                    guard let status = HTTPProbe.statusLine(response, complete: complete) else {
                        finish(.failure(ProbeError("invalid or incomplete HTTP response")))
                        return
                    }
                    finish(
                        .success(
                            (
                                http: "\(status), received \(response.count) bytes"
                                    + (complete ? " (EOF)" : " (sample limit)"), tlsTime: tlsTime, cert: cert
                            )))
                } else {
                    receiveMore()
                }
            }
        }

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                tlsTime = (ProcessInfo.processInfo.systemUptime - start)
                cert = peerCertSummary(connection) ?? ""
                let request =
                    "GET / HTTP/1.1\r\nHost: \(host)\r\nRange: bytes=0-65535\r\nConnection: close\r\n\r\n"
                connection.send(
                    content: Data(request.utf8),
                    completion: .contentProcessed { error in
                        if let error {
                            finish(.failure(ProbeError("send: \(error.localizedDescription)")))
                            return
                        }
                        receiveMore()
                    })
            case .failed(let error):
                finish(.failure(ProbeError("connection: \(error.localizedDescription)")))
            case .waiting(let error):
                if (ProcessInfo.processInfo.systemUptime - start) > timeout {
                    finish(.failure(ProbeError("waiting: \(error.localizedDescription)")))
                }
            default:
                break
            }
        }
        connection.start(queue: DispatchQueue(label: "net.dighole.vault.probe.https"))

        let timer = DispatchWorkItem { finish(.failure(ProbeError("timeout"))) }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
        _ = semaphore.wait(timeout: .now() + timeout)
        timer.cancel()
        connection.cancel()
        lock.lock()
        defer { lock.unlock() }
        return outcome ?? .failure(ProbeError("timeout"))
    }

    private static func peerCertSummary(_ connection: NWConnection) -> String? {
        guard
            let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                as? NWProtocolTLS.Metadata
        else { return nil }
        let secMetadata = metadata.securityProtocolMetadata
        var subject: String?
        sec_protocol_metadata_access_peer_certificate_chain(secMetadata) { certificate in
            if subject == nil {
                subject =
                    SecCertificateCopySubjectSummary(
                        sec_certificate_copy_ref(certificate).takeRetainedValue()) as String?
            }
        }
        return subject
    }

    // MARK: - Socket helpers

    private static func bindToInterface(_ fd: Int32, index: UInt32, family: Int32 = AF_INET) -> Bool {
        var value = index
        if family == AF_INET6 {
            return setsockopt(
                fd, IPPROTO_IPV6, IPV6_BOUND_IF, &value, socklen_t(MemoryLayout<UInt32>.size)) == 0
        }
        return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &value, socklen_t(MemoryLayout<UInt32>.size))
            == 0
    }

    private static func setReceiveTimeout(_ fd: Int32, timeout: TimeInterval) -> Bool {
        var tv = timeval(
            tv_sec: Int(timeout),
            tv_usec: Int32(max(1, (timeout - Double(Int(timeout))) * 1_000_000))
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

/// Probe failure reason retained in per-target results and logs.
struct ProbeError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Minimal DNS wire codec: builds an A or AAAA query and extracts matching
/// address records from a response, following compression pointers when skipping
/// names. Unknown record types are skipped via their rdlength.
struct DNSPacket {

    enum RecordType: UInt16 { case a = 1, aaaa = 28 }

    static func buildQuery(domain: String, id: UInt16, type: RecordType = .a) -> Data? {
        var data = Data()
        data.append(contentsOf: [UInt8(id >> 8), UInt8(id & 0xff)])
        data.append(contentsOf: [0x01, 0x00])  // RD
        data.append(contentsOf: [0x00, 0x01])  // QDCOUNT
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let name = domain.hasSuffix(".") ? String(domain.dropLast()) : domain
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return nil }
        var nameLength = 1
        for label in labels {
            guard !label.isEmpty, label.count <= 63,
                label.utf8.allSatisfy({
                    (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45
                }),
                label.first != "-", label.last != "-"
            else { return nil }
            nameLength += label.count + 1
            guard nameLength <= 255 else { return nil }
            data.append(UInt8(label.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(0)
        data.append(contentsOf: [UInt8(type.rawValue >> 8), UInt8(type.rawValue & 0xff)])  // QTYPE
        data.append(contentsOf: [0x00, 0x01])  // QCLASS IN
        return data
    }

    /// Returns matching address records; an empty array when the answer
    /// is valid but holds no matching records (e.g. CNAME-only chains we did not
    /// follow); nil when the packet is malformed or carries an error rcode.
    static func parseAnswers(_ data: Data, expectedID: UInt16, type expectedType: RecordType = .a) -> [String]? {
        guard data.count >= 12 else { return nil }
        func u16(_ offset: Int) -> UInt16 {
            UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        }
        guard u16(0) == expectedID else { return nil }
        let flags = u16(2)
        guard flags & 0x8000 != 0 else { return nil }  // QR
        guard flags & 0x0200 == 0 else { return nil }  // truncated
        guard flags & 0x7800 == 0 else { return nil }  // standard query
        guard flags & 0x000f == 0 else { return nil }  // rcode NOERROR only
        let qdcount = Int(u16(4))
        let ancount = Int(u16(6))

        guard qdcount == 1 else { return nil }
        var offset = 12
        for _ in 0..<qdcount {
            guard let next = skipName(data, offset) else { return nil }
            offset = next + 4  // qtype + qclass
            guard offset <= data.count, u16(next) == expectedType.rawValue, u16(next + 2) == 1 else { return nil }
        }

        var answers: [String] = []
        for _ in 0..<ancount {
            guard let nameEnd = skipName(data, offset) else { return nil }
            guard nameEnd + 10 <= data.count else { return nil }
            let type = u16(nameEnd)
            let rdlength = Int(u16(nameEnd + 8))
            let rdata = nameEnd + 10
            guard rdata + rdlength <= data.count else { return nil }
            if type == expectedType.rawValue, u16(nameEnd + 2) == 1 {
                guard rdlength == (expectedType == .aaaa ? 16 : 4) else { return nil }
            }
            if type == expectedType.rawValue, type == 1, u16(nameEnd + 2) == 1, rdlength == 4 {
                answers.append("\(data[rdata]).\(data[rdata + 1]).\(data[rdata + 2]).\(data[rdata + 3])")
            }
            if type == expectedType.rawValue, type == 28, u16(nameEnd + 2) == 1, rdlength == 16 {
                let bytes = Data(data[rdata..<(rdata + 16)])
                guard let address = IPv6Address(bytes) else { return nil }
                answers.append(address.debugDescription)
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

/// A complete HTTP/1.x header is required before reporting HTTPS success.
enum HTTPProbe {
    static func statusLine(_ data: Data, complete: Bool = false) -> String? {
        guard let end = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let headers = String(decoding: data[..<end.lowerBound], as: UTF8.self)
        guard let line = headers.components(separatedBy: "\r\n").first else { return nil }
        let parts = line.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(parts[0])),
            parts[1].count == 3, let code = Int(parts[1]), (200...599).contains(code)
        else { return nil }
        if complete, code != 204, code != 304 {
            let fields = headers.components(separatedBy: "\r\n").dropFirst().compactMap { field -> (String, String)? in
                guard let colon = field.firstIndex(of: ":") else { return nil }
                return (field[..<colon].lowercased(), field[field.index(after: colon)...].trimmingCharacters(in: .whitespaces))
            }
            let body = Data(data[end.upperBound...])
            if fields.contains(where: { $0.0 == "transfer-encoding" && $0.1.lowercased().contains("chunked") }) {
                guard completeChunks(body) else { return nil }
            } else if let length = fields.first(where: { $0.0 == "content-length" })?.1 {
                guard let size = Int(length), size >= 0, body.count == size else { return nil }
            }
        }
        return line
    }

    private static func completeChunks(_ data: Data) -> Bool {
        var offset = data.startIndex
        while offset < data.endIndex {
            guard let end = data.range(of: Data("\r\n".utf8), in: offset..<data.endIndex),
                  let sizeText = String(data: data[offset..<end.lowerBound], encoding: .ascii),
                  let hex = sizeText.split(separator: ";", maxSplits: 1).first,
                  let size = Int(hex, radix: 16), size >= 0 else { return false }
            offset = end.upperBound
            if size == 0 {
                let tail = Data(data[offset...])
                return tail == Data("\r\n".utf8) || tail.range(of: Data("\r\n\r\n".utf8)) != nil
            }
            guard size <= data.endIndex - offset, data.endIndex - offset - size >= 2 else { return false }
            offset += size
            guard data[offset] == 13, data[offset + 1] == 10 else { return false }
            offset += 2
        }
        return false
    }
}
