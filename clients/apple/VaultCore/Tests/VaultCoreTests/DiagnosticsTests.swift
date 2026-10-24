import Foundation
import Testing

@testable import VaultCore

@Test func routeAddressComparisonUsesBinaryIPv6() {
  #expect(RouteCheck.sameAddress("fd00::1", "fd00:0:0:0:0:0:0:1"))
  #expect(!RouteCheck.sameAddress("fd00::1", "fd00::2"))
  #expect(!RouteCheck.sameAddress(nil, "fd00::1"))
  #expect(!RouteCheck.sameAddress("invalid", "invalid"))
}

@Test func incompleteAndCancelledChecksNeverPass() {
  let cancellation = DiagnosticsCancellation()
  var context = TunnelDiagnostics.Context(
    startedAt: ProcessInfo.processInfo.systemUptime, cancellation: cancellation,
    tunnelName: "utun-test", tunnelIndex: 1, tunnelNWInterface: nil)
  context.incomplete = true
  #expect(TunnelDiagnostics.summarize(ctx: context).hasPrefix("INCOMPLETE"))
  context.failures = 1
  #expect(TunnelDiagnostics.summarize(ctx: context).hasPrefix("PROBLEMS FOUND; INCOMPLETE"))
  cancellation.cancel()
  #expect(TunnelDiagnostics.summarize(ctx: context).contains("session changed"))
}

@Test func exhaustedBudgetStopsProbingAndClampsTimeouts() {
  let context = TunnelDiagnostics.Context(
    startedAt: ProcessInfo.processInfo.systemUptime - 61,
    cancellation: DiagnosticsCancellation(), tunnelName: "utun-test",
    tunnelIndex: 1, tunnelNWInterface: nil)
  #expect(context.overBudget)
  #expect(context.timeout(6) <= 0.001)
  #expect(TunnelDiagnostics.summarize(ctx: context).hasPrefix("INCOMPLETE"))
}

@Test func applicationFailureCannotBeHiddenByProviderSuccess() {
  var result = DiagnosticsResult(summary: "OK - IPv4 checks passed", lines: ["provider"])
  result.appendApplicationResult(
    DiagnosticsResult(summary: "PROBLEMS FOUND - app HTTPS failed", lines: ["app"]))
  #expect(result.summary.hasPrefix("PROBLEMS FOUND"))
  #expect(result.lines == ["provider", "app"])
  var incomplete = DiagnosticsResult(summary: "INCOMPLETE - provider timed out", lines: [])
  incomplete.appendApplicationResult(DiagnosticsResult(summary: "OK - app HTTPS passed", lines: []))
  #expect(incomplete.summary.hasPrefix("INCOMPLETE"))
}

@Test func httpsRequiresCompleteValidHTTPHeaders() {
  #expect(HTTPProbe.statusLine(Data("H".utf8)) == nil)
  #expect(HTTPProbe.statusLine(Data("HTTP/1.1 200 OK\r\n".utf8)) == nil)
  #expect(HTTPProbe.statusLine(Data("garbage\r\n\r\n".utf8)) == nil)
  #expect(HTTPProbe.statusLine(Data("HTTP/1.1 xyz OK\r\n\r\n".utf8)) == nil)
  #expect(
    HTTPProbe.statusLine(Data("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".utf8))
      == "HTTP/1.1 200 OK")
  // HTTP errors prove transport reachability; keep the status for the user.
  #expect(
    HTTPProbe.statusLine(Data("HTTP/1.1 503 Unavailable\r\n\r\n".utf8))
      == "HTTP/1.1 503 Unavailable")
}

@Test func dnsRejectsTruncatedAndNonInternetAnswers() {
  var packet = DNSPacket.buildQuery(domain: "example.com", id: 7)!
  packet[2] = 0x83  // QR + TC
  #expect(DNSPacket.parseAnswers(packet, expectedID: 7) == nil)
  packet[2] = 0x81
  packet[7] = 1
  packet.append(contentsOf: [0xc0, 0x0c, 0, 1, 0, 3, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4])
  #expect(DNSPacket.parseAnswers(packet, expectedID: 7) == [])
}

@Test func diagnosticsReplyRemainsCompatibleWithOlderProviders() throws {
  let result = try JSONDecoder().decode(
    DiagnosticsResult.self, from: Data(#"{"summary":"OK","lines":[]}"#.utf8))
  #expect(result.domains == nil)
}

@Test func probeDomainsRejectHTTPHeaderInjection() {
  #expect(DNSPacket.buildQuery(domain: "example.com\r\nHost: injected", id: 1) == nil)
  #expect(DNSPacket.buildQuery(domain: "https://example.com", id: 1) == nil)
  #expect(DNSPacket.buildQuery(domain: "example.com.", id: 1) != nil)
}

@Test func httpsDetectsPrematureEOF() {
    let truncated = Data("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".utf8)
    #expect(HTTPProbe.statusLine(truncated, complete: true) == nil)
    #expect(HTTPProbe.statusLine(truncated, complete: false) != nil) // bounded samples are explicit
    let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    #expect(HTTPProbe.statusLine(Data((chunked + "3\r\nabc\r\n").utf8), complete: true) == nil)
    #expect(HTTPProbe.statusLine(Data((chunked + "3\r\nabc\r\n0\r\n\r\n").utf8), complete: true) != nil)
    #expect(HTTPProbe.statusLine(Data((chunked + "ffffffffffffffff\r\n").utf8), complete: true) == nil)
}

@Test func structuredChecksAndDurationsSurviveProviderReply() throws {
    var result = DiagnosticsResult(summary: "OK", lines: [], checks: [
        DiagnosticsCheck(id: "dns", passed: 3, attempted: 3, state: .passed, durationMs: 587)
    ], durationMs: 4000)
    result.appendApplicationResult(DiagnosticsResult(summary: "PROBLEMS FOUND", lines: [], checks: [
        DiagnosticsCheck(id: "application", passed: 2, attempted: 3, state: .failed, durationMs: 6150)
    ], durationMs: 6150))
    let decoded = try JSONDecoder().decode(DiagnosticsResult.self, from: JSONEncoder().encode(result))
    #expect(decoded.durationMs == 10150)
    #expect(decoded.checks?.map(\.id) == ["dns", "application"])
    #expect(decoded.checks?.last?.state == .failed)
    #expect(decoded.checks?.last?.durationMs == 6150)
    #expect(decoded.summary.hasPrefix("PROBLEMS FOUND"))
}

@Test func progressReplyRetainsActiveCheckWithoutClaimingSuccess() throws {
    let running = DiagnosticsResult(summary: "RUNNING", lines: [], checks: [
        DiagnosticsCheck(id: "dns", passed: 3, attempted: 3, state: .passed, durationMs: 500)
    ], durationMs: 600, activeCheck: "tcp")
    let reply = try JSONDecoder().decode(DiagnosticsResult.self, from: JSONEncoder().encode(running))
    #expect(reply.activeCheck == "tcp")
    #expect(reply.checks?.count == 1)
    #expect(!reply.summary.hasPrefix("OK"))
}

@Test func settingsRejectMalformedValuesBeforeSaving() {
    #expect(SettingsValidation.isValidServer("vpn.example.com"))
    #expect(SettingsValidation.isValidServer("2607:8700:5500:d2b6:0:1:0:2"))
    #expect(!SettingsValidation.isValidServer("https://vpn.example.com"))
    #expect(!SettingsValidation.isValidServer("vpn.example.com:9527"))
    #expect(SettingsValidation.isValidDNSList("1.1.1.1, 2606:4700:4700::1111"))
    #expect(!SettingsValidation.isValidDNSList("1.1.1.1,"))
    #expect(!SettingsValidation.isValidDNSList("dns.example.com"))
    #expect(SettingsValidation.isValidDNSList(""))
    #expect(SettingsValidation.isValidMTU(""))
    #expect(SettingsValidation.isValidMTU("1280"))
    #expect(SettingsValidation.isValidMTU("1427"))
    #expect(!SettingsValidation.isValidMTU("1279"))
    #expect(!SettingsValidation.isValidMTU("1500"))
    #expect(SettingsValidation.isValidProbeList("www.google.com, github.com"))
    #expect(!SettingsValidation.isValidProbeList("google..com"))
    #expect(!SettingsValidation.isValidProbeList("https://google.com"))
    #expect(!SettingsValidation.isValidProbeList("google.com,"))
}

@Test func probeDetailsKeepHandshakeAndRequestTimingsDistinct() throws {
    var reply = DiagnosticsResult(summary: "OK", lines: [], probes: [
        DiagnosticsProbe(stage: "tcp", domain: "example.com", durationMs: 180, succeeded: false, detail: "first candidate timed out"),
        DiagnosticsProbe(stage: "https", domain: "example.com", durationMs: 1200, succeeded: true, detail: "HTTP/1.1 200 OK", tlsDurationMs: 380)
    ])
    reply.appendApplicationResult(DiagnosticsResult(summary: "OK", lines: [], probes: [
        DiagnosticsProbe(stage: "application", domain: "example.com", durationMs: 1400, succeeded: true, detail: "HTTP/1.1 200 OK", tlsDurationMs: 410)
    ]))
    let decoded = try JSONDecoder().decode(DiagnosticsResult.self, from: JSONEncoder().encode(reply))
    #expect(decoded.probes?.count == 3)
    #expect(decoded.probes?[0].succeeded == false)
    #expect(decoded.probes?[1].durationMs == 1200)
    #expect(decoded.probes?[1].tlsDurationMs == 380)
    #expect(decoded.probes?[2].stage == "application")
    #expect(Set(decoded.probes?.map(\.id) ?? []).count == 3)
}

@Test func checkDurationAveragesActualRequestsIncludingRetries() throws {
    let probes = [
        DiagnosticsProbe(stage: "dns", domain: "example.com", durationMs: 100, succeeded: false, detail: "first resolver failed"),
        DiagnosticsProbe(stage: "dns", domain: "example.com", durationMs: 200, succeeded: true, detail: "second resolver answered"),
        DiagnosticsProbe(stage: "dns", domain: "other.example", durationMs: 701, succeeded: true, detail: "answered"),
        DiagnosticsProbe(stage: "tcp", domain: "example.com", durationMs: 9999, succeeded: true, detail: "different check")
    ]
    let check = DiagnosticsCheck.measured(id: "dns", passed: 2, attempted: 2, state: .passed, probes: probes)
    #expect(check.durationMs == 334)
    #expect(check.sampleCount == 3)
    #expect(check.attempted == 2) // domain counts and request samples have different meanings
    let result = DiagnosticsResult(summary: "OK", lines: [], checks: [check], durationMs: 14000)
    let decoded = try JSONDecoder().decode(DiagnosticsResult.self, from: JSONEncoder().encode(result))
    #expect(decoded.durationMs == 14000) // total wall time must not become a mean
    #expect(decoded.checks?.first?.durationMs == 334)
    #expect(decoded.checks?.first?.sampleCount == 3)
    let skipped = DiagnosticsCheck.measured(id: "https", passed: 0, attempted: 0, state: .incomplete, probes: probes)
    #expect(skipped.sampleCount == 0)
}

@Test func ipv4BudgetCannotConsumeIPv6Window() {
    let now = ProcessInfo.processInfo.systemUptime
    var context = TunnelDiagnostics.Context(startedAt: now - 26,
        cancellation: DiagnosticsCancellation(), tunnelName: "utun-test", tunnelIndex: 1, tunnelNWInterface: nil)
    context.phaseDeadline = context.startedAt + 25
    #expect(context.overBudget)
    context.phaseDeadline = context.startedAt + 50
    #expect(!context.overBudget)
    #expect(context.remaining <= 24)
    context.cancellation.cancel()
    #expect(context.overBudget)
}

@Test func connectionValidationRejectsInvalidDraftsAndPersistedSettings() {
    func error(host: String = " vpn.example.com ", port: String = "9527",
        password: String = "secret", dns: String = "", mtu: String = "",
        domains: String = "") -> String? {
        SettingsValidation.configurationError(host: host, port: port, password: password,
            dns: dns, mtu: mtu, probeDomains: domains)
    }
    #expect(error() == nil)
    #expect(error(host: "https://vpn.example.com") != nil)
    #expect(error(port: "") != nil)
    #expect(error(port: "0") != nil)
    #expect(error(port: "65536") != nil)
    #expect(error(password: "") != nil)
    #expect(error(dns: "1.1.1.1,") != nil)
    #expect(error(mtu: "abc") != nil)
    #expect(error(domains: "https://example.com") != nil)
    #expect(error(dns: "1.1.1.1, ::1", mtu: " 1280 ", domains: "example.com") == nil)
}
