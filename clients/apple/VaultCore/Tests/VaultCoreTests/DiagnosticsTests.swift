// SPDX-License-Identifier: MIT
import Foundation
import Testing

@testable import VaultCore

private func context() -> AppleDiagnosticContext {
  AppleDiagnosticContext(
    provider: "provider-test", generation: 7, ipv4: "10.0.0.2",
    mask: "255.255.255.0", ipv6: "fd00::2", mtu: 1427, dns: [], domains: ["example.com"])
}

private func response(_ request: DiagnosticRequest) -> DiagnosticResponse {
  switch request.operation {
  case .route: return .route(ipv4: "10.0.0.2", ipv6: "fd00::2")
  case .dns(_, let ipv6): return .dns(addresses: [ipv6 ? "2001:db8::1" : "192.0.2.1"])
  case .tcp: return .tcp
  case .https:
    return .https(
      statusLine: "HTTP/1.1 200 OK", receivedBytes: 40,
      tlsDurationMs: 0, certificate: "test certificate")
  case .ping: return .failed(kind: .permission, detail: "ICMP filtered")
  }
}

@Test func engineFlow() {
  var scopes: [DiagnosticStage: DiagnosticScope] = [:]
  let result = RustDiagnostics.run(
    context: context(), cancellation: DiagnosticsCancellation(),
    execute: { request, remaining in
      #expect(remaining > 0)
      scopes[request.stage] = request.scope
      return response(request)
    })
  #expect(result.engineState == .passed)
  #expect(DiagnosticsPresentation.passed(result))
  #expect(result.checks?.count == 9)
  #expect(result.domainStates["example.com"] == .passed)
  #expect(scopes[.dns] == .tunnel && scopes[.https6] == .tunnel)
  #expect(scopes[.application] == .application && scopes[.route] == .application)
  #expect(scopes[.gateway] == .hostDefault && scopes[.ping] == .application)
  #expect(result.probes?.contains { $0.stage == "https" && $0.tlsDurationMs == 0 } == true)
  #expect(result.probes?.filter { $0.stage == "ping" }.allSatisfy { !$0.succeeded } == true)
}

@Test func cancelRun() {
  let cancellation = DiagnosticsCancellation()
  var calls = 0
  let result = RustDiagnostics.run(
    context: context(), cancellation: cancellation,
    execute: { _, _ in
      calls += 1
      cancellation.cancel()
      return nil
    })
  #expect(calls == 1)
  #expect(result.engineState == .incomplete)
  #expect(!DiagnosticsPresentation.passed(result))
}

@Test func missingReply() {
  let result = RustDiagnostics.run(
    context: context(), cancellation: DiagnosticsCancellation(), execute: { _, _ in nil })
  #expect(result.engineState == .incomplete)
}

@Test func probeTimeout() {
  var stages: Set<DiagnosticStage> = []
  var delayed = false
  let result = RustDiagnostics.run(
    context: context(), cancellation: DiagnosticsCancellation(),
    execute: { request, remaining in
      stages.insert(request.stage)
      if request.stage == .gateway && !delayed {
        delayed = true
        let native = AppleProbeRequest(
          request: request, context: context(), run: "timeout", remainingMs: remaining)
        // Simulate a full transport timeout plus provider reply delivery.
        let elapsed = Double(remaining) / 1000 + 0.05
        #expect(native.replyTimeout > elapsed)
        Thread.sleep(forTimeInterval: elapsed)
        return .failed(kind: .timeout, detail: "probe timed out")
      }
      return response(request)
    })
  #expect(delayed)
  #expect(stages.contains(.application))
  #expect(stages.contains(.ping))
  #expect(stages.contains(.ping6))
  #expect(result.engineState == .passed)
}

@Test func wireRoundtrip() throws {
  let ctx = context()
  let engine = try ctx.makeEngine()
  while let request = try engine.nextRequest() {
    let native = AppleProbeRequest(
      request: request, context: ctx, run: "run-test", remainingMs: 2500)
    let decoded = try JSONDecoder().decode(
      AppleProbeRequest.self, from: JSONEncoder().encode(native))
    #expect(decoded.provider == ctx.provider && decoded.generation == 7)
    #expect(decoded.run == "run-test" && decoded.id == request.id && decoded.timeout == 2.5)
    #expect(decoded.operation == native.operation && decoded.tunnel == native.tunnel)
    let reply = AppleProbeReply(
      request: decoded,
      response: .https(
        statusLine: "HTTP/1.1 200 OK", receivedBytes: 40, tlsMs: 12, certificate: "certificate"))
    let roundtrip = try JSONDecoder().decode(
      AppleProbeReply.self, from: JSONEncoder().encode(reply))
    #expect(roundtrip.run == "run-test" && roundtrip.id == request.id)
    #expect(
      roundtrip.response.rust
        == .https(
          statusLine: "HTTP/1.1 200 OK", receivedBytes: 40, tlsDurationMs: 12,
          certificate: "certificate"))
    try engine.complete(id: request.id, response: response(request))
  }
}

@Test func rustVerdicts() throws {
  let result = RustDiagnostics.run(
    context: context(), cancellation: DiagnosticsCancellation(),
    execute: { request, _ in
      if request.stage == .route { return .route(ipv4: "192.168.1.2", ipv6: "fd00::2") }
      return response(request)
    })
  let decoded = try JSONDecoder().decode(DiagnosticsResult.self, from: JSONEncoder().encode(result))
  #expect(decoded.engineState == .failed)
  #expect(!DiagnosticsPresentation.passed(decoded))
  #expect(decoded.domainStates["example.com"] == .passed)
  #expect(decoded.lines.contains { $0.contains("route:") })
}

@Test func sessionClockClampsAndKeepsHoursPastOneDay() {
  #expect(DiagnosticsPresentation.connectionDuration(-5) == "00:00:00")
  #expect(DiagnosticsPresentation.connectionDuration(1476.9) == "00:24:36")
  #expect(DiagnosticsPresentation.connectionDuration(90061) == "25:01:01")
}

@Test func logSearchCombinesSourceAndCaseInsensitiveText() {
  let text = "[app] HTTPS ready\n[ne] DNS ready\n[ne] HTTPS failed"
  #expect(
    DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "https") == "[ne] HTTPS failed"
  )
  #expect(
    DiagnosticsPresentation.filteredLogs(text, source: "all", search: "ready")
      == "[app] HTTPS ready\n[ne] DNS ready")
  #expect(DiagnosticsPresentation.filteredLogs(text, source: "app", search: "DNS").isEmpty)
}

@Test func tunnelLogFilterIncludesCoreFailures() {
  let text = "[app] ready\n[ne] start\n[rust] handshake failed\n[rust] PANIC"
  #expect(
    DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "")
      == "[ne] start\n[rust] handshake failed\n[rust] PANIC")
  #expect(
    DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "HANDSHAKE")
      == "[rust] handshake failed")
  #expect(DiagnosticsPresentation.filteredLogs(text, source: "app", search: "") == "[app] ready")
}
