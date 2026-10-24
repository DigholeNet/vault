import Testing
@testable import VaultCore

@Test func sessionClockClampsAndKeepsHoursPastOneDay() {
    #expect(DiagnosticsPresentation.connectionDuration(-5) == "00:00:00")
    #expect(DiagnosticsPresentation.connectionDuration(1476.9) == "00:24:36")
    #expect(DiagnosticsPresentation.connectionDuration(90061) == "25:01:01")
}

@Test func logSearchCombinesSourceAndCaseInsensitiveText() {
    let text = "[app] HTTPS ready\n[ne] DNS ready\n[ne] HTTPS failed"
    #expect(DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "https") == "[ne] HTTPS failed")
    #expect(DiagnosticsPresentation.filteredLogs(text, source: "all", search: "ready") == "[app] HTTPS ready\n[ne] DNS ready")
    #expect(DiagnosticsPresentation.filteredLogs(text, source: "app", search: "DNS").isEmpty)
}

@Test func resultPresentationDoesNotMarkIncompleteChecksPassed() {
    let check = DiagnosticsCheck(id: "dns", passed: 0, attempted: 0, state: .incomplete, durationMs: 0)
    #expect(!DiagnosticsPresentation.passed(DiagnosticsResult(summary: "OK", lines: [], checks: [check])))
    #expect(DiagnosticsPresentation.incomplete(DiagnosticsResult(summary: "PROBLEMS FOUND; INCOMPLETE", lines: [])))
    #expect(DiagnosticsPresentation.passed(DiagnosticsResult(summary: "OK - legacy result", lines: [])))
}

@Test func successfulRetriesDoNotFailDomainSummary() {
    let domain = "example.com"
    var probes = DiagnosticsPresentation.checkIDs.map {
        DiagnosticsProbe(stage: $0, domain: domain, durationMs: 100, succeeded: true, detail: "ok")
    }
    probes.insert(DiagnosticsProbe(stage: "dns", domain: domain, durationMs: 500,
        succeeded: false, detail: "first resolver timed out"), at: 0)
    let result = DiagnosticsResult(summary: "OK", lines: [], probes: probes)
    #expect(DiagnosticsPresentation.domainState(result, domain: domain) == .passed)
    #expect(result.probes?.first?.succeeded == false)
}

@Test func domainSummaryKeepsFailuresAndMissingStagesDistinct() {
    let failed = DiagnosticsResult(summary: "PROBLEMS FOUND", lines: [], probes: [
        DiagnosticsProbe(stage: "dns", domain: "example.com", durationMs: 100, succeeded: false, detail: "timeout")
    ])
    #expect(DiagnosticsPresentation.domainState(failed, domain: "example.com") == .failed)
    #expect(DiagnosticsPresentation.domainState(failed, domain: "other.com") == .incomplete)
}

@Test func legacyStageDurationIsNotLabelledAnAverage() {
    let legacy = DiagnosticsResult(summary: "OK", lines: [], checks: [
        DiagnosticsCheck(id: "dns", passed: 3, attempted: 3, state: .passed, durationMs: 600)
    ])
    #expect(DiagnosticsPresentation.durationHeading(legacy) == "Duration")
    let measured = DiagnosticsResult(summary: "OK", lines: [], checks: [
        DiagnosticsCheck(id: "dns", passed: 3, attempted: 3, state: .passed, durationMs: 200, sampleCount: 3)
    ])
    #expect(DiagnosticsPresentation.durationHeading(measured) == "Average duration")
}

@Test func tunnelLogFilterIncludesCoreFailures() {
    let text = "[app] ready\n[ne] start\n[rust] handshake failed\n[rust] PANIC"
    #expect(DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "")
        == "[ne] start\n[rust] handshake failed\n[rust] PANIC")
    #expect(DiagnosticsPresentation.filteredLogs(text, source: "ne", search: "HANDSHAKE")
        == "[rust] handshake failed")
    #expect(DiagnosticsPresentation.filteredLogs(text, source: "app", search: "") == "[app] ready")
}

@Test func failedOrMissingIPv6CannotBeHiddenByIPv4Success() {
    let checks = DiagnosticsPresentation.requiredCheckIDs.map {
        DiagnosticsCheck(id: $0, passed: 1, attempted: 1, state: .passed, durationMs: 1)
    }
    var result = DiagnosticsResult(summary: "OK", lines: [], checks: checks)
    #expect(DiagnosticsPresentation.passed(result))
    result.checks?.removeAll { $0.id == "https6" }
    #expect(!DiagnosticsPresentation.passed(result))
    #expect(DiagnosticsPresentation.incomplete(result))
    result.checks = checks
    result.checks?[4].state = .failed
    #expect(!DiagnosticsPresentation.passed(result))
}

@Test func blockedPingIsInformationalAndRTTUsesOnlyReplies() {
    let probes = [
        DiagnosticsProbe(stage: "ping", domain: "1.1.1.1", durationMs: 200, succeeded: true, detail: "reply"),
        DiagnosticsProbe(stage: "ping", domain: "1.1.1.1", durationMs: 2000, succeeded: false, detail: "timeout")
    ]
    let ping = DiagnosticsCheck.ping(id: "ping", probes: probes)
    #expect(ping.attempted == 2 && ping.passed == 1)
    #expect(ping.sampleCount == 1 && ping.durationMs == 200)
    #expect(ping.state == .incomplete)
    let checks = DiagnosticsPresentation.requiredCheckIDs.map {
        DiagnosticsCheck(id: $0, passed: 1, attempted: 1, state: .passed, durationMs: 1)
    }
    let result = DiagnosticsResult(summary: "OK", lines: [], checks: checks + [ping])
    #expect(DiagnosticsPresentation.passed(result))
    #expect(!DiagnosticsPresentation.incomplete(result))
}

@Test func domainsWithoutAAAAAreNotReportedAsIPv6TransportFailures() {
    var probes = ["dns", "tcp", "https", "application"].map {
        DiagnosticsProbe(stage: $0, domain: "example.com", durationMs: 1, succeeded: true, detail: "ok")
    }
    probes.append(DiagnosticsProbe(stage: "dns6", domain: "example.com", durationMs: 1,
        succeeded: true, detail: "[] (no AAAA records)"))
    #expect(DiagnosticsPresentation.domainState(DiagnosticsResult(summary: "OK", lines: [], probes: probes),
        domain: "example.com") == .passed)
}
