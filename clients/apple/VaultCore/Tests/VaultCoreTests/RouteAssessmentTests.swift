import Testing
@testable import VaultCore

private let routeV6 = "2607:8700:5500:d2b6:0:1:0:3"

@Test func absentCachedAddressesNeverEstablishIPv6Bypass() {
    for assigned: String? in [nil, "", "  "] {
        let assessment = RouteCheck.assess(routes: ("192.168.10.2", routeV6), assignedIP: assigned)
        #expect(assessment.issues.isEmpty)
        #expect(!assessment.unavailable.isEmpty)
        var result = DiagnosticsResult(summary: "OK - checks passed", lines: [])
        result.appendRouteAssessment(assessment)
        #expect(result.summary.hasPrefix("INCOMPLETE"))
        #expect(!result.summary.contains("bypass"))
        #expect(!result.summary.contains("PROBLEMS FOUND"))
    }
}

@Test func authoritativeDualStackSnapshotMatchesReportedIOSRoute() {
    let assessment = RouteCheck.assess(routes: ("192.168.10.2", routeV6),
        assignedIP: "192.168.10.2/2607:8700:5500:d2b6:0000:0001:0000:0003")
    #expect(assessment.issues.isEmpty)
    #expect(assessment.unavailable.isEmpty)
    var result = DiagnosticsResult(summary: "OK - checks passed", lines: [])
    result.appendRouteAssessment(assessment)
    #expect(result.summary == "OK - checks passed")
}

@Test func ipv6OnlyMetadataCanStillVerifyIPv6WithoutClaimingBypass() {
    let assessment = RouteCheck.assess(routes: ("192.168.10.2", routeV6), assignedIP: "/\(routeV6)")
    #expect(assessment.issues.isEmpty)
    #expect(assessment.unavailable.count == 1)
}

@Test func actualRouteMismatchAndConfirmedIPv4OnlyBypassRemainFailures() {
    let mismatch = RouteCheck.assess(routes: ("192.168.1.20", routeV6),
        assignedIP: "192.168.10.2/2607:8700:5500:d2b6:0:1:0:2")
    #expect(mismatch.issues.count == 2)
    #expect(mismatch.unavailable.isEmpty)
    let bypass = RouteCheck.assess(routes: ("192.168.10.2", routeV6), assignedIP: "192.168.10.2")
    #expect(bypass.issues.count == 1)
    #expect(bypass.issues[0].contains("bypass"))
    var result = DiagnosticsResult(summary: "OK", lines: [])
    result.appendRouteAssessment(bypass)
    #expect(result.summary.hasPrefix("PROBLEMS FOUND"))
}

@Test func routeMeasurementFailureDoesNotMasqueradeAsMismatch() {
    let assessment = RouteCheck.assess(routes: (nil, nil), assignedIP: "192.168.10.2/\(routeV6)")
    #expect(assessment.issues.isEmpty)
    #expect(assessment.unavailable.count == 2)
    var result = DiagnosticsResult(summary: "PROBLEMS FOUND - HTTPS failed", lines: [])
    result.appendRouteAssessment(assessment)
    #expect(result.summary.contains("HTTPS failed"))
    #expect(result.summary.contains("INCOMPLETE"))
    #expect(result.lines.count == 2)
}

@Test func malformedAddressPayloadCannotEstablishValidRouting() {
    let result = RouteCheck.assess(routes: ("192.168.10.2", routeV6),
        assignedIP: "192.168.10.2/\(routeV6)/unexpected")
    #expect(result.issues.isEmpty)
    #expect(!result.unavailable.isEmpty)
}
