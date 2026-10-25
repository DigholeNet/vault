import Foundation
import Testing
@testable import VaultCore

private func legacyProfile() -> [String: Any] {
    ["host": " [::1] ", "port": 9527, "password": " secret ", "id": Data(repeating: 1, count: 16)]
}

@Test func launchConfigurationReadsExistingProfiles() throws {
    let launch = try TunnelLaunchConfiguration(providerConfiguration: legacyProfile())
    #expect(launch.host == "::1")
    #expect(launch.port == 9527 && launch.password == " secret ")
    #expect(launch.dns == ["1.1.1.1", "8.8.8.8"])
    #expect(launch.probeDomains.isEmpty && launch.mtuCap == 1427)
}

@Test func launchConfigurationPropertyListRoundtrip() throws {
    var values = legacyProfile()
    values["host"] = " vpn.example.com "
    values["dns"] = " 1.1.1.1, ::1 "
    values["probeDomains"] = " example.com, github.com "
    values["mtu"] = " 1280 "
    values["clearLogsToken"] = "clear"
    let launch = try TunnelLaunchConfiguration(providerConfiguration: values)
    let data = try PropertyListSerialization.data(fromPropertyList: launch.providerConfiguration, format: .binary, options: 0)
    let decoded = try #require(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    let loaded = try TunnelLaunchConfiguration(providerConfiguration: decoded)
    #expect(loaded.host == "vpn.example.com" && loaded.port == launch.port)
    #expect(loaded.peerID == launch.peerID && loaded.password == launch.password)
    #expect(loaded.dns == ["1.1.1.1", "::1"])
    #expect(loaded.probeDomains == ["example.com", "github.com"])
    #expect(loaded.mtuCap == 1280 && loaded.clearLogsToken == "clear")
}

@Test func launchConfigurationRejectsInvalidRequiredFields() throws {
    for key in ["host", "port", "password", "id"] {
        var values = legacyProfile()
        values.removeValue(forKey: key)
        #expect(throws: (any Error).self) { try TunnelLaunchConfiguration(providerConfiguration: values) }
    }
    let invalidPorts: [Any] = [-1, 0, 65536, true, 9527.5, "9527"]
    for port in invalidPorts {
        var values = legacyProfile()
        values["port"] = port
        #expect(throws: (any Error).self) { try TunnelLaunchConfiguration(providerConfiguration: values) }
    }
    var values = legacyProfile()
    values["id"] = Data([1])
    #expect(throws: (any Error).self) { try TunnelLaunchConfiguration(providerConfiguration: values) }
}

@Test func launchConfigurationClampsMtuAndResetsOptionalValues() throws {
    var values = legacyProfile()
    values["mtu"] = "1000"
    values["dns"] = " , "
    #expect(try TunnelLaunchConfiguration(providerConfiguration: values).mtuCap == 1280)
    values["mtu"] = "9000"
    #expect(try TunnelLaunchConfiguration(providerConfiguration: values).mtuCap == 1427)
    values["mtu"] = "invalid"
    let loaded = try TunnelLaunchConfiguration(providerConfiguration: values)
    #expect(loaded.mtuCap == 1427 && !loaded.dns.isEmpty)
    #expect(loaded.probeDomains.isEmpty)
}
