import Foundation
import Testing
@testable import VaultCore

private func profile() -> [String: Any] {
    ["host": " [::1] ", "port": 9527, "password": " secret ", "id": Data(repeating: 1, count: 16)]
}

@Test func launchDefaults() throws {
    let launch = try TunnelLaunchConfiguration(providerConfiguration: profile())
    #expect(launch.host == "::1")
    #expect(launch.port == 9527 && launch.password == " secret ")
    #expect(launch.dnsIpv4.isEmpty && launch.dnsIpv6.isEmpty)
    #expect(launch.effectiveDNS(ipv4: true, ipv6: false) == ["1.1.1.1", "8.8.8.8"])
    #expect(launch.effectiveDNS(ipv4: false, ipv6: true) == ["2001:4860:4860::8888", "2001:4860:4860::8844"])
    #expect(launch.effectiveDNS(ipv4: true, ipv6: true).count == 4)
    #expect(launch.effectiveDNS(ipv4: false, ipv6: false).isEmpty)
    #expect(launch.probeDomains.isEmpty && launch.mtuCap == 1427)
}

@Test func launchRoundtrip() throws {
    var values = profile()
    values["host"] = " vpn.example.com "
    values["dnsIpv4"] = " 9.9.9.9 "
    values["dnsIpv6"] = " 2606:4700:4700::1111 "
    values["probeDomains"] = " example.com, github.com "
    values["mtu"] = " 1280 "
    values["clearLogsToken"] = "clear"
    let launch = try TunnelLaunchConfiguration(providerConfiguration: values)
    let data = try PropertyListSerialization.data(fromPropertyList: launch.providerConfiguration, format: .binary, options: 0)
    let decoded = try #require(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    let loaded = try TunnelLaunchConfiguration(providerConfiguration: decoded)
    #expect(loaded.host == "vpn.example.com" && loaded.port == launch.port)
    #expect(loaded.peerID == launch.peerID && loaded.password == launch.password)
    #expect(loaded.dnsIpv4 == ["9.9.9.9"] && loaded.dnsIpv6 == ["2606:4700:4700::1111"])
    #expect(loaded.effectiveDNS(ipv4: true, ipv6: true) == ["9.9.9.9", "2606:4700:4700::1111"])
    #expect(loaded.probeDomains == ["example.com", "github.com"])
    #expect(loaded.mtuCap == 1280 && loaded.clearLogsToken == "clear")
}

@Test func launchInvalid() throws {
    for key in ["host", "port", "password", "id"] {
        var values = profile()
        values.removeValue(forKey: key)
        #expect(throws: (any Error).self) { try TunnelLaunchConfiguration(providerConfiguration: values) }
    }
    let invalidPorts: [Any] = [-1, 0, 65536, true, 9527.5, "9527"]
    for port in invalidPorts {
        var values = profile()
        values["port"] = port
        #expect(throws: (any Error).self) { try TunnelLaunchConfiguration(providerConfiguration: values) }
    }
    for (key, value) in [("dnsIpv4", "::1"), ("dnsIpv6", "1.1.1.1"), ("dnsIpv4", "1.1.1.1,")] {
        var values = profile()
        values[key] = value
        #expect(throws: (any Error).self) { try TunnelLaunchConfiguration(providerConfiguration: values) }
    }
    var values = profile()
    values["id"] = Data([1])
    #expect(throws: (any Error).self) { try TunnelLaunchConfiguration(providerConfiguration: values) }
}

@Test func launchMtu() throws {
    var values = profile()
    values["mtu"] = "1000"
    #expect(try TunnelLaunchConfiguration(providerConfiguration: values).mtuCap == 1280)
    values["mtu"] = "9000"
    #expect(try TunnelLaunchConfiguration(providerConfiguration: values).mtuCap == 1427)
    values["mtu"] = "invalid"
    let loaded = try TunnelLaunchConfiguration(providerConfiguration: values)
    #expect(loaded.mtuCap == 1427 && loaded.probeDomains.isEmpty)
}

@Test func oldDnsIgnored() throws {
    var values = profile()
    values["dns"] = "9.9.9.9"
    let loaded = try TunnelLaunchConfiguration(providerConfiguration: values)
    #expect(loaded.dnsIpv4.isEmpty && loaded.dnsIpv6.isEmpty)
    #expect(loaded.providerConfiguration["dns"] == nil)
}
