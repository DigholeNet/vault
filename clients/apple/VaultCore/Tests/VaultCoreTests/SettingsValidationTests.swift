// SPDX-License-Identifier: MIT
import Testing
@testable import VaultCore

@Test func settingsValidation() {
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

@Test func dnsFamilies() {
    #expect(SettingsValidation.isValidDNSList("1.1.1.1", ipv6: false))
    #expect(SettingsValidation.isValidDNSList("2001:4860:4860::8888", ipv6: true))
    #expect(!SettingsValidation.isValidDNSList("::1", ipv6: false))
    #expect(!SettingsValidation.isValidDNSList("1.1.1.1", ipv6: true))
}

@Test func listLimits() {
    #expect(SettingsValidation.isValidDNSList(Array(repeating: "1.1.1.1", count: 4).joined(separator: ","), ipv6: false))
    #expect(!SettingsValidation.isValidDNSList(Array(repeating: "1.1.1.1", count: 5).joined(separator: ","), ipv6: false))
    #expect(SettingsValidation.isValidProbeList((0 ..< 32).map { "d\($0).example" }.joined(separator: ",")))
    #expect(!SettingsValidation.isValidProbeList((0 ..< 33).map { "d\($0).example" }.joined(separator: ",")))
}
