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
