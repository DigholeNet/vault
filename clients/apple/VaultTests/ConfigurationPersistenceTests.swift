import Combine
import NetworkExtension
import VaultCore
import XCTest
#if os(macOS)
import SystemExtensions
#endif
@testable import Vault

extension VaultTests {
    func testDraftValidation() throws {
        let config = try makeConfig().config
        var draft = config.connectionDraft
        draft.host = " test.invalid "
        draft.password = " secret "
        draft.dnsIpv4 = "invalid-dns"
        XCTAssertNotNil(config.save(draft))
        XCTAssertEqual(config.host, "")
        XCTAssertEqual(config.password, "")
        draft.dnsIpv4 = " 1.1.1.1 "
        draft.mtu = " 1280 "
        draft.probeDomains = " example.com "
        XCTAssertNil(config.save(draft))
        XCTAssertEqual(config.host, "test.invalid")
        XCTAssertEqual(config.password, " secret ")
        XCTAssertEqual(config.dnsIpv4, "1.1.1.1")
        XCTAssertEqual(config.mtu, "1280")
        XCTAssertEqual(config.probeDomains, "example.com")
    }

    func testSectionSave() throws {
        let config = try makeConfig().config
        var draft = config.connectionDraft
        draft.dnsIpv4 = "8.8.8.8"
        draft.mtu = "1280"
        // Network/advanced can be saved before connection settings are complete.
        XCTAssertNil(config.save(draft, section: .network))
        XCTAssertEqual(config.dnsIpv4, "8.8.8.8")
        XCTAssertEqual(config.mtu, "")
        XCTAssertNil(config.save(draft, section: .advanced))
        XCTAssertEqual(config.mtu, "1280")
        draft.host = "test.invalid"
        draft.password = "secret"
        draft.dnsIpv4 = "invalid"
        XCTAssertNil(config.save(draft, section: .connection))
        XCTAssertEqual(config.host, "test.invalid")
        XCTAssertEqual(config.dnsIpv4, "8.8.8.8")
    }

    func testPasswordSaveFailure() throws {
        let suite = "VaultDraft.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        let passwords = PasswordPersistence(read: { "old" }, write: { _ in
            throw NSError(domain: "Keychain", code: 1)
        }, readLegacy: { nil }, clearLegacy: {})
        let config = VaultConfig(defaults: defaults, passwords: passwords)
        var draft = config.connectionDraft
        draft.host = "test.invalid"
        draft.password = "new"
        draft.dnsIpv4 = "1.1.1.1"
        XCTAssertNotNil(config.save(draft))
        XCTAssertEqual(config.host, "")
        XCTAssertEqual(config.password, "old")
        XCTAssertEqual(config.dnsIpv4, "")
    }
}

extension VaultTests {
    func testOldDnsIgnored() throws {
        let suite = "VaultDNS.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        defaults.set("9.9.9.9", forKey: "dns")
        let passwords = PasswordPersistence(read: { "secret" }, write: { _ in }, readLegacy: { nil }, clearLegacy: {})
        let config = VaultConfig(defaults: defaults, passwords: passwords)
        XCTAssertEqual(config.dnsIpv4, "")
        XCTAssertEqual(config.dnsIpv6, "")
        var draft = config.connectionDraft
        draft.dnsIpv4 = "9.9.9.9"
        draft.dnsIpv6 = "2606:4700:4700::1111"
        XCTAssertNil(config.save(draft, section: .network))
        XCTAssertEqual(defaults.string(forKey: "dnsIpv4"), "9.9.9.9")
        XCTAssertEqual(defaults.string(forKey: "dnsIpv6"), "2606:4700:4700::1111")
    }
}
