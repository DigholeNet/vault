import Combine
import NetworkExtension
import VaultCore
import XCTest
@testable import Vault

extension VaultTests {
    func testDraftValidation() throws {
        let config = try makeConfig().config
        var draft = config.connectionDraft
        draft.name = " Work "
        draft.host = " test.invalid "
        draft.password = " secret "
        draft.dnsIpv4 = "invalid-dns"
        XCTAssertNotNil(config.saveProfile(draft))
        XCTAssertTrue(config.profiles.isEmpty)
        draft.dnsIpv4 = " 1.1.1.1 "
        draft.mtu = " 1280 "
        XCTAssertNil(config.saveProfile(draft))
        XCTAssertEqual(config.host, "test.invalid")
        XCTAssertEqual(config.password, " secret ")
        XCTAssertEqual(config.selectedProfile?.dnsIpv4, "1.1.1.1")
        XCTAssertEqual(config.selectedProfile?.mtu, "1280")
    }

    func testProbeDomains() throws {
        let (config, defaults) = try makeConfig()
        XCTAssertNil(config.saveProbeDomains(" example.com, github.com "))
        XCTAssertEqual(config.probeDomains, "example.com, github.com")
        XCTAssertEqual(config.diagnosticDomains, ["example.com", "github.com"])
        XCTAssertEqual(defaults.string(forKey: "probeDomains"), "example.com, github.com")
        XCTAssertNotNil(config.saveProbeDomains("https://example.com"))
        XCTAssertEqual(config.probeDomains, "example.com, github.com")
    }

    func testProfileCrud() throws {
        let config = try makeConfig().config
        XCTAssertTrue(saveTestProfile(config, name: "Home", host: "home.invalid", password: "home"))
        XCTAssertTrue(saveTestProfile(config, name: "Work", host: "work.invalid", password: "work"))
        config.selectProfile("Home")
        XCTAssertEqual(config.selectedProfileName, "Home")
        var renamed = config.draft(for: "Home")
        renamed.name = "Personal"
        XCTAssertNil(config.saveProfile(renamed, originalName: "Home"))
        XCTAssertEqual(config.selectedProfileName, "Personal")
        XCTAssertNil(config.profile(named: "Home"))
        XCTAssertEqual(config.profile(named: "Personal")?.password, "home")
        XCTAssertNotNil(config.saveProfile(renamed, originalName: nil))
        config.deleteProfile("Personal")
        XCTAssertEqual(config.selectedProfileName, "Work")
        XCTAssertEqual(config.profiles.count, 1)
    }

    func testNewProfileSection() throws {
        let config = try makeConfig().config
        var draft = ConnectionDraft()
        draft.name = "Work"
        draft.host = "work.invalid"
        draft.password = "secret"
        XCTAssertNil(config.saveProfile(draft, section: .connection))
        XCTAssertEqual(config.selectedProfileName, "Work")
        XCTAssertEqual(config.selectedProfile?.host, "work.invalid")
        XCTAssertEqual(config.selectedProfile?.password, "secret")
    }

    func testIncompleteProfile() throws {
        let config = try makeConfig().config
        var draft = ConnectionDraft()
        draft.dnsIpv4 = "1.1.1.1"
        XCTAssertNotNil(config.saveProfile(draft, section: .network))
        XCTAssertNotNil(config.saveProfile(draft, section: .advanced))
        XCTAssertTrue(config.profiles.isEmpty)
    }

    func testProfileDns() throws {
        let config = try makeConfig().config
        XCTAssertTrue(saveTestProfile(config, name: "Home"))
        XCTAssertTrue(saveTestProfile(config, name: "Work"))
        var home = config.draft(for: "Home")
        home.dnsIpv4 = "1.1.1.1"
        XCTAssertNil(config.saveProfile(home, originalName: "Home", section: .network))
        var work = config.draft(for: "Work")
        work.dnsIpv4 = "9.9.9.9"
        XCTAssertNil(config.saveProfile(work, originalName: "Work", section: .network))
        XCTAssertEqual(config.profile(named: "Home")?.dnsIpv4, "1.1.1.1")
        XCTAssertEqual(config.profile(named: "Work")?.dnsIpv4, "9.9.9.9")
    }

    func testSectionSave() throws {
        let config = try makeConfig().config
        XCTAssertTrue(saveTestProfile(config))
        var draft = config.connectionDraft
        draft.dnsIpv4 = "8.8.8.8"
        draft.mtu = "1280"
        XCTAssertNil(config.saveProfile(draft, originalName: "Test", section: .network))
        XCTAssertEqual(config.selectedProfile?.dnsIpv4, "8.8.8.8")
        XCTAssertEqual(config.selectedProfile?.mtu, "")
        XCTAssertNil(config.saveProfile(draft, originalName: "Test", section: .advanced))
        XCTAssertEqual(config.selectedProfile?.mtu, "1280")
        draft.host = "other.invalid"
        draft.dnsIpv4 = "invalid"
        XCTAssertNil(config.saveProfile(draft, originalName: "Test", section: .connection))
        XCTAssertEqual(config.host, "other.invalid")
        XCTAssertEqual(config.selectedProfile?.dnsIpv4, "8.8.8.8")
    }

    func testPasswordSaveFailure() throws {
        let suite = "VaultDraft.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        addTeardownBlock { defaults.removePersistentDomain(forName: suite) }
        let config = VaultConfig(defaults: defaults, passwordStore: { _ in
            PasswordPersistence(
                read: { "" },
                write: { _ in throw NSError(domain: "Keychain", code: 1) },
                readLegacy: { nil },
                clearLegacy: {}
            )
        })
        var draft = ConnectionDraft()
        draft.name = "Test"
        draft.host = "test.invalid"
        draft.password = "new"
        XCTAssertNotNil(config.saveProfile(draft))
        XCTAssertTrue(config.profiles.isEmpty)
        XCTAssertNil(config.selectedProfileName)
    }

    func testLegacyIgnored() throws {
        let (config, defaults) = try makeConfig()
        defaults.set("legacy.invalid", forKey: "host")
        defaults.set("legacy", forKey: "password")
        let reopened = VaultConfig(defaults: defaults)
        XCTAssertTrue(reopened.profiles.isEmpty)
        XCTAssertNil(reopened.selectedProfileName)
        XCTAssertNil(defaults.object(forKey: "host"))
        XCTAssertNil(defaults.object(forKey: "password"))
        XCTAssertEqual(config.host, "")
    }
}
