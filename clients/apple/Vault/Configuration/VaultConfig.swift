// SPDX-License-Identifier: MIT
import Foundation
import os.log
import SwiftUI
import VaultCore

struct VaultProfile: Codable, Equatable {
    var name = ""
    var host = ""
    var port = 9527
    var dnsIpv4 = ""
    var dnsIpv6 = ""
    var mtu = ""
    var password = ""
    var hostLatencyMs: UInt64?

    enum CodingKeys: String, CodingKey {
        case name, host, port, dnsIpv4, dnsIpv6, mtu
        case hostLatencyMs = "networkLatencyMs"
    }
}

private struct VaultProfileStore: Codable {
    var version = 1
    var selectedProfileName: String?
    var profiles: [VaultProfile]
    var lastImportedHostLatency: UUID?
}

class VaultConfig: ObservableObject {
    static let sharedDefaults: UserDefaults = {
        guard let defaults = UserDefaults(suiteName: kAppGroupIdentifier) else {
            Logger.network.warning(
                "Failed to load UserDefaults for suite '\(kAppGroupIdentifier)', falling back to standard"
            )
            return .standard
        }
        return defaults
    }()

    private static let profileStoreKey = "connectionProfiles.v1"

    @AppStorage var id: String
    @AppStorage var probeDomains: String
    @Published private(set) var profiles: [VaultProfile] = []
    @Published private(set) var selectedProfileName: String?
    @Published private(set) var passwordStorageError: String?

    private(set) var lastImportedHostLatency: UUID?
    private let defaults: UserDefaults
    private let passwordStore: (String) -> PasswordPersistence

    var selectedProfile: VaultProfile? {
        profiles.first { $0.name == selectedProfileName }
    }

    var host: String { selectedProfile?.host ?? "" }
    var password: String { selectedProfile?.password ?? "" }

    init(
        defaults: UserDefaults = VaultConfig.sharedDefaults,
        passwordStore: @escaping (String) -> PasswordPersistence = { name in
            PasswordPersistence(
                read: { try KeychainPasswordStore.load(profile: name) },
                write: { try KeychainPasswordStore.save($0, profile: name) },
                readLegacy: { nil },
                clearLegacy: {}
            )
        }
    ) {
        self.defaults = defaults
        self.passwordStore = passwordStore
        _id = AppStorage(wrappedValue: "", "id", store: defaults)
        _probeDomains = AppStorage(wrappedValue: "", "probeDomains", store: defaults)
        for key in ["ip", "host", "port", "password", "dnsIpv4", "dnsIpv6", "mtu"] {
            defaults.removeObject(forKey: key)
        }
        do {
            try KeychainPasswordStore.deleteLegacy()
        } catch {
            Logger.network.error("Legacy password cleanup failed: \(error.localizedDescription)")
        }
        loadProfiles()
        if id.isEmpty {
            id = generatePeerIdHex()
        }
    }

    private func loadProfiles() {
        guard let data = defaults.data(forKey: Self.profileStoreKey) else {
            profiles = []
            selectedProfileName = nil
            return
        }
        do {
            let store = try JSONDecoder().decode(VaultProfileStore.self, from: data)
            lastImportedHostLatency = store.lastImportedHostLatency
            profiles = store.profiles.map { profile in
                var loaded = profile
                do {
                    loaded.password = try passwordStore(profile.name).load()
                } catch {
                    passwordStorageError = "Password could not be saved or loaded. Please try again."
                    Logger.network.error("Password load failed: \(error.localizedDescription)")
                }
                return loaded
            }
            selectedProfileName = store.profiles.contains { $0.name == store.selectedProfileName }
                ? store.selectedProfileName : store.profiles.first?.name
        } catch {
            profiles = []
            selectedProfileName = nil
            passwordStorageError = "Configuration could not be loaded. Please try again."
            Logger.network.error("Profile store load failed: \(error.localizedDescription)")
        }
    }

    private func persist() {
        do {
            let store = VaultProfileStore(
                selectedProfileName: selectedProfileName, profiles: profiles,
                lastImportedHostLatency: lastImportedHostLatency
            )
            defaults.set(try JSONEncoder().encode(store), forKey: Self.profileStoreKey)
        } catch {
            passwordStorageError = "Configuration could not be loaded. Please try again."
            Logger.network.error("Profile store save failed: \(error.localizedDescription)")
        }
    }

    func profile(named name: String) -> VaultProfile? {
        profiles.first { $0.name == name }
    }

    func recordHostLatency(_ milliseconds: UInt64, for name: String, host: String, port: Int) {
        guard let index = profiles.firstIndex(where: {
            $0.name == name && $0.host == host && $0.port == port
        }), profiles[index].hostLatencyMs != milliseconds else { return }
        profiles[index].hostLatencyMs = milliseconds
        persist()
    }

    #if os(iOS)
    func importHostLatency(from url: URL? = SavedHostLatency.sharedURL) {
        guard let url, let sample = try? SavedHostLatency.read(from: url),
              lastImportedHostLatency != sample.id else { return }
        lastImportedHostLatency = sample.id
        if let index = profiles.firstIndex(where: {
            $0.name == sample.profileName && $0.host == sample.host && $0.port == sample.port
        }) {
            profiles[index].hostLatencyMs = sample.milliseconds
        }
        persist()
    }
    #endif

    func selectProfile(_ name: String) {
        guard profiles.contains(where: { $0.name == name }) else { return }
        selectedProfileName = name
        persist()
    }

    var connectionDraft: ConnectionDraft {
        draft(for: selectedProfileName)
    }

    func draft(for name: String?) -> ConnectionDraft {
        var draft = ConnectionDraft()
        guard let profile = profiles.first(where: { $0.name == name }) else { return draft }
        draft.name = profile.name
        draft.host = profile.host
        draft.port = String(profile.port)
        draft.password = profile.password
        draft.dnsIpv4 = profile.dnsIpv4
        draft.dnsIpv6 = profile.dnsIpv6
        draft.mtu = profile.mtu
        return draft
    }

    private struct ProfileSaveError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private struct PreparedProfile {
        var profile: VaultProfile
        let existingIndex: Int?
        let draft: ConnectionDraft
    }

    private func prepareProfile(
        _ source: ConnectionDraft,
        originalName: String?,
        section: ConnectionDraft.Section
    ) throws -> PreparedProfile {
        let draft = source.normalized
        if let error = draft.validationError(in: section) { throw ProfileSaveError(message: error) }
        guard let port = Int(draft.port), (1 ... 65535).contains(port) else {
            throw ProfileSaveError(message: "Port must be a number between 1 and 65535.")
        }
        let duplicate = profiles.contains { profile in
            if let originalName, profile.name == originalName { return false }
            return profile.name.caseInsensitiveCompare(draft.name) == .orderedSame
        }
        if duplicate { throw ProfileSaveError(message: "A profile with this name already exists.") }

        let existingIndex = originalName.flatMap { name in profiles.firstIndex { $0.name == name } }
        if originalName != nil && existingIndex == nil {
            throw ProfileSaveError(message: "Configuration could not be loaded. Please try again.")
        }
        if originalName == nil && (section == .network || section == .advanced) {
            throw ProfileSaveError(message: "Save the connection settings first.")
        }
        var profile = existingIndex.map { profiles[$0] } ?? VaultProfile()
        if section == .all || section == .connection {
            if profile.host != draft.host || profile.port != port {
                profile.hostLatencyMs = nil
            }
            profile.name = draft.name
            profile.host = draft.host
            profile.port = port
        }
        return PreparedProfile(profile: profile, existingIndex: existingIndex, draft: draft)
    }

    private func storePassword(
        for prepared: inout PreparedProfile,
        originalName: String?,
        section: ConnectionDraft.Section
    ) throws {
        guard section == .all || section == .connection else { return }
        do {
            if prepared.profile.password != prepared.draft.password || originalName != prepared.draft.name {
                try passwordStore(prepared.draft.name).save(prepared.draft.password)
            }
            prepared.profile.password = prepared.draft.password
        } catch {
            let message = "Password could not be saved or loaded. Please try again."
            passwordStorageError = message
            Logger.network.error("Password save failed: \(error.localizedDescription)")
            throw ProfileSaveError(message: message)
        }
    }

    @discardableResult
    func saveProfile(
        _ draft: ConnectionDraft,
        originalName: String? = nil,
        section: ConnectionDraft.Section = .all
    ) -> String? {
        do {
            var prepared = try prepareProfile(draft, originalName: originalName, section: section)
            try storePassword(for: &prepared, originalName: originalName, section: section)
            var profile = prepared.profile
            if section == .all || section == .network {
                profile.dnsIpv4 = prepared.draft.dnsIpv4
                profile.dnsIpv6 = prepared.draft.dnsIpv6
            }
            if section == .all || section == .advanced {
                profile.mtu = prepared.draft.mtu
            }
            if let existingIndex = prepared.existingIndex {
                profiles[existingIndex] = profile
            } else {
                profiles.append(profile)
            }
            if selectedProfileName == nil || selectedProfileName == originalName {
                selectedProfileName = profile.name
            }
            passwordStorageError = nil
            persist()
            if let originalName, originalName != profile.name {
                do {
                    try passwordStore(originalName).save("")
                } catch {
                    Logger.network.error("Old profile password cleanup failed: \(error.localizedDescription)")
                }
            }
            return nil
        } catch let error as ProfileSaveError {
            return error.message
        } catch {
            return error.localizedDescription
        }
    }

    func deleteProfile(_ name: String) {
        guard let index = profiles.firstIndex(where: { $0.name == name }) else { return }
        profiles.remove(at: index)
        if selectedProfileName == name {
            selectedProfileName = profiles.first?.name
        }
        persist()
        do {
            try passwordStore(name).save("")
        } catch {
            passwordStorageError = "Password could not be saved or loaded. Please try again."
            Logger.network.error("Profile password deletion failed: \(error.localizedDescription)")
        }
    }

    func canRetryPassword(for profileName: String?) -> Bool {
        passwordStorageError != nil || profileName.flatMap { profile(named: $0) }?.password.isEmpty == true
    }

    @discardableResult
    func retryPasswordStorage(for profileName: String? = nil) -> String? {
        var recoveredPassword: String?
        var failed = false
        for index in profiles.indices {
            let name = profiles[index].name
            do {
                let password = try passwordStore(name).load()
                profiles[index].password = password
                if name == profileName { recoveredPassword = password }
            } catch {
                failed = true
                Logger.network.error("Password retry failed: \(error.localizedDescription)")
            }
        }
        passwordStorageError = failed ? "Password could not be saved or loaded. Please try again." : nil
        return recoveredPassword
    }

    func saveProbeDomains(_ value: String) -> String? {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard SettingsValidation.isValidProbeList(normalized) else {
            return "Enter up to 32 domain names, separated by commas, without URLs."
        }
        probeDomains = normalized
        return nil
    }

    var diagnosticDomains: [String] {
        probeDomains.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines)
        }.filter { !$0.isEmpty }
    }
}

struct ConnectionDraft: Equatable, Sendable {
    enum Section { case all, connection, network, advanced }
    var name = ""
    var host = ""
    var port = "9527"
    var password = ""
    var dnsIpv4 = ""
    var dnsIpv6 = ""
    var mtu = ""

    init() {}

    var normalized: Self {
        var draft = self
        draft.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.dnsIpv4 = dnsIpv4.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.dnsIpv6 = dnsIpv6.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.mtu = mtu.trimmingCharacters(in: .whitespacesAndNewlines)
        return draft
    }

    func validationError(in section: Section = .all) -> String? {
        if section == .all || section == .connection {
            guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return "Enter a profile name."
            }
            guard SettingsValidation.isValidServer(host) else {
                return "Enter a server IP address or hostname without a URL scheme."
            }
            guard let number = Int(port), (1 ... 65535).contains(number) else {
                return "Port must be a number between 1 and 65535."
            }
            guard !password.isEmpty else { return "Enter the server password." }
        }
        if section == .all || section == .network {
            guard SettingsValidation.isValidDNSList(dnsIpv4, ipv6: false) else {
                return "Enter up to 4 IPv4 DNS addresses, separated by commas."
            }
            guard SettingsValidation.isValidDNSList(dnsIpv6, ipv6: true) else {
                return "Enter up to 4 IPv6 DNS addresses, separated by commas."
            }
        }
        if section == .all || section == .advanced {
            guard SettingsValidation.isValidMTU(mtu) else { return "MTU must be between 1280 and 1427, or empty for automatic." }
        }
        return nil
    }
}

extension TunnelLaunchConfiguration {
    init(
        draft: ConnectionDraft, id: String, probeDomains: String = "", clearLogsToken: String? = nil
    ) throws {
        guard let peerID = try? peerIdFromHex(value: id) else { throw TunnelLaunchConfiguration.InvalidField.peerID }
        guard let port = UInt16(draft.port), port > 0 else { throw TunnelLaunchConfiguration.InvalidField.port }
        try self.init(providerConfiguration: [
            "profileName": draft.name, "host": draft.host, "port": port, "password": draft.password, "id": peerID,
            "dnsIpv4": draft.dnsIpv4, "dnsIpv6": draft.dnsIpv6, "probeDomains": probeDomains, "mtu": draft.mtu
        ], clearLogsToken: clearLogsToken)
    }
}
