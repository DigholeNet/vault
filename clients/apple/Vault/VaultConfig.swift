// SPDX-License-Identifier: MIT
import Foundation
import os.log
import SwiftUI
import VaultCore

// MARK: - Saved configuration

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

    @AppStorage var id: String
    @AppStorage var host: String
    @AppStorage var port: Int
    @AppStorage var dns: String
    /// Comma-separated domains for the on-demand diagnostics probes; empty
    /// selects the Rust diagnostic engine's defaults.
    @AppStorage var probeDomains: String
    /// Optional tunnel MTU cap; empty = automatic (built-in upper bound).
    @AppStorage var mtu: String

    /// The app stores this secret in Keychain rather than App Group defaults.
    /// Connecting also copies it into providerConfiguration, which the OS
    /// persists with the VPN profile so on-demand extension restarts work.
    /// The extension reads that saved profile, not this app's Keychain item.
    @Published private(set) var password = ""
    @Published private(set) var passwordStorageError: String?
    private let passwords: PasswordPersistence
    private var passwordNeedsReload = false

    init(defaults: UserDefaults = VaultConfig.sharedDefaults, passwords: PasswordPersistence? = nil) {
        _id = AppStorage(wrappedValue: "", "id", store: defaults)
        defaults.removeObject(forKey: "ip")
        _host = AppStorage(wrappedValue: "", "host", store: defaults)
        _port = AppStorage(wrappedValue: 9527, "port", store: defaults)
        _dns = AppStorage(wrappedValue: "", "dns", store: defaults)
        _probeDomains = AppStorage(wrappedValue: "", "probeDomains", store: defaults)
        _mtu = AppStorage(wrappedValue: "", "mtu", store: defaults)
        self.passwords = passwords ?? PasswordPersistence(
            read: KeychainPasswordStore.load,
            write: KeychainPasswordStore.save,
            readLegacy: { defaults.string(forKey: "password") },
            clearLegacy: { defaults.removeObject(forKey: "password") }
        )
        do {
            password = try self.passwords.load()
        } catch {
            // Migration failure leaves the recovery copy intact, including
            // in memory for this run. Never replace it with a stale item.
            let legacy = defaults.string(forKey: "password")
            password = legacy ?? ""
            passwordNeedsReload = legacy?.isEmpty != false
            passwordStorageError = "Password could not be saved or loaded. Please try again."
            Logger.network.error("Password storage failed: \(error.localizedDescription)")
        }

        if id.isEmpty {
            id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        }
    }

    func retryPasswordStorage() {
        guard passwordStorageError != nil else { return }
        do {
            if passwordNeedsReload {
                // Retry a failed read without writing the empty UI placeholder.
                password = try passwords.load()
            } else {
                try passwords.save(password)
            }
            passwordNeedsReload = false
            passwordStorageError = nil
        } catch {
            Logger.network.error("Password retry failed: \(error.localizedDescription)")
        }
    }

    @discardableResult
    func saveConnection(host: String, port: Int, password: String) -> Bool {
        if password != self.password {
            do {
                try passwords.save(password)
            } catch {
                passwordStorageError = "Password could not be saved or loaded. Please try again."
                Logger.network.error("Password storage failed: \(error.localizedDescription)")
                return false
            }
            self.password = password
            passwordNeedsReload = false
            passwordStorageError = nil
        } else if passwordStorageError != nil { return false }
        self.host = host
        self.port = port
        return true
    }

    var connectionDraft: ConnectionDraft {
        var draft = ConnectionDraft()
        draft.host = host
        draft.port = String(port)
        draft.password = password
        draft.dns = dns
        draft.mtu = mtu
        draft.probeDomains = probeDomains
        return draft
    }

    /// Validate before writing; a failed credential write leaves all fields intact.
    func save(_ draft: ConnectionDraft, section: ConnectionDraft.Section = .all) -> String? {
        let draft = draft.normalized
        if let error = draft.validationError(in: section) { return error }
        if section == .all || section == .connection {
            guard let port = Int(draft.port),
                  saveConnection(host: draft.host, port: port, password: draft.password) else {
                return passwordStorageError ?? "Password could not be saved or loaded. Please try again."
            }
        }
        if section == .all || section == .network { dns = draft.dns }
        if section == .all || section == .advanced {
            mtu = draft.mtu
            probeDomains = draft.probeDomains
        }
        return nil
    }
}

// MARK: - Editable draft and profile conversion

/// Editable App settings, including section-level validation and user feedback.
struct ConnectionDraft: Equatable, Sendable {
    enum Section { case all, connection, network, advanced }
    var host = ""
    var port = ""
    var password = ""
    var dns = ""
    var mtu = ""
    var probeDomains = ""

    init() {}

    var normalized: Self {
        var draft = self
        draft.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.dns = dns.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.mtu = mtu.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.probeDomains = probeDomains.trimmingCharacters(in: .whitespacesAndNewlines)
        return draft
    }

    func validationError(in section: Section = .all) -> String? {
        if section == .all || section == .connection {
            guard SettingsValidation.isValidServer(host) else {
                return "Enter a server IP address or hostname without a URL scheme."
            }
            guard let number = Int(port), (1 ... 65535).contains(number) else {
                return "Port must be a number between 1 and 65535."
            }
            guard !password.isEmpty else { return "Enter the server password." }
        }
        if section == .all || section == .network {
            guard SettingsValidation.isValidDNSList(dns) else { return "Enter valid DNS IP addresses, separated by commas." }
        }
        if section == .all || section == .advanced {
            guard SettingsValidation.isValidMTU(mtu) else { return "MTU must be between 1280 and 1427, or empty for automatic." }
            guard SettingsValidation.isValidProbeList(probeDomains) else {
                return "Enter domain names separated by commas, without URLs."
            }
        }
        return nil
    }
}

/// Convert the App draft into the shared profile schema at the App boundary.
extension TunnelLaunchConfiguration {
    init(draft: ConnectionDraft, id: String, clearLogsToken: String? = nil) throws {
        guard let bytes = [UInt8](hex: id), bytes.count == 16 else { throw TunnelLaunchConfiguration.InvalidField.peerID }
        guard let port = UInt16(draft.port), port > 0 else { throw TunnelLaunchConfiguration.InvalidField.port }
        try self.init(providerConfiguration: [
            "host": draft.host, "port": port, "password": draft.password, "id": Data(bytes),
            "dns": draft.dns, "probeDomains": draft.probeDomains, "mtu": draft.mtu
        ], clearLogsToken: clearLogsToken)
    }
}
