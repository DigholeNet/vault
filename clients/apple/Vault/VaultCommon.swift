//
//  VaultCommon.swift
//  Vault
//
//
import Network
import Security
import SwiftUI
import VaultCore
import os.log

enum VpnStatusUtil {
    static func titleKey(for status: VpnStatus) -> String {
        switch status {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .disconnecting: return "Disconnecting…"
        }
    }

    static func getStatus(_ status: VpnStatus) -> String {
        LanguageManager.shared.tr(titleKey(for: status))
    }
}

class AppData: ObservableObject {
    var canToggleConnection: Bool { vpnStatus != .disconnecting || connectionError != nil }
    var vpnOn: Bool { vpnStatus == .connected || vpnStatus == .connecting }
    @Published var vpnStatus: VpnStatus = VpnStatus.disconnected
    /// Set when the user tries to connect without server configuration;
    /// the UI should guide them to the configure page.
    @Published var showConfigureGuide: Bool = false

    @Published var connectedSince: Date?

    @Published var connectionError: String?

    #if os(macOS)
    @Published var isRecovering = false
    #endif

    // Packet statistics (total)
    @Published var packetsSent: UInt64 = 0
    @Published var packetsReceived: UInt64 = 0
    @Published var bytesSent: UInt64 = 0
    @Published var bytesReceived: UInt64 = 0

    // Byte rates (per second)
    @Published var bytesSentPerSecond: UInt64 = 0
    @Published var bytesReceivedPerSecond: UInt64 = 0

    private var statsTimer: Timer?
    private var previousStats: PacketStats.Stats = .zero
    /// Accumulates totals from previous provider sessions within one visible
    /// "on" period. The provider zeroes its counters when the extension
    /// restarts (watchdog/crash + On-Demand restart can do this without a
    /// user-visible disconnect); without the base, the displayed totals
    /// would go backwards.
    private var statsBase = (
        packetsSent: UInt64(0), packetsReceived: UInt64(0),
        bytesSent: UInt64(0), bytesReceived: UInt64(0)
    )

    #if os(macOS)
    /// macOS only: queries the running provider (a system extension in a
    /// different user session) for stats + assigned IP. Set by VpnManager.
    var providerStatusQuery: ((@escaping (ProviderStatus?) -> Void) -> Void)?
    /// Called with the provider-reported assigned IP when it changes.
    var onAssignedIp: ((String) -> Void)?
    #endif

    /// Start monitoring packet statistics
    func startStatsMonitoring() {
        // The main app is a read-only consumer; the network extension owns
        // and resets the counters per tunnel session. Do NOT reset here —
        // writing from both processes would make them overwrite each other.
        // Seed previousStats with the current value so the first-tick rate
        // does not spike to the session total.
        //
        // A status flap (on -> connecting -> on, e.g. an On-Demand restart
        // of the extension) must not stack a second timer or reseed the
        // baseline — that would leak timers and hide a counter regression.
        guard statsTimer == nil else { return }
        previousStats = PacketStats.shared.currentStats
        updateStats()

        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.updateStats()
        }
    }

    /// Stop monitoring packet statistics
    func stopStatsMonitoring() {
        statsTimer?.invalidate()
        statsTimer = nil
        statsBase = (0, 0, 0, 0)
        previousStats = .zero
        // Clear the displayed counters too: the session ended, so showing
        // its final totals as if they were current would mislead.
        packetsSent = 0
        packetsReceived = 0
        bytesSent = 0
        bytesReceived = 0
        bytesSentPerSecond = 0
        bytesReceivedPerSecond = 0
    }

    private func updateStats() {
        #if os(macOS)
        if let query = providerStatusQuery {
            query { [weak self] status in
                guard let status = status else { return }
                DispatchQueue.main.async {
                    self?.applyStats(status.stats)
                    if !status.ip.isEmpty {
                        self?.onAssignedIp?(status.ip)
                    }
                }
            }
            return
        }
        #endif
        applyStats(PacketStats.shared.currentStats)
    }

    private func applyStats(_ stats: PacketStats.Stats) {
        // Byte rates come straight from the Rust core's own speed calculation.
        bytesSentPerSecond = stats.bytesSentPerSecond
        bytesReceivedPerSecond = stats.bytesReceivedPerSecond

        // On a counter regression (extension restarted mid-session), fold
        // the lost counts into statsBase so the displayed totals never go
        // backwards while the tunnel stays up.
        if stats.packetsSent < previousStats.packetsSent {
            statsBase.packetsSent += previousStats.packetsSent
        }
        if stats.packetsReceived < previousStats.packetsReceived {
            statsBase.packetsReceived += previousStats.packetsReceived
        }
        if stats.bytesSent < previousStats.bytesSent {
            statsBase.bytesSent += previousStats.bytesSent
        }
        if stats.bytesReceived < previousStats.bytesReceived {
            statsBase.bytesReceived += previousStats.bytesReceived
        }

        packetsSent = statsBase.packetsSent + stats.packetsSent
        packetsReceived = statsBase.packetsReceived + stats.packetsReceived
        bytesSent = statsBase.bytesSent + stats.bytesSent
        bytesReceived = statsBase.bytesReceived + stats.bytesReceived

        previousStats = stats
    }
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

    @AppStorage var id: String
    @AppStorage var ip: String
    @AppStorage var host: String
    @AppStorage var port: Int
    @AppStorage var dns: String
    /// Comma-separated domains for the on-demand diagnostics probes; empty
    /// means the provider's defaults.
    @AppStorage var probeDomains: String
    /// Optional tunnel MTU cap; empty = automatic (built-in upper bound).
    @AppStorage var mtu: String

    /// The app stores this secret in Keychain rather than App Group defaults.
    /// Connecting also copies it into providerConfiguration, which the OS
    /// persists with the VPN profile so on-demand extension restarts work.
    /// The extension reads that saved profile, not this app's Keychain item.
    @Published var password: String = "" {
        didSet {
            guard !updatingSavedPassword else { return }
            passwordNeedsReload = false
            persistPassword()
        }
    }
    @Published var passwordStorageError: String?
    private let passwords: PasswordPersistence
    private var passwordNeedsReload = false
    private var updatingSavedPassword = false

    init(defaults: UserDefaults = VaultConfig.sharedDefaults, passwords: PasswordPersistence? = nil) {
        _id = AppStorage(wrappedValue: "", "id", store: defaults)
        _ip = AppStorage(wrappedValue: "", "ip", store: defaults)
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
        guard passwordNeedsReload else {
            persistPassword()
            return
        }
        do {
            // A read failure must be retried as a read. Saving the empty UI
            // placeholder here could delete an existing locked credential.
            password = try passwords.load()
        } catch {
            Logger.network.error("Password reload failed: \(error.localizedDescription)")
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
            // The credential is already saved; avoid a second Keychain write.
            updatingSavedPassword = true
            self.password = password
            updatingSavedPassword = false
            passwordNeedsReload = false
            passwordStorageError = nil
        } else if passwordStorageError != nil { return false }
        self.host = host
        self.port = port
        return true
    }

    func persistPassword() {
        do {
            try passwords.save(password)
            passwordStorageError = nil
        } catch {
            passwordStorageError = "Password could not be saved or loaded. Please try again."
            Logger.network.error("Password storage failed: \(error.localizedDescription)")
        }
    }
}

// MARK: - Keychain storage for the VPN password

/// Minimal Keychain wrapper for the single shared-network password.
enum KeychainPasswordStore {
    private static let service = "net.dighole.vault"
    private static let account = "password"

    static func load() throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return "" }
        guard status == errSecSuccess else { throw KeychainError(status: status) }
        guard let data = item as? Data,
              let password = String(data: data, encoding: .utf8) else {
            throw KeychainError(status: errSecDecode)
        }
        return password
    }

    static func save(_ password: String) throws {
        if password.isEmpty {
            try delete()
            return
        }
        let data = Data(password.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainError(status: addStatus) }
        } else if status != errSecSuccess {
            throw KeychainError(status: status)
        }
    }

    static func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }

    private struct KeychainError: LocalizedError {
        let status: OSStatus
        var errorDescription: String? { "Keychain operation failed (\(status))" }
    }
}

// MARK: - IP Parsing Helpers

extension String {
    /// Splits a supernode-assigned address string ("ipv4" or "ipv4/ipv6")
    /// into its parts; empty parts become nil.
    func parsedIPv4AndIPv6() -> (ipv4: String?, ipv6: String?) {
        guard !self.isEmpty else { return (nil, nil) }

        let components = self.split(separator: "/", omittingEmptySubsequences: false)
        let ipv4 = !components.isEmpty ? String(components[0]).trimmingCharacters(in: .whitespaces) : nil
        let ipv6 = components.count > 1 ? String(components[1]).trimmingCharacters(in: .whitespaces) : nil

        return (
            ipv4?.isEmpty == false ? ipv4 : nil,
            ipv6?.isEmpty == false ? ipv6 : nil
        )
    }
}

// MARK: - Version Helpers

extension Bundle {
    var appVersionShort: String {
        infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }

    var appVersion: String {
        let version = appVersionShort
        let build = infoDictionary?["CFBundleVersion"] as? String ?? "0"
        return "\(version).\(build)"
    }
}
