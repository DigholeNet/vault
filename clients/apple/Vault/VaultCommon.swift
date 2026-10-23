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

class VpnStatusUtil {

    public static func getStatus(_ vpnStatus: VpnStatus) -> String {
        switch vpnStatus {

        case .off:
            return LanguageManager.shared.tr("Off")
        case .connecting:
            return LanguageManager.shared.tr("Connecting")
        case .on:
            return LanguageManager.shared.tr("On")
        case .disconnecting:
            return LanguageManager.shared.tr("Disconnecting")
        }
    }

}

extension NumberFormatter {
    static var noneSeparator: NumberFormatter {
        let formater = NumberFormatter()
        formater.numberStyle = .decimal
        formater.groupingSeparator = ""
        return formater
    }
}

class AppData: ObservableObject {
    @Published var vpnOn: Bool = false
    @Published var vpnStatus: VpnStatus = VpnStatus.off
    /// Set when the user tries to connect without server configuration;
    /// the UI should guide them to the configure page.
    @Published var showConfigureGuide: Bool = false

    // Packet statistics (total)
    @Published var packetsSent: UInt64 = 0
    @Published var packetsReceived: UInt64 = 0
    @Published var bytesSent: UInt64 = 0
    @Published var bytesReceived: UInt64 = 0

    // Packet rates (per second)
    @Published var packetsSentPerSecond: UInt64 = 0
    @Published var packetsReceivedPerSecond: UInt64 = 0
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
        // Packet rates: the core does not track per-second packet rates, so
        // keep diffing snapshots for these (totals only are shown in the UI).
        // The counters go backwards when the network extension restarts and
        // resets them per session — plain UInt64 subtraction would trap.
        // Treat a regression as a new session: report 0 and reseed.
        packetsSentPerSecond =
            stats.packetsSent >= previousStats.packetsSent
            ? stats.packetsSent - previousStats.packetsSent : 0
        packetsReceivedPerSecond =
            stats.packetsReceived >= previousStats.packetsReceived
            ? stats.packetsReceived - previousStats.packetsReceived : 0
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

    @AppStorage("id", store: sharedDefaults) var id = ""
    @AppStorage("ip", store: sharedDefaults) var ip = ""
    @AppStorage("host", store: sharedDefaults) var host = ""
    @AppStorage("port", store: sharedDefaults) var port = 9527
    @AppStorage("dns", store: sharedDefaults) var dns = ""

    /// The app stores this secret in Keychain rather than App Group defaults.
    /// Connecting also copies it into providerConfiguration, which the OS
    /// persists with the VPN profile so on-demand extension restarts work.
    /// The extension reads that saved profile, not this app's Keychain item.
    @Published var password: String = "" {
        didSet {
            passwordNeedsReload = false
            persistPassword()
        }
    }
    @Published var passwordStorageError: String?
    private let passwords: PasswordPersistence
    private var passwordNeedsReload = false

    init() {
        passwords = PasswordPersistence(
            read: KeychainPasswordStore.load,
            write: KeychainPasswordStore.save,
            readLegacy: { VaultConfig.sharedDefaults.string(forKey: "password") },
            clearLegacy: { VaultConfig.sharedDefaults.removeObject(forKey: "password") }
        )
        do {
            password = try passwords.load()
        } catch {
            // Migration failure leaves the recovery copy intact, including
            // in memory for this run. Never replace it with a stale item.
            let legacy = VaultConfig.sharedDefaults.string(forKey: "password")
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
