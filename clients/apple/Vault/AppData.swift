import Combine
import Foundation
import VaultCore

class AppData: ObservableObject {
    var canToggleConnection: Bool { vpnStatus != .disconnecting || connectionError != nil }
    var vpnOn: Bool { vpnStatus == .connected || vpnStatus == .connecting }
    @Published var vpnStatus: VpnStatus = VpnStatus.disconnected
    /// Set when the user tries to connect without server configuration;
    /// the UI should guide them to the configure page.
    @Published var showConfigureGuide: Bool = false

    @Published var assignedIp = ""
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

    private var previousStats: PacketStats.Stats = .zero
    private var providerSession: String?
    /// Accumulates totals from previous provider sessions within one visible
    /// "on" period. The provider zeroes its counters when the extension
    /// restarts (watchdog/crash + On-Demand restart can do this without a
    /// user-visible disconnect); without the base, the displayed totals
    /// would go backwards.
    private var statsBase = (
        packetsSent: UInt64(0), packetsReceived: UInt64(0),
        bytesSent: UInt64(0), bytesReceived: UInt64(0)
    )

    /// Reset the visible connection period; the provider owns raw counters.
    func resetStats() {
        assignedIp = ""
        providerSession = nil
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

    func applyStatus(_ status: ProviderStatus) {
        assignedIp = status.ip
        let stats = status.stats
        let restarted = providerSession != nil && status.session != nil && providerSession != status.session
        providerSession = status.session
        // Byte rates come straight from the Rust core's own speed calculation.
        bytesSentPerSecond = stats.bytesSentPerSecond
        bytesReceivedPerSecond = stats.bytesReceivedPerSecond

        // On a counter regression (extension restarted mid-session), fold
        // the lost counts into statsBase so the displayed totals never go
        // backwards while the tunnel stays up.
        if restarted || stats.packetsSent < previousStats.packetsSent {
            statsBase.packetsSent += previousStats.packetsSent
        }
        if restarted || stats.packetsReceived < previousStats.packetsReceived {
            statsBase.packetsReceived += previousStats.packetsReceived
        }
        if restarted || stats.bytesSent < previousStats.bytesSent {
            statsBase.bytesSent += previousStats.bytesSent
        }
        if restarted || stats.bytesReceived < previousStats.bytesReceived {
            statsBase.bytesReceived += previousStats.bytesReceived
        }

        packetsSent = statsBase.packetsSent + stats.packetsSent
        packetsReceived = statsBase.packetsReceived + stats.packetsReceived
        bytesSent = statsBase.bytesSent + stats.bytesSent
        bytesReceived = statsBase.bytesReceived + stats.bytesReceived

        previousStats = stats
    }
}
