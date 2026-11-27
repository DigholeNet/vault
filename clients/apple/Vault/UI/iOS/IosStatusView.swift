import SwiftUI
import VaultCore

#if os(iOS)
struct IosStatusView: View {
    var vpnManager: VpnManager
    var openNewProfile: () -> Void = {}
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var config: VaultConfig
    @EnvironmentObject var languageManager: LanguageManager
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @ScaledMetric(relativeTo: .title2) private var statusTitleSize = 21.0
    @ScaledMetric(relativeTo: .title) private var durationSize = 26.0
    @ScaledMetric(relativeTo: .body) private var actionSize = 15.0
    @ScaledMetric(relativeTo: .caption) private var detailSize = 12.0
    @State private var pendingProfileSwitch: String?

    private var parsedIPs: (ipv4: String?, ipv6: String?) {
        appData.assignedIp.parsedIPv4AndIPv6()
    }

    private var phase: VaultConnectionPhase {
        VaultConnectionPhase(
            status: appData.vpnStatus,
            failed: appData.connectionError != nil,
            permissionRequired: appData.needsVPNPermission,
            recovering: appData.isRecovering
        )
    }

    private var active: Bool { appData.vpnStatus != .disconnected }
    private var noProfile: Bool { phase == .disconnected && config.profiles.isEmpty }
    private var showsStatusBadge: Bool { phase != .failed && phase != .permissionRequired }
    private var usesIndigoCard: Bool { phase == .connected || phase == .connecting || phase == .reconnecting }
    private var statusTitle: String {
        let key = switch phase {
        case .disconnected: noProfile ? "No configuration" : "Disconnected"
        case .connecting: "Connecting…"
        case .connected: "VPN connected"
        case .disconnecting: "Disconnecting…"
        case .reconnecting: "Reconnecting"
        case .failed: "Connection failed"
        case .permissionRequired: "VPN permission required"
        }
        return languageManager.tr(key)
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                let headerLayout = dynamicTypeSize.isAccessibilitySize
                    ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
                    : AnyLayout(HStackLayout(spacing: 12))
                headerLayout {
                    VaultPageHeader(
                        title: "Vault",
                        subtitle: languageManager.tr("Private networking, made simple.")
                    )
                    if showsStatusBadge {
                        VaultStatusBadge(
                            title: phase == .connected ? languageManager.tr("Running") : statusTitle,
                            active: usesIndigoCard
                        )
                    }
                }

                if !active && !noProfile {
                    profileSelector
                }
                connectionHero

                if phase == .disconnected && !noProfile {
                    VaultInfoCallout(
                        title: languageManager.tr("Ready to connect"),
                        detail: languageManager
                            .tr(
                                "Review the server configuration, then tap the power button. Network details and live traffic appear after connecting."
                            )
                    )
                } else if phase == .connected {
                    networkDetails
                    traffic
                }
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
        .vaultScreenBackground()
        .navigationBarHidden(true)
        .confirmationDialog(
            languageManager.tr("Switch Profile?"),
            isPresented: Binding(
                get: { pendingProfileSwitch != nil },
                set: { if !$0 { pendingProfileSwitch = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let name = pendingProfileSwitch {
                Button(languageManager.tr("Disconnect and Connect")) {
                    pendingProfileSwitch = nil
                    vpnManager.requestProfileSelection(name)
                }
            }
            Button(languageManager.tr("Cancel"), role: .cancel) { pendingProfileSwitch = nil }
        } message: {
            if let name = pendingProfileSwitch {
                Text(languageManager.tr("The current tunnel will disconnect before connecting to") + " \(name).")
            }
        }
    }

    private var connectionActionTitle: String {
        switch phase {
        case .disconnected: noProfile ? "Add Profile" : "Tap to connect"
        case .connecting, .disconnecting: "Please wait…"
        case .reconnecting, .connected: "Tap to disconnect"
        case .failed: "Tap to retry"
        case .permissionRequired: "Authorize VPN"
        }
    }

    private var connectionDetail: String? {
        switch phase {
        case .disconnected:
            noProfile ? languageManager.tr("No server configuration has been added.")
                : config.selectedProfileName.map { languageManager.tr("Using profile: %@", $0) }
        case .connecting, .reconnecting: languageManager.tr("Establishing a secure tunnel")
        case .disconnecting: languageManager.tr("Closing the secure tunnel")
        case .connected:
            (appData.runningProfileName ?? vpnManager.activeProfileName)
                .map { "\($0) · \(languageManager.tr(connectionActionTitle))" }
                ?? languageManager.tr(connectionActionTitle)
        case .failed, .permissionRequired:
            appData.connectionError.map { languageManager.tr($0) }
        }
    }

    private var connectionHero: some View {
        VStack(spacing: 0) {
            Text(statusTitle)
                .font(.system(size: statusTitleSize, weight: .bold))
                .foregroundStyle(usesIndigoCard ? VaultTheme.heroText : VaultTheme.textSecondary)

            Button {
                if noProfile { openNewProfile() }
                else if phase == .disconnected || phase == .failed || phase == .permissionRequired { vpnManager.connect() }
                else { vpnManager.disconnect() }
            } label: {
                statusIcon
            }
            .buttonStyle(VaultConnectionPressStyle(showsDisabledAppearance: false))
            .disabled(phase == .disconnecting || !appData.canToggleConnection)
            .accessibilityLabel(languageManager.tr(phase == .connecting ? "Cancel Connection" : connectionActionTitle))
            .accessibilityIdentifier("vpn.connection")
            .padding(.top, 12)

            if phase == .connected {
                ConnectionDurationView(
                    since: appData.connectedSince ?? .now,
                    size: durationSize,
                    design: .monospaced,
                    color: VaultTheme.heroText,
                    verticalPadding: 0
                )
                .padding(.top, 10)
            } else {
                Text(languageManager.tr(connectionActionTitle))
                    .font(.system(size: actionSize, weight: .semibold))
                    .foregroundStyle(usesIndigoCard ? VaultTheme.heroText : VaultTheme.primary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 10)
            }

            if let detail = connectionDetail {
                Text(detail)
                    .font(.system(size: detailSize))
                    .foregroundStyle(usesIndigoCard ? VaultTheme.heroSecondary : VaultTheme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 8)
            }
        }
        .multilineTextAlignment(.center)
        .padding(.horizontal, 20)
        .padding(.vertical, 20)
        .frame(maxWidth: .infinity)
        .frame(minHeight: 224, alignment: .top)
        .background {
            if phase == .connected { VaultHeroBackground(showsDecoration: false) }
            else if usesIndigoCard { Color(vaultHex: "312E81") }
            else { VaultTheme.surfaceMuted }
        }
        .clipShape(RoundedRectangle(cornerRadius: 24))
        .overlay {
            RoundedRectangle(cornerRadius: 24)
                .strokeBorder(usesIndigoCard ? Color.clear : VaultTheme.outline, lineWidth: 1)
        }
    }

    private var statusIcon: some View {
        VaultConnectionIcon(
            phase: phase,
            size: 76,
            symbolSize: 38,
            fill: usesIndigoCard ? VaultTheme.heroText
                : (colorScheme == .dark ? Color(vaultHex: "2A3045") : VaultTheme.surface),
            glyphColor: phase == .connected ? VaultTheme.heroPower : nil,
            showsAddSymbol: noProfile,
            showsProgressRing: true
        )
    }

    @ViewBuilder
    private var networkDetails: some View {
        let ips = parsedIPs
        if !appData.publicIp.isEmpty || ips.ipv4 != nil || ips.ipv6 != nil {
            VaultSection(languageManager.tr("Network details"), padding: 14, spacing: 10) {
                VStack(spacing: 8) {
                    if !appData.publicIp.isEmpty {
                        VaultAddressRow(title: "WAN", address: appData.publicIp, symbol: "globe")
                    }
                    if !appData.publicIp.isEmpty, ips.ipv4 != nil || ips.ipv6 != nil {
                        Divider().overlay(VaultTheme.outline)
                    }
                    if let ipv4 = ips.ipv4 {
                        VaultAddressRow(title: "IPv4", address: ipv4, symbol: "server.rack", color: VaultTheme.downlink)
                    }
                    if let ipv6 = ips.ipv6 {
                        VaultAddressRow(title: "IPv6", address: ipv6, symbol: "server.rack")
                    }
                }
            }
        }
    }

    private var traffic: some View {
        VaultSection(languageManager.tr("Live traffic"), padding: 14, spacing: 10) {
            let stacked = dynamicTypeSize.isAccessibilitySize
            let layout = stacked ? AnyLayout(VStackLayout(spacing: 12)) : AnyLayout(HStackLayout(spacing: 0))
            layout {
                VaultTrafficColumn(
                    title: "Uplink", symbol: "arrow.up", color: VaultTheme.primary,
                    packets: appData.packetsSent, bytes: appData.bytesSent,
                    rate: appData.bytesSentPerSecond, spacing: 4
                )
                Rectangle()
                    .fill(VaultTheme.outline)
                    .frame(width: stacked ? nil : 1, height: stacked ? 1 : 80)
                VaultTrafficColumn(
                    title: "Downlink", symbol: "arrow.down", color: VaultTheme.downlink,
                    packets: appData.packetsReceived, bytes: appData.bytesReceived,
                    rate: appData.bytesReceivedPerSecond, spacing: 4
                )
            }
        }
    }

    @ViewBuilder
    private var profileSelector: some View {
        if config.profiles.isEmpty {
            Button { appData.showConfigureGuide = true } label: {
                HStack(spacing: 12) {
                    VaultIconTile(systemName: "plus")
                    Text(languageManager.tr("Add Profile"))
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(VaultTheme.textPrimary)
                    Spacer()
                    Image(systemName: "chevron.right").foregroundStyle(VaultTheme.textDisabled)
                }
                .vaultCard(padding: 12, cornerRadius: 16)
            }
            .buttonStyle(.plain)
        } else {
            Menu {
                ForEach(config.profiles, id: \.name) { profile in
                    Button {
                        if appData.vpnStatus == .disconnected {
                            vpnManager.requestProfileSelection(profile.name)
                        } else if profile.name != vpnManager.activeProfileName {
                            pendingProfileSwitch = profile.name
                        }
                    } label: {
                        if config.selectedProfileName == profile.name {
                            Label(profile.name, systemImage: "checkmark")
                        } else {
                            Text(profile.name)
                        }
                    }
                }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: "server.rack")
                        .foregroundStyle(VaultTheme.primary)
                        .frame(width: 24)
                    Text(config.selectedProfileName ?? languageManager.tr("Add Profile"))
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(VaultTheme.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    Text(languageManager.tr("Switch Profile"))
                        .font(.caption)
                        .foregroundStyle(VaultTheme.textSecondary)
                    Image(systemName: "chevron.right")
                        .font(.system(size: 11))
                        .foregroundStyle(VaultTheme.textDisabled)
                }
                .padding(.horizontal, 16)
                .frame(minHeight: 56)
                .background(VaultTheme.surface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .strokeBorder(VaultTheme.outline)
                }
            }
            .buttonStyle(.plain)
            .disabled(appData.switchingProfileName != nil || appData.vpnStatus == .disconnecting)
        }
    }
}

#Preview {
    let config = VaultConfig()
    let appData = AppData()
    let vpnManager = VpnManager(config: config, appData: appData)
    IosStatusView(vpnManager: vpnManager)
        .environmentObject(appData)
        .environmentObject(config)
        .environmentObject(LanguageManager.shared)
}
#endif
