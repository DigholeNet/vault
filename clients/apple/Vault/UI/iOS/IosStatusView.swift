import SwiftUI
import VaultCore

#if os(iOS)
struct IosStatusView: View {
    var vpnManager: VpnManager
    var onOpenDiagnostics: () -> Void = {}
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var config: VaultConfig
    @EnvironmentObject var languageManager: LanguageManager
    @State private var pendingProfileSwitch: String?

    private var parsedIPs: (ipv4: String?, ipv6: String?) {
        appData.assignedIp.parsedIPv4AndIPv6()
    }

    private var active: Bool { appData.vpnStatus != .disconnected }
    private var failed: Bool { appData.vpnStatus == .disconnected && appData.connectionError != nil }
    private var statusTitle: String {
        failed ? languageManager.tr("Connection failed") : VpnStatusUtil.getStatus(appData.vpnStatus)
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                HStack(alignment: .center, spacing: 12) {
                    VaultPageHeader(
                        title: "Vault",
                        subtitle: languageManager.tr("Private networking, made simple.")
                    )
                    VaultStatusBadge(title: statusTitle, active: active, failure: failed)
                }

                if !active {
                    profileSelector
                }
                connectionHero

                if appData.vpnStatus == .disconnected && !failed {
                    VaultInfoCallout(
                        title: languageManager.tr("Ready to connect"),
                        detail: languageManager
                            .tr(
                                "Review the server configuration, then tap the power button. Network details and live traffic appear after connecting."
                            )
                    )
                } else if failed {
                    Button(action: onOpenDiagnostics) {
                        HStack(spacing: 12) {
                            VaultIconTile(systemName: "waveform.path.ecg", size: 28)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(languageManager.tr("Need to investigate further?"))
                                    .font(.system(size: 12, weight: .bold))
                                Text(languageManager.tr("Check the server address and network, or open Diagnostics."))
                                    .font(.system(size: 10.5))
                                    .foregroundStyle(VaultTheme.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer(minLength: 0)
                        }
                        .foregroundStyle(VaultTheme.textPrimary)
                        .vaultCard(padding: 18, cornerRadius: 18)
                    }
                    .buttonStyle(.plain)
                } else if appData.vpnStatus == .connected {
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

    private var connectionHero: some View {
        ZStack {
            if active {
                RoundedRectangle(cornerRadius: 28, style: .continuous).fill(VaultTheme.heroGradient)
                VaultHeroDecoration().clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
            } else {
                RoundedRectangle(cornerRadius: 28, style: .continuous)
                    .fill(failed ? VaultTheme.failureSurface : VaultTheme.surfaceMuted)
            }
            VStack(spacing: 0) {
                Text(statusTitle)
                    .font(.system(size: 23, weight: .bold))
                    .foregroundStyle(failed ? VaultTheme.danger : (active ? VaultTheme.heroText : VaultTheme.textSecondary))

                Toggle("", isOn: Binding(
                    get: { appData.vpnOn },
                    set: { enabled in
                        if enabled { vpnManager.connect() } else { vpnManager.disconnect() }
                    }
                ))
                .toggleStyle(CustomToggleStyle(failure: failed))
                .disabled(!appData.canToggleConnection)
                .padding(.top, 12)

                if appData.vpnStatus == .connected, appData.vpnOn, let since = appData.connectedSince {
                    ConnectionDurationView(since: since)
                        .font(.system(size: 28, weight: .light, design: .monospaced))
                        .foregroundStyle(VaultTheme.heroText)
                        .padding(.top, 8)
                }

                if !active {
                    Text(languageManager.tr(failed ? "Retry" : "Tap to connect"))
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(VaultTheme.primary)
                        .padding(.top, 10)
                }

                if let error = appData.connectionError {
                    Text(languageManager.tr(error))
                        .font(.system(size: 12))
                        .foregroundStyle(failed ? VaultTheme.danger : (active ? VaultTheme.heroSecondary : VaultTheme.textSecondary))
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 6)
                } else if let running = appData.runningProfileName, active {
                    Text("\(running) · " + languageManager.tr("Tap to disconnect"))
                        .font(.system(size: 12))
                        .foregroundStyle(VaultTheme.heroSecondary)
                        .padding(.top, 6)
                } else if let target = appData.switchingProfileName {
                    Text(languageManager.tr("Switching to") + " \(target)")
                        .font(.system(size: 12))
                        .foregroundStyle(VaultTheme.heroSecondary)
                        .padding(.top, 6)
                }

                Text(languageManager.tr(failed ? "Check the configuration, then retry" : "Encrypted tunnel · Auto reconnect"))
                    .font(.system(size: 10))
                    .foregroundStyle(active ? VaultTheme.heroSecondary : VaultTheme.textSecondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 5)
                    .background(
                        (active ? Color.white.opacity(0.09) : VaultTheme.surfaceSubtle),
                        in: Capsule()
                    )
                    .padding(.top, 10)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, active ? 12 : 24)
        }
        .frame(maxWidth: .infinity)
        .frame(height: active ? 258 : 286)
        .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 28, style: .continuous)
                .strokeBorder(failed ? VaultTheme.failureOutline : (active ? Color.clear : VaultTheme.outline), lineWidth: 1)
        }
    }

    @ViewBuilder
    private var networkDetails: some View {
        let ips = parsedIPs
        if !appData.publicIp.isEmpty || ips.ipv4 != nil || ips.ipv6 != nil {
            VaultSection(languageManager.tr("Network details")) {
                VStack(spacing: 14) {
                    if !appData.publicIp.isEmpty {
                        VaultAddressRow(title: "WAN", address: appData.publicIp, symbol: "globe")
                    }
                    if !appData.publicIp.isEmpty, ips.ipv4 != nil || ips.ipv6 != nil {
                        Divider().overlay(VaultTheme.outline)
                    }
                    if let ipv4 = ips.ipv4 {
                        VaultAddressRow(title: "IPv4", address: ipv4, symbol: "server.rack", color: Color(vaultHex: "2563EB"))
                    }
                    if let ipv6 = ips.ipv6 {
                        VaultAddressRow(title: "IPv6", address: ipv6, symbol: "server.rack")
                    }
                }
            }
        }
    }

    private var traffic: some View {
        VaultSection(languageManager.tr("Live traffic")) {
            HStack(spacing: 0) {
                VaultTrafficColumn(
                    title: "Uplink", symbol: "arrow.up", color: VaultTheme.primary,
                    packets: appData.packetsSent, bytes: appData.bytesSent,
                    rate: appData.bytesSentPerSecond
                )
                Divider().frame(height: 92).overlay(VaultTheme.outline)
                VaultTrafficColumn(
                    title: "Downlink", symbol: "arrow.down", color: Color(vaultHex: "2563EB"),
                    packets: appData.packetsReceived, bytes: appData.bytesReceived,
                    rate: appData.bytesReceivedPerSecond
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
                        .font(.system(size: 14, weight: .semibold))
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
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(VaultTheme.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    Text(languageManager.tr("Switch Profile"))
                        .font(.system(size: 11))
                        .foregroundStyle(VaultTheme.textDisabled)
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

struct CustomToggleStyle: ToggleStyle {
    var failure = false

    func makeBody(configuration: Configuration) -> some View {
        Button(action: { configuration.isOn.toggle() }) {
            Image(systemName: failure ? "exclamationmark" : "power")
                .font(.system(size: 38, weight: .medium))
                .foregroundStyle(failure ? VaultTheme.danger : (configuration.isOn ? VaultTheme.primary : VaultTheme.textDisabled))
                .frame(width: 94, height: 94)
                .background(VaultTheme.surface, in: Circle())
                .overlay {
                    Circle().strokeBorder(failure ? VaultTheme.failureOutline : (configuration.isOn ? Color.clear : VaultTheme.outline))
                }
                .contentShape(Circle())
        }
        .accessibilityLabel(LanguageManager.shared.tr(failure ? "Retry" : (configuration.isOn ? "Disconnect" : "Connect")))
        .accessibilityIdentifier("vpn.connection")
        .buttonStyle(ConnectionIconButtonStyle())
        .frame(width: 94, height: 94)
    }
}

private struct ConnectionIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .shadow(
                color: .black.opacity(configuration.isPressed ? 0.04 : 0.08),
                radius: configuration.isPressed ? 2 : 6,
                y: configuration.isPressed ? 1 : 3
            )
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
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
