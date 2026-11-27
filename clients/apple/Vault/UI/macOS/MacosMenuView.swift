#if os(macOS)
import AppKit
import SwiftUI
import VaultCore

struct MacosMenuLabel: View {
    @ObservedObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        Label {
            Text(languageManager.tr(appData.macStatusTitle))
        } icon: {
            Image("MenuIcon").renderingMode(.original)
        }
        .help("Vault · " + languageManager.tr(appData.macStatusTitle))
        .accessibilityLabel("Vault · " + languageManager.tr(appData.macStatusTitle))
        .onChange(of: languageManager.language) { _, _ in WindowManager.shared.refreshTitles() }
    }
}

struct MacosMenuView: View {
    let vpnManager: VpnManager
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var config: VaultConfig
    @EnvironmentObject var languageManager: LanguageManager
    @Environment(\.dismiss) private var dismiss
    @State private var pendingProfileSwitch: String?
    private enum Action: CaseIterable { case connection, settings, diagnostics, quit }
    @State private var focusedAction: Action?

    private var active: Bool { appData.vpnStatus != .disconnected }
    private var failed: Bool { appData.vpnStatus == .disconnected && appData.connectionError != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                MacosAppIcon(size: 24)
                Text("Vault")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundStyle(VaultTheme.textPrimary)
                Spacer()
                if !failed {
                    VaultStatusBadge(title: languageManager.tr(appData.macStatusTitle), active: active)
                }
            }
            Divider().overlay(VaultTheme.outline)

            if !active, !config.profiles.isEmpty {
                profileSelector
            }

            connectionHero
                .padding(.top, active ? 8 : 0)

            if appData.vpnStatus == .connected || appData.isRecovering {
                sessionAddresses
                traffic
            }

            Divider().overlay(VaultTheme.outline)
            HStack(spacing: 0) {
                Button { open("configure") } label: {
                    footerLabel("Settings", symbol: "gearshape")
                }
                .keyboardShortcut(",")
                .macosKeyboardAction(focus: $focusedAction, id: .settings) { open("configure") }
                Divider().frame(height: 22)
                Button { open("status") } label: {
                    footerLabel("Diagnostics", symbol: "waveform.path.ecg")
                }
                .macosKeyboardAction(focus: $focusedAction, id: .diagnostics) { open("status") }
                Divider().frame(height: 22)
                Button {
                    dismiss()
                    NSApp.terminate(nil)
                } label: {
                    footerLabel("Quit", symbol: "power")
                }
                .keyboardShortcut("q")
                .macosKeyboardAction(focus: $focusedAction, id: .quit) {
                    dismiss()
                    NSApp.terminate(nil)
                }
            }
            .buttonStyle(.plain)
            .font(.system(size: 12))
            .foregroundStyle(VaultTheme.textSecondary)
        }
        .font(.body)
        .padding(14)
        .frame(width: 340)
        .fixedSize(horizontal: false, vertical: true)
        .background(VaultTheme.background)
        .macosKeyboardNavigation { [focus = $focusedAction] event in
            if event.type == .leftMouseDown {
                focus.wrappedValue = nil
                return false
            }
            let modifiers = event.modifierFlags.intersection([.command, .control, .option, .shift])
            if event.keyCode == 48, modifiers.subtracting(.shift).isEmpty {
                let order = Action.allCases.filter { $0 != .connection || appData.canToggleConnection }
                if let current = focus.wrappedValue, let index = order.firstIndex(of: current) {
                    focus.wrappedValue = order[(index + (modifiers.contains(.shift) ? order.count - 1 : 1)) % order.count]
                } else {
                    focus.wrappedValue = modifiers.contains(.shift) ? order.last : order.first
                }
                event.window?.makeFirstResponder(nil)
                return true
            }
            if event.keyCode == 53, modifiers.isEmpty {
                dismiss()
                return true
            }
            guard modifiers.isEmpty, !event.isARepeat, [36, 49, 76].contains(event.keyCode),
                  let selected = focus.wrappedValue else { return false }
            switch selected {
            case .connection:
                if appData.canToggleConnection { toggleConnection() }
            case .diagnostics: open("status")
            case .settings: open("configure")
            case .quit:
                dismiss()
                NSApp.terminate(nil)
            }
            return true
        }
        .onExitCommand { dismiss() }
        .onAppear { focusedAction = nil }
        .onChange(of: appData.showConfigureGuide) { _, show in
            if show {
                appData.showConfigureGuide = false
                open("configure")
            }
        }
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

    private var profileSelector: some View {
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
                Image(systemName: "server.rack").foregroundStyle(VaultTheme.primary)
                Text(config.selectedProfileName ?? "")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(VaultTheme.textPrimary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Text(languageManager.tr("Switch Profile"))
                    .font(.system(size: 10))
                    .foregroundStyle(VaultTheme.textDisabled)
                Image(systemName: "chevron.right")
                    .font(.system(size: 10))
                    .foregroundStyle(VaultTheme.textDisabled)
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 52)
            .contentShape(Rectangle())
            .background(VaultTheme.surface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(VaultTheme.outline)
            }
        }
        .menuStyle(.borderlessButton)
        .disabled(appData.switchingProfileName != nil || appData.vpnStatus == .disconnecting)
    }

    private var connectionHero: some View {
        VStack(spacing: 0) {
            Text(languageManager.tr(appData.macStatusTitle))
                .font(.system(size: 18, weight: .bold))
                .foregroundStyle(active ? VaultTheme.heroText : VaultTheme.textSecondary)
            connectionButton.padding(.top, active ? 8 : 16)

            if active {
                activeConnectionDetails
            } else {
                inactiveConnectionDetails
            }
        }
        .padding(.horizontal, active ? 10 : 20)
        .padding(.top, active ? 16 : 20)
        .padding(.bottom, active ? 10 : 20)
        .frame(minHeight: active ? 190 : 286, alignment: .top)
        .frame(maxWidth: .infinity)
        .background {
            if active {
                VaultHeroBackground()
            } else {
                VaultTheme.surfaceMuted
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .strokeBorder(active ? Color.clear : VaultTheme.outline)
        }
    }

    @ViewBuilder
    private var activeConnectionDetails: some View {
        if let since = appData.connectedSince,
           appData.vpnStatus == .connected || (appData.vpnStatus == .connecting && appData.isRecovering) {
            ConnectionDurationView(since: since)
                .font(.system(size: 24, weight: .light, design: .monospaced))
                .foregroundStyle(VaultTheme.heroText)
                .padding(.top, 6)
        }
        if appData.isRecovering {
            Text(languageManager.tr("Network changed. Reconnecting…"))
                .font(.system(size: 11))
                .foregroundStyle(VaultTheme.heroSecondary)
                .padding(.top, 4)
        } else if let error = appData.connectionError {
            Text(languageManager.tr(error))
                .font(.system(size: 11))
                .foregroundStyle(VaultTheme.heroSecondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 4)
        } else if let running = appData.runningProfileName {
            Text("\(running) · " + languageManager.tr("Tap to disconnect"))
                .font(.system(size: 11))
                .foregroundStyle(VaultTheme.heroSecondary)
                .padding(.top, 4)
        }
    }

    @ViewBuilder
    private var inactiveConnectionDetails: some View {
        Text(languageManager.tr(appData.connectionError ??
            "Establish an encrypted tunnel for secure access to your private network"))
            .font(.system(size: 11))
            .foregroundStyle(VaultTheme.textSecondary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 12)
        Button(action: toggleConnection) {
            Label(
                languageManager.tr(appData.connectionActionTitle),
                systemImage: failed && !appData.needsVPNPermission ? "arrow.clockwise" : "power"
            )
        }
        .buttonStyle(VaultPrimaryButtonStyle())
        .frame(width: 140)
        .padding(.top, 12)
        .disabled(!appData.canToggleConnection)
        .help(languageManager.tr(appData.connectionActionTitle))
        .accessibilityLabel(languageManager.tr(appData.connectionActionTitle))
        .macosKeyboardAction(
            focus: $focusedAction,
            id: .connection,
            enabled: appData.canToggleConnection,
            action: toggleConnection
        )
    }

    private var connectionButton: some View {
        let phase = VaultConnectionPhase(
            status: appData.vpnStatus,
            failed: failed,
            permissionRequired: appData.needsVPNPermission,
            recovering: appData.isRecovering
        )
        let enabled = active && appData.canToggleConnection
        return Button(action: toggleConnection) {
            VaultConnectionIcon(phase: phase, size: active ? 56 : 64, symbolSize: 28)
        }
        .buttonStyle(VaultConnectionPressStyle(showsDisabledAppearance: active))
        .contentShape(.interaction, Circle())
        .disabled(!enabled)
        .allowsHitTesting(active)
        .help(languageManager.tr(appData.connectionActionTitle))
        .accessibilityLabel(languageManager.tr(appData.connectionActionTitle))
        .macosKeyboardAction(
            focus: Binding(
                get: { active ? focusedAction : nil },
                set: { focusedAction = $0 }
            ),
            id: .connection,
            enabled: enabled,
            circular: true,
            action: toggleConnection
        )
        .accessibilityHidden(!active)
    }

    private func footerLabel(_ title: String, symbol: String) -> some View {
        Label(languageManager.tr(title), systemImage: symbol)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
    }

    @ViewBuilder
    private var sessionAddresses: some View {
        let addresses = appData.assignedIp.parsedIPv4AndIPv6()
        if !appData.publicIp.isEmpty || addresses.ipv4 != nil || addresses.ipv6 != nil {
            VStack(spacing: 12) {
                if !appData.publicIp.isEmpty {
                    VaultAddressRow(title: "WAN", address: appData.publicIp, symbol: "globe")
                }
                if !appData.publicIp.isEmpty, addresses.ipv4 != nil || addresses.ipv6 != nil {
                    Divider().overlay(VaultTheme.outline)
                }
                if let ipv4 = addresses.ipv4 {
                    VaultAddressRow(title: "IPv4", address: ipv4, symbol: "server.rack", color: VaultTheme.downlink)
                }
                if let ipv6 = addresses.ipv6 {
                    VaultAddressRow(title: "IPv6", address: ipv6, symbol: "server.rack")
                }
            }
            .vaultCard(padding: 14)
        }
    }

    private var traffic: some View {
        HStack(spacing: 0) {
            VaultTrafficColumn(
                title: "Uplink", symbol: "arrow.up", color: VaultTheme.primary,
                packets: appData.packetsSent, bytes: appData.bytesSent, rate: appData.bytesSentPerSecond
            )
            Divider().frame(height: 88).overlay(VaultTheme.outline)
            VaultTrafficColumn(
                title: "Downlink", symbol: "arrow.down", color: VaultTheme.downlink,
                packets: appData.packetsReceived, bytes: appData.bytesReceived, rate: appData.bytesReceivedPerSecond
            )
        }
        .transaction { $0.animation = nil }
        .vaultCard(padding: 14)
    }

    private func toggleConnection() {
        vpnManager.toggleConnection { open("configure") }
    }

    private func open(_ id: String) {
        dismiss()
        WindowManager.shared.showWindow(withIdentifier: id)
    }
}

struct MacosStatusAddressRow: View {
    let title: String
    let address: String
    let symbol: String
    let color: Color

    var body: some View {
        VaultAddressRow(title: title, address: address, symbol: symbol, color: color)
    }
}

extension AppData {
    var macStatusTitle: String {
        if isRecovering { return "Reconnecting" }
        if needsVPNPermission { return "VPN permission required" }
        if connectionError != nil && vpnStatus == .disconnected { return "Connection failed" }
        return VpnStatusUtil.titleKey(for: vpnStatus)
    }

    var macStatusColor: Color {
        if isRecovering { return .orange }
        if vpnStatus == .connected { return VaultTheme.primary }
        if needsVPNPermission { return VaultTheme.connectionPermission }
        if connectionError != nil && vpnStatus == .disconnected { return VaultTheme.danger }
        return VaultTheme.textDisabled
    }
}
#endif
