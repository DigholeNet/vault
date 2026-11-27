#if os(macOS)
import AppKit
import SwiftUI
import VaultCore

struct MacosMenuLabel: View {
    @ObservedObject var appData: AppData
    @ObservedObject var config: VaultConfig
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        let title = languageManager.tr(appData.macConnectionPhase.statusTitle(hasProfiles: !config.profiles.isEmpty))
        Label {
            Text(title)
        } icon: {
            Image("MenuIcon").renderingMode(.original)
        }
        .help("Vault · " + title)
        .accessibilityLabel("Vault · " + title)
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

    private static let neutralConnectionTitle = Color(vaultLight: "475569", dark: "F1F5F9")
    private static let connectionControlSurface = Color(vaultLight: "FFFFFF", dark: "2A3045")

    private var phase: VaultConnectionPhase { appData.macConnectionPhase }
    private var noProfile: Bool { phase == .disconnected && config.profiles.isEmpty }
    private var statusTitle: String {
        let key = switch phase {
        case .connected: "Connected"
        case .connecting: "Connecting"
        case .disconnecting: "Disconnecting"
        default: phase.statusTitle(hasProfiles: !config.profiles.isEmpty)
        }
        return languageManager.tr(key)
    }
    private var showsProfileSelector: Bool {
        !config.profiles.isEmpty && (phase == .disconnected || phase == .failed || phase == .permissionRequired)
    }
    private var emphasizesBadge: Bool { phase == .connected || phase == .connecting || phase == .reconnecting }
    private var connectionControlEnabled: Bool {
        phase != .connecting && phase != .disconnecting && appData.canToggleConnection
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                MacosAppIcon(size: 24)
                Text("Vault")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundStyle(VaultTheme.textPrimary)
                Spacer()
                if phase != .failed && phase != .permissionRequired {
                    VaultStatusBadge(title: statusTitle, active: emphasizesBadge)
                }
            }
            Divider().overlay(VaultTheme.outline)

            if showsProfileSelector {
                profileSelector
            }

            connectionHero

            if phase == .connected {
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
                let order = Action.allCases.filter { $0 != .connection || connectionControlEnabled }
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
                if connectionControlEnabled { toggleConnection() }
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
        let connected = phase == .connected
        return VStack(spacing: 0) {
            Text(statusTitle)
                .font(.system(size: 18, weight: .bold))
                .foregroundStyle(connectionTitleColor)
            connectionButton.padding(.top, 12)

            if connected, let since = appData.connectedSince {
                ConnectionDurationView(
                    since: since,
                    size: 26,
                    design: .monospaced,
                    color: VaultTheme.heroText,
                    verticalPadding: 0
                )
                .padding(.top, 10)
            } else if phase.isBusy {
                Text(languageManager.tr(phase == .reconnecting ? "Disconnect" : "Please wait…"))
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(phase == .reconnecting ? VaultTheme.primary : VaultTheme.textSecondary)
                    .accessibilityHidden(phase == .reconnecting)
                    .padding(.top, 10)
            }

            Text(connectionDetail)
                .font(.system(size: 11))
                .foregroundStyle(connected ? VaultTheme.heroSecondary : VaultTheme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 8)
        }
        .multilineTextAlignment(.center)
        .padding(.horizontal, 20)
        .padding(.vertical, 18)
        .frame(minHeight: connected ? 190 : 170, alignment: .top)
        .frame(maxWidth: .infinity)
        .background(connected ? VaultTheme.heroSurface : VaultTheme.surfaceMuted)
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(connected ? Color.clear : VaultTheme.outline)
        }
    }

    private var connectionTitleColor: Color {
        switch phase {
        case .connected: VaultTheme.heroText
        case .connecting, .reconnecting: VaultTheme.textPrimary
        case .disconnected, .disconnecting, .failed, .permissionRequired: Self.neutralConnectionTitle
        }
    }

    private var connectionDetail: String {
        switch phase {
        case .disconnected:
            if let name = config.selectedProfileName { return languageManager.tr("Using profile: %@", name) }
            return languageManager.tr("No server configuration has been added.")
        case .connecting, .reconnecting:
            return languageManager.tr("Establishing a secure tunnel")
        case .connected:
            let action = languageManager.tr("Disconnect")
            return vpnManager.activeProfileName.map { "\($0) · \(action)" } ?? action
        case .disconnecting:
            return languageManager.tr("Closing the secure tunnel")
        case .failed:
            return languageManager.tr(appData.connectionError ?? "Connection failed")
        case .permissionRequired:
            return languageManager.tr(AppData.vpnPermissionError)
        }
    }

    private var connectionButton: some View {
        let title = languageManager.tr(noProfile ? "Add Profile" : appData.connectionActionTitle)
        return Button(action: toggleConnection) {
            VaultConnectionIcon(
                phase: phase, size: 64, symbolSize: 32,
                fill: phase == .connected ? VaultTheme.heroText : Self.connectionControlSurface,
                glyphColor: phase == .connected ? VaultTheme.heroPower : nil,
                showsAddSymbol: noProfile,
                showsProgressRing: true
            )
        }
        .buttonStyle(VaultConnectionPressStyle(showsDisabledAppearance: false))
        .contentShape(.interaction, Circle())
        .disabled(!connectionControlEnabled)
        .help(title)
        .accessibilityLabel(title)
        .accessibilityHidden(phase == .connecting || phase == .disconnecting)
        .macosKeyboardAction(
            focus: $focusedAction,
            id: .connection,
            enabled: connectionControlEnabled,
            circular: true,
            action: toggleConnection
        )
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
                    VaultAddressRow(title: "IPv4", address: ipv4, symbol: "server.rack")
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
                title: "Uplink", symbol: "arrow.up",
                packets: appData.packetsSent, bytes: appData.bytesSent, rate: appData.bytesSentPerSecond
            )
            Divider().frame(height: 88).overlay(VaultTheme.outline)
            VaultTrafficColumn(
                title: "Downlink", symbol: "arrow.down",
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
    var macConnectionPhase: VaultConnectionPhase {
        VaultConnectionPhase(
            status: vpnStatus,
            failed: connectionError != nil,
            permissionRequired: needsVPNPermission,
            recovering: isRecovering
        )
    }

}
#endif
