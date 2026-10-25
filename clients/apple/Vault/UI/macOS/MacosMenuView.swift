#if os(macOS)
import AppKit
import SwiftUI
import VaultCore

/// The label is observed separately so the menu bar updates while the popover is closed.
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
    @State private var hoveringConnection = false
    private enum Action: CaseIterable { case connection, settings, diagnostics, quit }
    @State private var focusedAction: Action?

    var body: some View {
        VStack(alignment: .leading, spacing: appData.vpnStatus == .disconnected ? 8 : 12) {
            HStack(spacing: 8) {
                MacosAppIcon(size: 20)
                Text("Vault").font(.body.weight(.semibold))
                Spacer()
                if appData.vpnStatus == .connecting || appData.vpnStatus == .disconnecting {
                    ProgressView().controlSize(.mini)
                } else {
                    Circle().fill(appData.macStatusColor).frame(width: 7, height: 7)
                }
                Text(languageManager.tr(appData.macStatusTitle)).font(.body)
                    .foregroundStyle(.secondary)
            }
            Divider()
            connectionButton
            if let since = appData.connectedSince,
               appData.vpnStatus == .connected || (appData.vpnStatus == .connecting && appData.isRecovering) {
                ConnectionDurationView(since: since)
            }
            if appData.isRecovering {
                Text(languageManager.tr("Network changed. Reconnecting…"))
                    .font(.body).foregroundStyle(.primary.opacity(0.8))
            } else if let error = appData.connectionError {
                Text(languageManager.tr(error)).font(.body).foregroundStyle(.primary.opacity(0.8))
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
            // Never show stale counters while disconnected or establishing a new session.
            if appData.vpnStatus == .connected || appData.isRecovering {
                Divider()
                traffic
            }
            Divider()
            HStack(spacing: 0) {
                Button { open("configure") } label: {
                    footerLabel("Settings", symbol: "gearshape")
                }.keyboardShortcut(",")
                    .macosKeyboardAction(focus: $focusedAction, id: .settings) { open("configure") }
                Divider().frame(height: 16)
                Button { open("status") } label: {
                    footerLabel("Diagnostics", symbol: "stethoscope")
                }
                .macosKeyboardAction(focus: $focusedAction, id: .diagnostics) { open("status") }
                Divider().frame(height: 16)
                Button {
                    dismiss()
                    NSApp.terminate(nil)
                } label: {
                    footerLabel("Quit", symbol: "power")
                }.keyboardShortcut("q")
                    .macosKeyboardAction(focus: $focusedAction, id: .quit) { dismiss()
                        NSApp.terminate(nil)
                    }
            }
            .buttonStyle(.plain).font(.body).foregroundStyle(.primary)
        }
        .font(.body)
        .padding(.horizontal, 14)
        .padding(.vertical, appData.vpnStatus == .disconnected ? 12 : 14)
        .frame(width: 340)
        .fixedSize(horizontal: false, vertical: true)
        .macosKeyboardNavigation { [focus = $focusedAction] event in
            if event.type == .leftMouseDown { focus.wrappedValue = nil
                return false
            }
            let modifiers = event.modifierFlags.intersection([.command, .control, .option, .shift])
            if event.keyCode == 48, modifiers.subtracting(.shift).isEmpty {
                let order = Action.allCases.filter { $0 != .connection || appData.canToggleConnection }
                if let current = focus.wrappedValue, let index = order.firstIndex(of: current) {
                    focus.wrappedValue = order[(index + (modifiers.contains(.shift) ? order.count - 1 : 1)) % order.count]
                } else { focus.wrappedValue = modifiers.contains(.shift) ? order.last : order.first }
                event.window?.makeFirstResponder(nil)
                return true
            }
            if event.keyCode == 53, modifiers.isEmpty { dismiss()
                return true
            }
            guard modifiers.isEmpty, !event.isARepeat, [36, 49, 76].contains(event.keyCode),
                  let selected = focus.wrappedValue else { return false }
            switch selected {
            case .connection:
                if appData.canToggleConnection { toggleConnection() }
            case .diagnostics: open("status")
            case .settings: open("configure")
            case .quit: dismiss()
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
    }

    private var connectionButton: some View {
        HStack(spacing: 0) {
            Spacer(minLength: 0)
            Button(action: toggleConnection) {
                ZStack {
                    Circle()
                        .fill(connectionColor.opacity(hoveringConnection ? 0.1 : 0.04))
                        .overlay(Circle().strokeBorder(connectionColor.opacity(hoveringConnection ? 0.25 : 0.1)))
                        .shadow(color: Color.black.opacity(hoveringConnection ? 0.16 : 0), radius: 8, y: 4)
                    Image(systemName: appData.vpnStatus == .disconnected ? "personalhotspot.slash" : "personalhotspot")
                        .font(.system(size: 48, weight: .regular))
                        .foregroundStyle(connectionColor)
                    if appData.vpnStatus == .connecting || appData.vpnStatus == .disconnecting {
                        ProgressView().controlSize(.small)
                            .padding(5).background(.regularMaterial, in: Circle()).offset(x: 30, y: 30)
                    }
                }
                .frame(width: 88, height: 88)
                .contentShape(.interaction, Circle())
            }
            .buttonStyle(.plain)
            .frame(width: 88, height: 88)
            .contentShape(.interaction, Circle())
            .onContinuousHover { phase in
                switch phase {
                case .active(let point):
                    let dx = point.x - 44
                    let dy = point.y - 44
                    hoveringConnection = dx * dx + dy * dy <= 44 * 44
                case .ended:
                    hoveringConnection = false
                }
            }
            .animation(.easeOut(duration: 0.15), value: hoveringConnection)
            .disabled(!appData.canToggleConnection)
            .help(languageManager.tr(actionTitle))
            .accessibilityLabel(languageManager.tr(actionTitle))
            .macosKeyboardAction(
                focus: $focusedAction,
                id: .connection,
                enabled: appData.canToggleConnection,
                circular: true,
                action: toggleConnection
            )
            Spacer(minLength: 0)
        }
        .padding(.vertical, 8)
    }

    private var connectionColor: Color {
        if appData.isRecovering { return .orange }
        switch appData.vpnStatus {
        case .connected: return .green
        case .connecting: return .accentColor
        case .disconnecting: return .secondary
        case .disconnected: return .red
        }
    }

    private func footerLabel(_ title: String, symbol: String) -> some View {
        Label(languageManager.tr(title), systemImage: symbol)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 7)
            .contentShape(Rectangle())
    }

    private var actionTitle: String {
        switch appData.vpnStatus {
        case .connected: return "Disconnect"
        case .connecting: return appData.isRecovering ? "Disconnect" : "Cancel Connection"
        case .disconnecting: return appData.connectionError == nil ? "Disconnecting…" : "Disconnect"
        case .disconnected: return appData.connectionError == nil ? "Connect" : "Retry"
        }
    }

    private var traffic: some View {
        // Explicit cell widths keep live values from redistributing the grid.
        // All values use the same font; large counters wrap instead of scaling.
        Grid(alignment: .trailing, horizontalSpacing: 8, verticalSpacing: 2) {
            GridRow {
                Color.clear.frame(width: 72, height: 24)
                trafficHeading("Uplink", symbol: "arrow.up.circle.fill", color: .blue)
                trafficHeading("Downlink", symbol: "arrow.down.circle.fill", color: .green)
            }
            GridRow {
                trafficLabel("VPN Rate")
                trafficValue(PacketStats.formatBytes(appData.bytesSentPerSecond) + "/s")
                trafficValue(PacketStats.formatBytes(appData.bytesReceivedPerSecond) + "/s")
            }
            GridRow {
                trafficLabel("VPN Traffic")
                trafficValue(PacketStats.formatBytes(appData.bytesSent))
                trafficValue(PacketStats.formatBytes(appData.bytesReceived))
            }
            GridRow {
                trafficLabel("Packets")
                trafficValue(String(appData.packetsSent))
                trafficValue(String(appData.packetsReceived))
            }
        }
        .font(.system(size: NSFont.systemFontSize))
        .transaction { $0.animation = nil }
        .frame(maxWidth: .infinity)
    }

    private func trafficHeading(_ title: String, symbol: String, color: Color) -> some View {
        HStack(spacing: 4) {
            Image(systemName: symbol).foregroundStyle(color)
            Text(languageManager.tr(title)).foregroundStyle(.secondary)
        }
        .frame(width: 100, height: 24, alignment: .trailing)
    }

    private func trafficLabel(_ title: String) -> some View {
        Text(languageManager.tr(title))
            .foregroundStyle(.secondary)
            .frame(width: 72, height: 34, alignment: .leading)
    }

    private func trafficValue(_ value: String) -> some View {
        Text(verbatim: value)
            .monospacedDigit()
            .lineLimit(2)
            .multilineTextAlignment(.trailing)
            .frame(width: 100, height: 34, alignment: .trailing)
    }

    private func toggleConnection() {
        if appData.vpnStatus == .connected || appData.vpnStatus == .connecting || appData.vpnStatus == .disconnecting {
            vpnManager.disconnect()
        } else {
            if config.host.isEmpty || config.password.isEmpty { open("configure")
                return
            }
            vpnManager.connect()
        }
    }

    private func open(_ id: String) { dismiss()
        WindowManager.shared.showWindow(withIdentifier: id)
    }
}

extension AppData {
    var macStatusTitle: String {
        if isRecovering { return "Reconnecting" }
        if connectionError != nil && vpnStatus == .disconnected { return "Connection failed" }
        return VpnStatusUtil.titleKey(for: vpnStatus)
    }

    var macStatusColor: Color {
        if isRecovering { return .orange }
        if vpnStatus == .connected { return .green }
        if connectionError != nil && vpnStatus == .disconnected { return .red }
        return .secondary
    }
}
#endif
