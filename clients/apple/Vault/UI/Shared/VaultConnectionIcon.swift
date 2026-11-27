import SwiftUI
import VaultCore

enum VaultConnectionPhase: Hashable {
    case disconnected, connecting, connected, disconnecting, reconnecting, failed, permissionRequired

    init(status: VpnStatus, failed: Bool, permissionRequired: Bool = false, recovering: Bool = false) {
        switch status {
        case .disconnected:
            if permissionRequired { self = .permissionRequired }
            else { self = failed ? .failed : .disconnected }
        case .connecting: self = recovering ? .reconnecting : .connecting
        case .connected: self = .connected
        case .disconnecting: self = .disconnecting
        }
    }

    var isBusy: Bool {
        self == .connecting || self == .disconnecting || self == .reconnecting
    }

    func statusTitle(hasProfiles: Bool) -> String {
        switch self {
        case .disconnected: hasProfiles ? "Disconnected" : "No configuration"
        case .connecting: "Connecting…"
        case .connected: "VPN connected"
        case .disconnecting: "Disconnecting…"
        case .reconnecting: "Reconnecting"
        case .failed: "Connection failed"
        case .permissionRequired: "VPN permission required"
        }
    }

    var color: Color {
        switch self {
        case .connected, .connecting, .reconnecting, .disconnected, .disconnecting: VaultTheme.primary
        case .failed: VaultTheme.danger
        case .permissionRequired: VaultTheme.connectionPermission
        }
    }

    var outline: Color {
        switch self {
        case .disconnected, .failed, .permissionRequired: VaultTheme.outline
        default: .clear
        }
    }
}

struct VaultConnectionIcon: View {
    let phase: VaultConnectionPhase
    let size: CGFloat
    let symbolSize: CGFloat
    var fill: Color = VaultTheme.surface
    var glyphColor: Color?
    var showsAddSymbol = false
    var showsProgressRing = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            glyph
                .id(phase)
                .transition(.opacity)
        }
        .frame(width: size, height: size)
        .background(fill, in: Circle())
        .overlay { Circle().strokeBorder(phase.outline) }
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.18), value: phase)
        .contentShape(.interaction, Circle())
    }

    @ViewBuilder private var glyph: some View {
        if phase.isBusy && showsProgressRing {
            TimelineView(.animation(paused: reduceMotion)) { context in
                let angle = context.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 1.2) * 300
                Circle()
                    .trim(from: 0, to: 0.61)
                    .stroke(
                        VaultTheme.primary,
                        style: StrokeStyle(lineWidth: 4, lineCap: .round)
                    )
                    .frame(width: size * 0.66, height: size * 0.66)
                    .rotationEffect(.degrees(reduceMotion ? -90 : angle))
            }
            .accessibilityHidden(true)
        } else if phase.isBusy && !reduceMotion {
            ProgressView()
                .controlSize(size >= 80 ? .large : .regular)
                .tint(phase.color)
                .accessibilityHidden(true)
        } else {
            Image(systemName: symbol)
                .font(.system(size: symbolSize, weight: .medium))
                .foregroundStyle(showsAddSymbol ? VaultTheme.primary : (glyphColor ?? phase.color))
        }
    }

    private var symbol: String {
        if showsAddSymbol { return "plus" }
        return switch phase {
        case .failed: "arrow.clockwise"
        case .permissionRequired: "exclamationmark.shield"
        case .connecting, .disconnecting, .reconnecting: "hourglass"
        case .connected, .disconnected: "power"
        }
    }
}

struct VaultConnectionPressStyle: ButtonStyle {
    var showsDisabledAppearance = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let pressed = configuration.isPressed
        return configuration.label
            .shadow(color: .black.opacity(pressed ? 0.04 : 0.08), radius: pressed ? 2 : 6, y: pressed ? 1 : 3)
            .scaleEffect(pressed && !reduceMotion ? 0.96 : 1)
            .opacity(showsDisabledAppearance && !isEnabled ? 0.6 : 1)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.15), value: pressed)
    }
}
