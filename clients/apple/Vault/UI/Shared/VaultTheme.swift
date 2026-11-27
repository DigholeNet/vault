import SwiftUI
import VaultCore

#if os(iOS)
import UIKit
#else
import AppKit
#endif

enum VaultTheme {
    #if os(macOS)
    static let cardRadius: CGFloat = 14
    static let controlHeight: CGFloat = 36
    static let actionFontSize: CGFloat = 13
    #else
    static let cardRadius: CGFloat = 20
    static let controlHeight: CGFloat = 48
    static let actionFontSize: CGFloat = 15
    #endif

    static let primary = Color(vaultLight: "4F46E5", dark: "A5B4FC")
    static let primaryDark = Color(vaultLight: "3730A3", dark: "C7D2FE")
    static let onPrimary = Color(vaultLight: "FFFFFF", dark: "1E1B4B")
    static let background = Color(vaultLight: "F6F7FB", dark: "0F1220")
    static let surface = Color(vaultLight: "FFFFFF", dark: "171B2E")
    static let surfaceMuted = Color(vaultLight: "EDF0F5", dark: "20253A")
    static let surfaceSubtle = surfaceMuted
    static let indigoSoft = Color(vaultLight: "EEF0FF", dark: "292D55")
    static let textPrimary = Color(vaultLight: "172033", dark: "F1F5F9")
    static let textSecondary = Color(vaultLight: "526078", dark: "A7B0C2")
    static let textDisabled = Color(vaultLight: "8A96A8", dark: "8A96A8")
    static let outline = Color(vaultLight: "DEE2EC", dark: "30374E")
    static let connectionPermission = Color(vaultLight: "A16207", dark: "FACC15")
    static let diagnosticWarning = Color(vaultLight: "92400E", dark: "FCD34D")
    static let danger = Color(vaultLight: "BE123C", dark: "FDA4AF")
    static let failureSurface = Color(vaultLight: "FFF1F2", dark: "3B1D2A")
    static let failureOutline = Color(vaultLight: "FECDD3", dark: "6B2D3F")
    static let heroText = Color(vaultHex: "F1F5F9")
    static let heroSecondary = Color(vaultHex: "D7DFEF")
    static let heroPower = Color(vaultHex: "4F46E5")
    static let heroSurface = Color(vaultLight: "18244D", dark: "25355F")
    static let fieldSurface = Color(vaultLight: "FAFAFD", dark: "20253A")
    static let fieldOutline = Color(vaultLight: "748199", dark: "838FA9")
}

extension Color {
    init(vaultHex hex: String) {
        let value = UInt64(hex, radix: 16) ?? 0
        self.init(
            .sRGB,
            red: Double((value >> 16) & 0xFF) / 255,
            green: Double((value >> 8) & 0xFF) / 255,
            blue: Double(value & 0xFF) / 255,
            opacity: 1
        )
    }

    init(vaultLight light: String, dark: String) {
        #if os(iOS)
        self.init(uiColor: UIColor { traits in
            UIColor(Color(vaultHex: traits.userInterfaceStyle == .dark ? dark : light))
        })
        #else
        self.init(nsColor: NSColor(name: nil) { appearance in
            let darkAppearance = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            return NSColor(Color(vaultHex: darkAppearance ? dark : light))
        })
        #endif
    }
}

struct VaultCardModifier: ViewModifier {
    let padding: CGFloat
    let cornerRadius: CGFloat

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(VaultTheme.surface, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .strokeBorder(VaultTheme.outline, lineWidth: 1)
            }
    }
}

extension View {
    func vaultCard(padding: CGFloat = 16, cornerRadius: CGFloat = VaultTheme.cardRadius) -> some View {
        modifier(VaultCardModifier(padding: padding, cornerRadius: cornerRadius))
    }

    func vaultScreenBackground() -> some View {
        background(VaultTheme.background.ignoresSafeArea())
    }

    func vaultLogClearConfirmation(isPresented: Binding<Bool>, onClear: @escaping () -> Void) -> some View {
        modifier(VaultLogClearConfirmation(isPresented: isPresented, onClear: onClear))
    }
}

private struct VaultLogClearConfirmation: ViewModifier {
    @EnvironmentObject private var languageManager: LanguageManager
    @Binding var isPresented: Bool
    let onClear: () -> Void

    func body(content: Content) -> some View {
        content.alert(languageManager.tr("Clear runtime logs?"), isPresented: $isPresented) {
            Button(languageManager.tr("Clear"), role: .destructive, action: onClear)
            Button(languageManager.tr("Cancel"), role: .cancel) {}
        } message: {
            Text(languageManager.tr("This clears all runtime logs."))
        }
    }
}

struct VaultPageHeader: View {
    let title: String
    let subtitle: String
    @ScaledMetric(relativeTo: .title) private var titleSize = 28.0

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: titleSize, weight: .bold))
                .foregroundStyle(VaultTheme.textPrimary)
            if !subtitle.isEmpty {
                Text(subtitle)
                    .font(.footnote)
                    .foregroundStyle(VaultTheme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct VaultStatusBadge: View {
    let title: String
    var active = false
    var failure = false
    @ScaledMetric(relativeTo: .caption) private var titleSize = 12.0

    var body: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(failure ? VaultTheme.danger : (active ? VaultTheme.primary : VaultTheme.textDisabled))
                .frame(width: 6, height: 6)
            Text(title)
                .font(.system(size: titleSize, weight: .semibold))
                .fixedSize(horizontal: false, vertical: true)
        }
        .foregroundStyle(failure ? VaultTheme.danger : (active ? VaultTheme.primaryDark : VaultTheme.textSecondary))
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(
            failure ? VaultTheme.failureSurface : (active ? VaultTheme.indigoSoft : VaultTheme.surfaceSubtle),
            in: Capsule()
        )
        .accessibilityElement(children: .combine)
    }
}

struct VaultIconTile: View {
    let systemName: String
    var size: CGFloat = 44
    var emphasized = true

    var body: some View {
        Image(systemName: systemName)
            .font(.system(size: size * 0.45, weight: .medium))
            .foregroundStyle(emphasized ? VaultTheme.primary : VaultTheme.textSecondary)
            .frame(width: size, height: size)
            .background(emphasized ? VaultTheme.indigoSoft : VaultTheme.surfaceMuted, in: RoundedRectangle(cornerRadius: size * 0.32, style: .continuous))
            .accessibilityHidden(true)
    }
}

struct VaultStatusIcon: View {
    enum Kind: String {
        case passed = "VaultStatusPassed"
        case failed = "VaultStatusFailed"
        case skipped = "VaultStatusSkipped"
    }

    let kind: Kind
    let size: CGFloat

    var body: some View {
        Image(kind.rawValue)
            .renderingMode(.template)
            .resizable()
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

struct VaultSection<Content: View>: View {
    let title: String
    let padding: CGFloat
    let spacing: CGFloat
    @ViewBuilder let content: Content

    init(_ title: String, padding: CGFloat = 16, spacing: CGFloat = 12, @ViewBuilder content: () -> Content) {
        self.title = title
        self.padding = padding
        self.spacing = spacing
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: spacing) {
            Text(title)
                .font(.subheadline.bold())
                .foregroundStyle(VaultTheme.textPrimary)
            content
        }
        .vaultCard(padding: padding)
    }
}

struct VaultInfoCallout: View {
    let title: String
    let detail: String
    @ScaledMetric(relativeTo: .footnote) private var titleSize = 13.0
    @ScaledMetric(relativeTo: .caption) private var detailSize = 12.0

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "info.circle")
                .font(.system(size: 18))
                .foregroundStyle(VaultTheme.textSecondary)
                .frame(width: 30, height: 30)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.system(size: titleSize, weight: .bold))
                Text(detail).font(.system(size: detailSize)).foregroundStyle(VaultTheme.textSecondary)
            }
            .foregroundStyle(VaultTheme.textPrimary)
        }
        .vaultCard(padding: 18)
    }
}

struct VaultPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @ScaledMetric(relativeTo: .body) private var labelSize = VaultTheme.actionFontSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: labelSize, weight: .semibold))
            .foregroundStyle(VaultTheme.onPrimary)
            .frame(maxWidth: .infinity, minHeight: VaultTheme.controlHeight)
            .background(VaultTheme.primary, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .opacity(isEnabled ? (configuration.isPressed ? 0.78 : 1) : 0.45)
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.985 : 1)
    }
}

struct VaultSecondaryButtonStyle: ButtonStyle {
    var isDestructive = false
    var isPending = false
    @Environment(\.isEnabled) private var isEnabled
    @ScaledMetric(relativeTo: .body) private var labelSize = VaultTheme.actionFontSize

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: labelSize, weight: .semibold))
            .foregroundStyle(isPending ? VaultTheme.textSecondary : (isDestructive ? VaultTheme.danger : VaultTheme.primaryDark))
            .frame(maxWidth: .infinity, minHeight: VaultTheme.controlHeight)
            .background(isPending ? VaultTheme.surfaceMuted : (isDestructive ? VaultTheme.failureSurface : VaultTheme.indigoSoft), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .opacity(isEnabled || isPending ? (configuration.isPressed ? 0.7 : 1) : 0.45)
    }
}

struct VaultAddressRow: View {
    let title: String
    let address: String
    let symbol: String
    var color: Color = VaultTheme.textSecondary
    var stacked = false
    @ScaledMetric(relativeTo: .caption) private var textSize = 12.0

    var body: some View {
        if stacked {
            VStack(alignment: .leading, spacing: 6) {
                label
                value
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            HStack(alignment: .top, spacing: 10) {
                label
                Spacer(minLength: 8)
                value.multilineTextAlignment(.trailing)
            }
        }
    }

    private var label: some View {
        Label {
            Text(verbatim: title).font(.system(size: textSize)).foregroundStyle(VaultTheme.textSecondary)
        } icon: {
            Image(systemName: symbol).font(.system(size: 14)).foregroundStyle(color)
                .frame(width: 18).accessibilityHidden(true)
        }
    }

    private var value: some View {
        Text(verbatim: address)
            .font(.system(size: textSize, design: .monospaced))
            .foregroundStyle(VaultTheme.textPrimary)
            .textSelection(.enabled)
    }
}

struct VaultTrafficColumn: View {
    let title: String
    let symbol: String
    let packets: UInt64
    let bytes: UInt64
    let rate: UInt64
    var spacing: CGFloat = 7
    @EnvironmentObject var languageManager: LanguageManager
    @ScaledMetric(relativeTo: .body) private var rateSize = 17.0
    @ScaledMetric(relativeTo: .caption) private var detailSize = 12.0

    var body: some View {
        VStack(spacing: spacing) {
            HStack(spacing: 6) {
                Image(systemName: symbol).foregroundStyle(VaultTheme.textSecondary)
                Text(languageManager.tr(title))
                    .font(.system(size: detailSize))
                    .foregroundStyle(VaultTheme.textSecondary)
            }
            Text(PacketStats.formatBytes(rate) + "/s")
                .font(.system(size: rateSize, weight: .bold, design: .monospaced))
                .foregroundStyle(VaultTheme.textPrimary)
            Text(PacketStats.formatBytes(bytes))
                .font(.system(size: detailSize))
                .monospacedDigit()
                .foregroundStyle(VaultTheme.textSecondary)
            Text(languageManager.tr("Packets") + " \(packets)")
                .font(.system(size: detailSize))
                .monospacedDigit()
                .foregroundStyle(VaultTheme.textSecondary)
        }
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
    }
}
