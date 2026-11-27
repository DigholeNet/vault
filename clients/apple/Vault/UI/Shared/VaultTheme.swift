import SwiftUI
import VaultCore

#if os(iOS)
import UIKit
#else
import AppKit
#endif

enum VaultTheme {
    static let primary = Color(vaultLight: "4F46E5", dark: "A5B4FC")
    static let downlink = Color(vaultLight: "2563EB", dark: "7DA7FF")
    static let primaryDark = Color(vaultLight: "3730A3", dark: "C7D2FE")
    static let onPrimary = Color(vaultLight: "FFFFFF", dark: "1E1B4B")
    static let background = Color(vaultLight: "F6F7FB", dark: "0F1220")
    static let surface = Color(vaultLight: "FFFFFF", dark: "171B2E")
    static let surfaceMuted = Color(vaultLight: "EDF0F5", dark: "20253A")
    static let surfaceSubtle = Color(vaultLight: "F0F2F8", dark: "20253A")
    static let indigoSoft = Color(vaultLight: "E9E9FF", dark: "292D55")
    static let textPrimary = Color(vaultLight: "172033", dark: "F1F5F9")
    static let textSecondary = Color(vaultLight: "64748B", dark: "A7B0C2")
    static let textDisabled = Color(vaultLight: "8A96A8", dark: "8A96A8")
    static let outline = Color(vaultLight: "DEE2EC", dark: "30374E")
    static let connectionPermission = Color(vaultLight: "A16207", dark: "FACC15")
    static let danger = Color(vaultLight: "DC4655", dark: "FDA4AF")
    static let failureSurface = Color(vaultLight: "FFF1F2", dark: "3B1D2A")
    static let failureOutline = Color(vaultLight: "FECDD3", dark: "6B2D3F")
    static let heroText = Color(vaultHex: "F8FAFF")
    static let heroSecondary = Color(vaultHex: "C7D2FE")
    static let heroPower = Color(vaultHex: "4F46E5")
    static let heroGradient = LinearGradient(
        colors: [Color(vaultHex: "343B91"), Color(vaultHex: "18244D")],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )
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
    var padding: CGFloat = 16
    var cornerRadius: CGFloat = 20

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
    func vaultCard(padding: CGFloat = 16, cornerRadius: CGFloat = 20) -> some View {
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
            Text(subtitle)
                .font(.footnote)
                .foregroundStyle(VaultTheme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
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

    var body: some View {
        Image(systemName: systemName)
            .font(.system(size: size * 0.45, weight: .medium))
            .foregroundStyle(VaultTheme.primary)
            .frame(width: size, height: size)
            .background(VaultTheme.indigoSoft, in: RoundedRectangle(cornerRadius: size * 0.32, style: .continuous))
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
                .foregroundStyle(VaultTheme.primary)
                .frame(width: 30, height: 30)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.system(size: titleSize, weight: .bold))
                Text(detail).font(.system(size: detailSize)).foregroundStyle(VaultTheme.textSecondary)
            }
            .foregroundStyle(VaultTheme.primaryDark)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VaultTheme.indigoSoft, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

struct VaultPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(VaultTheme.onPrimary)
            .frame(maxWidth: .infinity, minHeight: 48)
            .background(VaultTheme.primary, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .opacity(isEnabled ? (configuration.isPressed ? 0.78 : 1) : 0.45)
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.985 : 1)
    }
}

struct VaultSecondaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(VaultTheme.primaryDark)
            .frame(maxWidth: .infinity, minHeight: 44)
            .background(VaultTheme.indigoSoft, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .opacity(isEnabled ? (configuration.isPressed ? 0.7 : 1) : 0.45)
    }
}

struct VaultAddressRow: View {
    let title: String
    let address: String
    let symbol: String
    var color: Color = VaultTheme.primary
    @ScaledMetric(relativeTo: .caption) private var textSize = 12.0

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 14))
                .foregroundStyle(color)
                .frame(width: 18)
                .accessibilityHidden(true)
            Text(verbatim: title)
                .font(.system(size: textSize))
                .foregroundStyle(VaultTheme.textSecondary)
            Spacer(minLength: 8)
            Text(verbatim: address)
                .font(.system(size: textSize, design: .monospaced))
                .foregroundStyle(VaultTheme.textPrimary)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }
}

struct VaultTrafficColumn: View {
    let title: String
    let symbol: String
    let color: Color
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
                Image(systemName: symbol).foregroundStyle(color)
                Text(languageManager.tr(title))
                    .font(.system(size: detailSize))
                    .foregroundStyle(VaultTheme.textSecondary)
            }
            Text(PacketStats.formatBytes(rate) + "/s")
                .font(.system(size: rateSize, weight: .bold, design: .monospaced))
                .foregroundStyle(color)
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

struct VaultHeroBackground: View {
    var showsDecoration = true
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        if colorScheme == .dark {
            Color(vaultHex: "312E81")
        } else {
            VaultTheme.heroGradient.overlay {
                if showsDecoration { VaultHeroDecoration() }
            }
        }
    }
}

private struct VaultHeroDecoration: View {
    var body: some View {
        ZStack {
            Circle()
                .stroke(VaultTheme.heroSecondary.opacity(0.09), lineWidth: 26)
                .frame(width: 184, height: 184)
                .offset(x: 150, y: -90)
            Circle()
                .stroke(VaultTheme.heroSecondary.opacity(0.06), lineWidth: 22)
                .frame(width: 140, height: 140)
                .offset(x: -155, y: 120)
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}
