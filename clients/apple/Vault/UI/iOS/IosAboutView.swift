import SwiftUI

#if os(iOS)
struct IosAboutView: View {
    @EnvironmentObject var languageManager: LanguageManager

    private var appIcon: UIImage? {
        let icons = Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any]
        let primary = icons?["CFBundlePrimaryIcon"] as? [String: Any]
        let names = primary?["CFBundleIconFiles"] as? [String] ?? []
        return names.reversed().compactMap { UIImage(named: $0) }.first
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                VaultPageHeader(
                    title: languageManager.tr("About"),
                    subtitle: languageManager.tr("Private, secure, open source.")
                )

                ZStack {
                    VaultHeroBackground()
                    VStack(spacing: 0) {
                        if let icon = appIcon {
                            Image(uiImage: icon)
                                .resizable().scaledToFit().frame(width: 96, height: 96)
                                .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
                                .accessibilityHidden(true)
                        }
                        Text("Vault")
                            .font(.system(size: 34, weight: .bold))
                            .foregroundStyle(VaultTheme.heroText)
                            .padding(.top, 18)
                        Text(languageManager.tr(
                            "Version %@ · BUILD %@",
                            Bundle.main.appVersionShort,
                            Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
                        ))
                        .font(.system(size: 11))
                        .foregroundStyle(VaultTheme.heroSecondary)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 8)
                        .background(Color.white.opacity(0.1), in: Capsule())
                        .padding(.top, 20)
                    }
                    .padding(28)
                }
                .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))

                VStack(spacing: 18) {
                    Text(languageManager.tr("A secure VPN client for cross-regional connectivity."))
                        .font(.system(size: 14))
                        .foregroundStyle(VaultTheme.textPrimary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(languageManager.tr("Encrypted connections with automatic path discovery."))
                        .font(.system(size: 12))
                        .foregroundStyle(VaultTheme.textSecondary)
                    Link(destination: URL(string: "https://github.com/DigholeNet/vault")!) {
                        HStack(spacing: 10) {
                            Image(systemName: "globe")
                            Text(verbatim: "github.com/DigholeNet/vault")
                                .font(.system(size: 13, weight: .semibold))
                        }
                        .foregroundStyle(VaultTheme.primary)
                        .frame(maxWidth: .infinity, minHeight: 48)
                        .background(VaultTheme.surfaceSubtle, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    }
                }
                .vaultCard(padding: 22)

                Text(verbatim: "© 2026 Dighole Team")
                    .font(.system(size: 11))
                    .foregroundStyle(VaultTheme.textDisabled)
                    .padding(.top, 8)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
        .vaultScreenBackground()
        .navigationBarHidden(true)
    }
}
#endif
