#if os(macOS)
import SwiftUI

struct MacosAboutView: View {
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        VStack(spacing: 18) {
            ZStack {
                VaultHeroBackground()
                VStack(spacing: 0) {
                    MacosAppIcon(size: 112).accessibilityHidden(true)
                    Text("Vault")
                        .font(.system(size: 38, weight: .bold))
                        .foregroundStyle(VaultTheme.heroText)
                        .padding(.top, 18)
                    Text(languageManager.tr(
                        "Version %@ · BUILD %@",
                        Bundle.main.appVersionShort,
                        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
                    ))
                    .font(.system(size: 12))
                    .foregroundStyle(VaultTheme.heroSecondary)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 8)
                    .background(Color.white.opacity(0.1), in: Capsule())
                    .padding(.top, 20)
                }
                .padding(32)
            }
            .clipShape(RoundedRectangle(cornerRadius: 26, style: .continuous))

            VStack(spacing: 14) {
                Text(languageManager.tr("A secure VPN client for cross-regional connectivity."))
                    .font(.system(size: 14))
                    .foregroundStyle(VaultTheme.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(languageManager.tr("Encrypted connections with automatic path discovery."))
                    .font(.system(size: 12))
                    .foregroundStyle(VaultTheme.textSecondary)
                Link(destination: URL(string: "https://github.com/DigholeNet/vault")!) {
                    Label("github.com/DigholeNet/vault", systemImage: "globe")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(VaultTheme.primary)
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .background(VaultTheme.indigoSoft, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
                .buttonStyle(.plain)
            }
            .vaultCard(padding: 20)

            Text(verbatim: "© 2026 Dighole Team")
                .font(.system(size: 11))
                .foregroundStyle(VaultTheme.textDisabled)
        }
        .multilineTextAlignment(.center)
        .padding(.horizontal, 28)
        .padding(.bottom, 24)
        .frame(maxWidth: .infinity)
    }
}
#endif
