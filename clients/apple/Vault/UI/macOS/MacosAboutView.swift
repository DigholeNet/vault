#if os(macOS)
import SwiftUI

struct MacosAboutView: View {
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        VStack(spacing: 0) {
            MacosAppIcon(size: 80)
                .accessibilityHidden(true)
                .padding(.bottom, 16)
            Text("Vault")
                .font(.system(size: 24, weight: .bold))
                .padding(.bottom, 12)
            Text(languageManager.tr(
                "Version %@ (%@)",
                Bundle.main.appVersionShort,
                Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
            ))
            .font(.system(size: 16))
            .foregroundStyle(.secondary)
            .padding(.bottom, 32)

            Link(destination: URL(string: "https://github.com/DigholeNet/vault")!) {
                Text(verbatim: "https://github.com/DigholeNet/vault")
            }
            .font(.system(size: 14))
            .padding(.bottom, 16)
            Text(languageManager.tr("A secure VPN client for cross-regional connectivity."))
                .font(.system(size: 14))
                .fixedSize(horizontal: false, vertical: true)
                .padding(.bottom, 16)
            Text(verbatim: "© 2026 Dighole Team")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
        .multilineTextAlignment(.center)
        .padding(32)
        .frame(width: 420, height: 440)
    }
}

#endif
