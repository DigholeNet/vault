import SwiftUI

#if os(iOS)
struct IosAboutView: View {
    @EnvironmentObject var languageManager: LanguageManager

    /// Read the icon files emitted from the existing AppIcon asset catalog.
    private var appIcon: UIImage? {
        let icons = Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any]
        let primary = icons?["CFBundlePrimaryIcon"] as? [String: Any]
        let names = primary?["CFBundleIconFiles"] as? [String] ?? []
        return names.reversed().compactMap { UIImage(named: $0) }.first
    }

    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(spacing: 0) {
                    if let icon = appIcon {
                        Image(uiImage: icon)
                            .resizable().scaledToFit().frame(width: 80, height: 80)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                            .accessibilityHidden(true)
                            .padding(.bottom, 16)
                    }
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
                        .padding(.bottom, 16)
                    Text(verbatim: "© 2026 Dighole Team")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.center)
                .padding(32)
                .frame(maxWidth: .infinity)
                .frame(minHeight: geometry.size.height)
            }
        }
        .navigationTitle(languageManager.tr("About"))
        .navigationBarTitleDisplayMode(.inline)
    }
}
#endif
