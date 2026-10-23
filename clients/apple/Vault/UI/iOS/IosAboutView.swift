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
        VStack(spacing: 14) {
            if let icon = appIcon {
                Image(uiImage: icon)
                    .resizable().scaledToFit().frame(width: 80, height: 80)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
                    .accessibilityHidden(true)
            }
            Text("Vault").font(.title2.weight(.semibold))
            Text(languageManager.tr("Vault version : %@", Bundle.main.appVersionShort))
                .foregroundStyle(.secondary)
            Text(languageManager.tr("VPN Client")).foregroundStyle(.secondary)
        }
        .font(.body)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(languageManager.tr("About"))
        .navigationBarTitleDisplayMode(.inline)
    }
}
#endif
