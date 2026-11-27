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
            VStack(spacing: 0) {
                VaultPageHeader(title: languageManager.tr("About"), subtitle: "")

                if let icon = appIcon {
                    Image(uiImage: icon)
                        .resizable().scaledToFit().frame(width: 72, height: 72)
                        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                        .accessibilityHidden(true)
                        .padding(.top, 44)
                        .padding(.bottom, 14)
                }
                AboutContent()
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
        .vaultScreenBackground()
        .navigationBarHidden(true)
    }
}
#endif
