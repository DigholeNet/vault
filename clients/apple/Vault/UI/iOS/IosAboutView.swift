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
                    AboutContent()
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
