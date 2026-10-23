#if os(macOS)
import SwiftUI

struct MacosAboutView: View {
    @EnvironmentObject var languageManager: LanguageManager
    var body: some View {
        VStack(spacing: 14) {
            MacosAppIcon(size: 80)
            Text("Vault").font(.system(size: 20, weight: .semibold))
            Text(languageManager.tr("Vault version : %@", Bundle.main.appVersionShort))
                .font(.body).foregroundStyle(.secondary)
            Text(languageManager.tr("VPN Client")).font(.body).foregroundStyle(.secondary)
        }.padding(32).frame(width: 380, height: 340)
    }
}

#endif
