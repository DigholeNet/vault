// SPDX-License-Identifier: MIT
import Foundation
import SwiftUI

/// Product details shared by the platform-specific About containers.
struct AboutContent: View {
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        VStack(spacing: 0) {
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
            #if os(macOS)
                .fixedSize(horizontal: false, vertical: true)
            #endif
                .padding(.bottom, 16)
            Text(verbatim: "© 2026 Dighole Team")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
    }
}
