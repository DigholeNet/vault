// SPDX-License-Identifier: MIT
import Foundation
import SwiftUI

struct AboutContent: View {
    @EnvironmentObject private var languageManager: LanguageManager
    @ScaledMetric(relativeTo: .largeTitle) private var titleSize = 30.0

    private static let repository = URL(string: "https://github.com/DigholeNet/vault")!

    var body: some View {
        VStack(spacing: 0) {
            Text("Vault")
                .font(.system(size: titleSize, weight: .bold))
                .foregroundStyle(VaultTheme.textPrimary)
            Text(languageManager.tr(
                "Version %@ · BUILD %@",
                Bundle.main.appVersionShort,
                Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
            ))
            .font(.footnote)
            .foregroundStyle(VaultTheme.textSecondary)
            .padding(.top, 6)

            Text(languageManager.tr("A secure VPN client for cross-regional connectivity."))
                .font(.body)
                .foregroundStyle(VaultTheme.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 24)

            Link(destination: Self.repository) {
                Label {
                    Text(verbatim: Self.repository.absoluteString)
                        .multilineTextAlignment(.center)
                } icon: {
                    Image(systemName: "globe")
                }
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(VaultTheme.primary)
                .padding(.horizontal, 4)
                .frame(minHeight: VaultTheme.controlHeight)
                .contentShape(Rectangle())
            }
            .padding(.top, 8)

            Text(verbatim: "© 2026 Dighole Team")
                .font(.caption)
                .foregroundStyle(VaultTheme.textSecondary)
                .padding(.top, 16)
        }
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
    }
}
