#if os(macOS)
import SwiftUI

struct MacosAboutView: View {
    var body: some View {
        VStack(spacing: 0) {
            MacosAppIcon(size: 80)
                .accessibilityHidden(true)
                .padding(.bottom, 16)
            AboutContent()
        }
        .multilineTextAlignment(.center)
        .padding(.horizontal, 32)
        .padding(.bottom, 32)
        .frame(maxWidth: .infinity)
    }
}

#endif
