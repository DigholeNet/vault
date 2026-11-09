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
        .padding(32)
        .frame(width: 420, height: 440)
    }
}

#endif
