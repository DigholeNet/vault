#if os(macOS)
import SwiftUI

struct MacosAboutView: View {
    var body: some View {
        VStack(spacing: 16) {
            MacosAppIcon(size: 76).accessibilityHidden(true)
            AboutContent()
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 20)
        .padding(.vertical, 36)
    }
}
#endif
