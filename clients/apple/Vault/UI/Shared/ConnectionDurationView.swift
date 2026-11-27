import SwiftUI
import VaultCore

struct ConnectionDurationView: View {
    let since: Date
    var size: CGFloat = 32
    var design: Font.Design = .rounded
    var color: Color = .primary
    var verticalPadding: CGFloat = 4
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let elapsed = DiagnosticsPresentation.connectionDuration(context.date.timeIntervalSince(since))
            Text(elapsed)
                .font(.system(size: size, weight: .light, design: design))
                .monospacedDigit()
                .tracking(2)
                .foregroundStyle(color)
#if !os(macOS)
                // macOS keeps rendering this animation while the menu popover is hidden.
                .contentTransition(.numericText())
                .animation(.easeOut(duration: 0.2), value: elapsed)
#endif
                .frame(maxWidth: .infinity)
                .padding(.vertical, verticalPadding)
                .accessibilityLabel(languageManager.tr("Connected for") + " " + elapsed)
        }
    }
}
