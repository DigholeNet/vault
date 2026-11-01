import SwiftUI
import VaultCore

struct ConnectionDurationView: View {
    let since: Date
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let elapsed = DiagnosticsPresentation.connectionDuration(context.date.timeIntervalSince(since))
            Text(elapsed)
                .font(.system(size: 32, weight: .light, design: .rounded))
                .monospacedDigit()
                .tracking(2)
                .foregroundStyle(.primary)
                .contentTransition(.numericText())
                .animation(.easeOut(duration: 0.2), value: elapsed)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 4)
                .accessibilityLabel(languageManager.tr("Connected for") + " " + elapsed)
        }
    }
}
