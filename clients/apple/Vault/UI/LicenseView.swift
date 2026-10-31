import SwiftUI

struct LicenseView: View {
    @EnvironmentObject var languageManager: LanguageManager
    @Environment(\.dismiss) private var dismiss

    private var contents: String {
        let texts = ["LICENSE", "NOTICE"].compactMap { name -> String? in
            guard let url = Bundle.main.url(forResource: name, withExtension: nil) else { return nil }
            return try? String(contentsOf: url, encoding: .utf8)
        }
        return texts.count == 2 ? texts.joined(separator: "\n\n") : languageManager.tr("License information unavailable.")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(languageManager.tr("Open-source licenses")).font(.headline)
            ScrollView { Text(contents).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
            Button(languageManager.tr("Close")) { dismiss() }
        }
        .padding(24)
        .frame(minWidth: 300, idealWidth: 600, minHeight: 400)
    }
}
