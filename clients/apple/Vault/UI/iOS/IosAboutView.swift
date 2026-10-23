//
//  IosAboutView.swift
//  Vault
//
//

import SwiftUI
import VaultCore

#if os(iOS)
    import UIKit

    struct IosAboutView: View {

        @Binding var selectedTab: Int
        @State private var showLogSheet = false
        /// The complete log; LogTextView (UITextView) renders it lazily, so
        /// no display-side truncation is needed.
        @State private var logText = ""
        @State private var isLoadingLogs = false
        @State private var errorMessage: String?
        @State private var showError = false
        /// Live-refresh task for the open log sheet; cancelled on dismiss.
        @State private var logRefreshTask: Task<Void, Never>?
        @EnvironmentObject var languageManager: LanguageManager

        var body: some View {
            VStack(spacing: 20) {
                Text(languageManager.tr("Vault version : %@", Bundle.main.appVersionShort))

                HStack {
                    Text(languageManager.tr("Language"))
                    Picker(selection: $languageManager.language) {
                        ForEach(AppLanguage.allCases) { language in
                            Text(language.displayName).tag(language)
                        }
                    } label: {
                        EmptyView()
                    }
                    .labelsHidden()
                    .fixedSize()
                }

                Button(action: viewLogs) {
                    Label(languageManager.tr("View Logs"), systemImage: "doc.text.magnifyingglass")
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(50.0)
            .navigationBarBackButtonHidden(true)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(action: {
                        selectedTab = 0
                    }) {
                        HStack {
                            Image(systemName: "chevron.left")
                        }
                        .foregroundColor(.blue)
                    }
                }
            }
            .sheet(isPresented: $showLogSheet) {
                NavigationView {
                    ZStack {
                        if isLoadingLogs {
                            ProgressView(languageManager.tr("Loading logs..."))
                        } else {
                            // Native text view: SwiftUI Text re-layouts the
                            // whole log on every refresh and stalls with
                            // 10k+ lines; UITextView is built for this and
                            // gives free selection/scrolling.
                            LogTextView(text: logText)
                        }
                    }
                    .navigationTitle(languageManager.tr("Logs"))
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .navigationBarTrailing) {
                            Button(languageManager.tr("Done")) {
                                showLogSheet = false
                            }
                        }
                        ToolbarItem(placement: .navigationBarLeading) {
                            Button(languageManager.tr("Copy")) {
                                UIPasteboard.general.string = logText
                            }
                            .disabled(logText.isEmpty)
                        }
                    }
                }
                .onDisappear {
                    logRefreshTask?.cancel()
                    logRefreshTask = nil
                }
            }
            .alert(languageManager.tr("No Logs"), isPresented: $showError, presenting: errorMessage) { _ in
                Button(languageManager.tr("OK")) {}
            } message: { message in
                Text(message)
            }
        }

        private func viewLogs() {
            showLogSheet = true
            isLoadingLogs = true
            logText = ""
            logRefreshTask?.cancel()

            // Live refresh while the sheet is open (the extension shares the
            // file on iOS, so re-reading picks up new [ne]/[probe] lines).
            logRefreshTask = Task {
                var firstLoad = true
                while !Task.isCancelled {
                    let text = await FileLogger.shared.readLogAsync() ?? ""
                    let wasFirstLoad = firstLoad
                    firstLoad = false
                    await MainActor.run {
                        if wasFirstLoad {
                            isLoadingLogs = false
                            if text.isEmpty {
                                errorMessage = LanguageManager.shared.tr("No log content found.")
                                showError = true
                                showLogSheet = false
                                return
                            }
                        }
                        if !text.isEmpty, text != logText {
                            logText = text
                        }
                    }
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
        }
    }

    /// Read-only, selectable, monospaced log view backed by UITextView.
    /// SwiftUI Text re-layouts the entire string on every 2s live refresh —
    /// with 10k+ lines that blocked the main thread long enough to freeze
    /// the sheet. UITextView lays out lazily.
    struct LogTextView: UIViewRepresentable {
        let text: String

        func makeUIView(context: Context) -> UITextView {
            let textView = UITextView()
            textView.isEditable = false
            textView.isSelectable = true
            textView.font = UIFont.monospacedSystemFont(
                ofSize: UIFont.smallSystemFontSize, weight: .regular
            )
            return textView
        }

        func updateUIView(_ textView: UITextView, context: Context) {
            guard textView.text != text else { return }
            textView.text = text
            // Tail-follow the live refresh.
            textView.scrollRangeToVisible(NSRange(location: text.count, length: 0))
        }
    }

    #Preview {
        @Previewable @State var selectedTab: Int = 0
        IosAboutView(selectedTab: $selectedTab)
            .environmentObject(LanguageManager.shared)
    }

#endif
