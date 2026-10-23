//
//  MacosAboutView.swift
//  Vault
//
//

import SwiftUI
import VaultCore

#if os(macOS)
    import AppKit

    struct MacosAboutView: View {
        var vpnManager: VpnManager
        @State private var showLogSheet = false
        /// The complete merged log; LogTextView (NSTextView) renders it
        /// lazily, so no display-side truncation is needed.
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
            .sheet(isPresented: $showLogSheet) {
                VStack(spacing: 0) {
                    HStack {
                        Text(languageManager.tr("Logs"))
                            .font(.headline)
                        Spacer()
                        Button(languageManager.tr("Copy")) {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(logText, forType: .string)
                        }
                        .disabled(logText.isEmpty)
                        Button(languageManager.tr("Close")) {
                            showLogSheet = false
                        }
                    }
                    .padding()

                    Divider()

                    ZStack {
                        if isLoadingLogs {
                            ProgressView(languageManager.tr("Loading logs..."))
                        } else {
                            // Native text view: SwiftUI Text re-layouts the
                            // whole log on every refresh and visibly stalls
                            // with 10k+ lines; NSTextView is built for this
                            // and gives free selection/scrolling.
                            LogTextView(text: logText)
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                // Fill whatever size the sheet window gets: with a fixed
                // frame the content is smaller than the window during
                // loading (no ScrollView to expand it) and macOS centers it,
                // leaving the header floating mid-window.
                .frame(minWidth: 700, minHeight: 450)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
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

            // Live refresh while the sheet is open: the merged view includes
            // the extension log fetched over the provider-message channel,
            // so new [ne]/[probe] lines appear without reopening the sheet.
            logRefreshTask = Task {
                var firstLoad = true
                while !Task.isCancelled {
                    let text = await vpnManager.collectLogs()
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

    /// Read-only, selectable, monospaced log view backed by NSTextView.
    /// SwiftUI Text re-layouts the entire string on every 2s live refresh —
    /// with textSelection enabled and 10k+ lines that blocked the main
    /// thread long enough to freeze the sheet. NSTextView lays out lazily.
    struct LogTextView: NSViewRepresentable {
        let text: String

        func makeNSView(context: Context) -> NSScrollView {
            let scrollView = NSTextView.scrollableTextView()
            let textView = scrollView.documentView as? NSTextView
            textView?.isEditable = false
            textView?.isSelectable = true
            textView?.font = NSFont.monospacedSystemFont(
                ofSize: NSFont.systemFontSize(for: .small), weight: .regular
            )
            return scrollView
        }

        func updateNSView(_ scrollView: NSScrollView, context: Context) {
            guard let textView = scrollView.documentView as? NSTextView,
                textView.string != text else { return }
            textView.string = text
            // Tail-follow the live refresh.
            textView.scrollToEndOfDocument(nil)
        }
    }

    #Preview {
        let config = VaultConfig()
        MacosAboutView(vpnManager: VpnManager(config: config, appData: AppData()))
    }
#endif
