//
//  MacosAboutView.swift
//  Vault
//
//

import SwiftUI
import VaultCore

#if os(macOS)
    struct MacosAboutView: View {
        @State private var showLogSheet = false
        @State private var logText = ""
        @State private var isLoadingLogs = false
        @State private var errorMessage: String?
        @State private var showError = false
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
                            ScrollView {
                                Text(logText)
                                    .font(.system(.footnote, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding()
                            }
                        }
                    }
                }
                .frame(width: 700, height: 450)
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

            Task {
                let text = await FileLogger.shared.readLogAsync() ?? ""
                await MainActor.run {
                    isLoadingLogs = false
                    if text.isEmpty {
                        errorMessage = LanguageManager.shared.tr("No log content found.")
                        showError = true
                        showLogSheet = false
                    } else {
                        logText = text
                    }
                }
            }
        }
    }

    #Preview {
        MacosAboutView()
    }
#endif
