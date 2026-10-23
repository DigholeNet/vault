//
//  IosAboutView.swift
//  Vault
//
//

import SwiftUI
import VaultCore

#if os(iOS)
    struct IosAboutView: View {

        @Binding var selectedTab: Int
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
                            ScrollView {
                                Text(logText)
                                    .font(.system(.footnote, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding()
                            }
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
        @Previewable @State var selectedTab: Int = 0
        IosAboutView(selectedTab: $selectedTab)
            .environmentObject(LanguageManager.shared)
    }

#endif
