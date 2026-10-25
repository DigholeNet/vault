//
//  IosConfigureView.swift
//  Vault
//
//

import SwiftUI
import VaultCore

#if os(iOS)

struct IosConfigureView: View {
    @Binding var selectedTab: Int
    @EnvironmentObject var config: VaultConfig
    @EnvironmentObject var languageManager: LanguageManager

    @State private var isSecured: Bool = true
    @State private var draft = ConnectionDraft()
    @State private var savedDraft: ConnectionDraft?
    @State private var loaded = false

    private var validationError: String? { draft.validationError() }

    private func save() {
        guard config.save(draft) == nil else { return }
        draft = config.connectionDraft
        savedDraft = draft
    }

    var body: some View {
        ZStack {
            Form {
                Section {
                    HStack {
                        Image(systemName: "accessibility")
                        TextField(
                            "ID", text: $config.id, prompt: Text("ID")
                        )
                        .autocorrectionDisabled()
                        .disabled(true)
                    }
                }

                Section {
                    HStack {
                        Image(
                            systemName:
                            "externaldrive.connected.to.line.below"
                        )
                        TextField(
                            languageManager.tr("Host"), text: $draft.host,
                            prompt: Text(languageManager.tr("IP Address or domain"))
                        ).autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    }
                    HStack {
                        Image(systemName: "number.circle")
                        TextField(
                            languageManager.tr("Port"), text: $draft.port,
                            prompt: Text("1-65535")
                        )
                        .keyboardType(.numberPad)
                        .autocorrectionDisabled()
                    }
                    HStack {
                        Group {
                            if isSecured {
                                HStack {
                                    Image(systemName: "p.circle.fill")
                                    SecureField(
                                        languageManager.tr("Password"), text: $draft.password
                                    )
                                    .textInputAutocapitalization(
                                        .never
                                    )
                                }
                            } else {
                                HStack {
                                    Image(systemName: "p.circle.fill")
                                    TextField(
                                        languageManager.tr("Password"), text: $draft.password
                                    )
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(
                                        .never
                                    )
                                }
                            }
                        }
                        Button(action: {
                            isSecured.toggle()

                        }) {
                            Image(
                                systemName: self.isSecured
                                    ? "eye.slash" : "eye"
                            )
                            .accentColor(.gray)
                        }
                    }
                    HStack {
                        Image(systemName: "arrow.up.arrow.down.circle")
                        TextField(
                            languageManager.tr("MTU"), text: $draft.mtu,
                            prompt: Text("1280-1427")
                        )
                        .keyboardType(.numberPad)
                        .autocorrectionDisabled()
                    }
                }

                Section {
                    HStack {
                        Image(systemName: "network")
                        TextField(
                            languageManager.tr("DNS"), text: $draft.dns,
                            prompt: Text(languageManager.tr("DNS Server"))
                        )
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    }
                } footer: {
                    Text(languageManager.tr("DNS server address separated by comma."))
                }

                Section {
                    HStack {
                        Image(systemName: "stethoscope")
                        TextField(
                            languageManager.tr("Probe Domains"), text: $draft.probeDomains,
                            prompt: Text(languageManager.tr("Domains to probe"))
                        )
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    }
                } footer: {
                    Text(languageManager.tr("Diagnostic probe domains, separated by commas. Leave empty to use defaults."))
                }

                Section {
                    Picker(languageManager.tr("Language"), selection: $languageManager.language) {
                        ForEach(AppLanguage.allCases) { language in
                            Text(language.displayName).tag(language)
                        }
                    }
                }

                if savedDraft == draft || validationError != nil || config.passwordStorageError != nil {
                    Section {
                        if savedDraft == draft {
                            Text(languageManager.tr("Saved. Changes apply the next time you connect."))
                                .font(.footnote)
                        }
                        if let error = validationError {
                            Text(languageManager.tr(error))
                                .foregroundColor(.red)
                                .font(.footnote)
                        }
                        if let error = config.passwordStorageError {
                            Text(languageManager.tr(error))
                                .foregroundColor(.red)
                                .font(.footnote)
                            Button(languageManager.tr("Retry")) { config.retryPasswordStorage() }
                        }
                    }
                }

            }.formStyle(.grouped)

        }.navigationBarBackButtonHidden(true)
            .onAppear {
                guard !loaded else { return }
                loaded = true
                draft = config.connectionDraft
                savedDraft = nil
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(languageManager.tr("Save")) { save() }
                        .disabled(validationError != nil)
                }
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
    }
}

#Preview {
    @Previewable @State var selectedTab: Int = 0
    let config = VaultConfig()
    IosConfigureView(selectedTab: $selectedTab).environmentObject(config)
        .environmentObject(LanguageManager.shared)
}

#endif
