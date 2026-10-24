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
        @State private var host = ""
        @State private var password = ""
        @State private var portText = ""
        @State private var dns = ""
        @State private var mtu = ""
        @State private var probeDomains = ""
        @State private var savedDraft: [String]?
        @State private var loaded = false

        private var draft: [String] { [host, portText, password, dns, mtu, probeDomains] }

        private var validationError: String? {
            SettingsValidation.configurationError(host: host, port: portText, password: password,
                dns: dns, mtu: mtu, probeDomains: probeDomains)
        }

        private func save() {
            guard validationError == nil, let port = Int(portText) else { return }
            guard config.saveConnection(host: host.trimmingCharacters(in: .whitespacesAndNewlines),
                port: port, password: password) else { return }
            config.dns = dns.trimmingCharacters(in: .whitespacesAndNewlines)
            config.mtu = mtu.trimmingCharacters(in: .whitespacesAndNewlines)
            config.probeDomains = probeDomains.trimmingCharacters(in: .whitespacesAndNewlines)
            host = config.host
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
                                    "externaldrive.connected.to.line.below")
                            TextField(
                                languageManager.tr("Host"), text: $host,
                                prompt: Text(languageManager.tr("IP Address or domain"))
                            ).autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        }
                        HStack {
                            Image(systemName: "number.circle")
                            TextField(
                                languageManager.tr("Port"), text: $portText,
                                prompt: Text("1-65535")
                            )
                            .keyboardType(.numberPad)
                            .autocorrectionDisabled()
                        }
                        if let error = validationError {
                            Text(languageManager.tr(error))
                                .foregroundColor(.red)
                                .font(.footnote)
                        }
                        HStack {
                            Group {
                                if isSecured {
                                    HStack {
                                        Image(systemName: "p.circle.fill")
                                        SecureField(
                                            languageManager.tr("Password"), text: $password
                                        )
                                        .textInputAutocapitalization(
                                            .never)
                                    }
                                } else {
                                    HStack {
                                        Image(systemName: "p.circle.fill")
                                        TextField(
                                            languageManager.tr("Password"), text: $password
                                        )
                                        .autocorrectionDisabled()
                                        .textInputAutocapitalization(
                                            .never)
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
                                languageManager.tr("MTU"), text: $mtu,
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
                                languageManager.tr("DNS"), text: $dns,
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
                                languageManager.tr("Probe Domains"), text: $probeDomains,
                                prompt: Text(languageManager.tr("Domains to probe"))
                            )
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        }
                    } footer: {
                        Text(languageManager.tr("Domains probed by Run Diagnostics, separated by comma. Empty uses defaults."))
                    }

                    Section {
                        Picker(languageManager.tr("Language"), selection: $languageManager.language) {
                            ForEach(AppLanguage.allCases) { language in
                                Text(language.displayName).tag(language)
                            }
                        }
                    }

                    Section {
                        Button(languageManager.tr("Save")) { save() }
                            .disabled(validationError != nil)
                        if savedDraft == draft {
                            Text(languageManager.tr("Saved. Changes apply the next time you connect."))
                                .font(.footnote)
                        }
                        if let error = config.passwordStorageError {
                            Text(languageManager.tr(error))
                                .foregroundColor(.red)
                                .font(.footnote)
                            Button(languageManager.tr("Retry")) { config.retryPasswordStorage() }
                        }
                    }

                }.formStyle(.grouped)

            }.navigationBarBackButtonHidden(true)
                .onAppear {
                    guard !loaded else { return }
                    loaded = true
                    portText = String(config.port)
                    host = config.host
                    password = config.password
                    dns = config.dns
                    mtu = config.mtu
                    probeDomains = config.probeDomains
                    savedDraft = nil
                }
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

        }

    }

    #Preview {
        @Previewable @State var selectedTab: Int = 0
        let config = VaultConfig()
        IosConfigureView(selectedTab: $selectedTab).environmentObject(config)
            .environmentObject(LanguageManager.shared)
    }

#endif
