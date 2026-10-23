//
//  MacosConfigureView.swift
//  Vault
//
//

import SwiftUI

#if os(macOS)
    struct MacosConfigureView: View {

        @ObservedObject var config: VaultConfig
        @EnvironmentObject var languageManager: LanguageManager

        @State private var isSecured: Bool = true
        // The port is edited as text and only persisted when it parses to
        // 1...65535; an invalid edit stays visible with an error hint
        // instead of being written to the shared defaults.
        @State private var portText: String = ""
        @State private var portInvalid: Bool = false

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
                                languageManager.tr("Host"), text: $config.host,
                                prompt: Text(languageManager.tr("IP Address or domain"))
                            ).autocorrectionDisabled()
                        }
                        HStack {
                            Image(systemName: "number.circle")
                            TextField(
                                languageManager.tr("Port"), text: $portText,
                                prompt: Text("1-65535")
                            )
                            .autocorrectionDisabled()
                            .onChange(of: portText) { newValue in
                                if let port = Int(newValue), (1...65535).contains(port) {
                                    portInvalid = false
                                    config.port = port
                                } else {
                                    portInvalid = true
                                }
                            }
                        }
                        if portInvalid {
                            Text(languageManager.tr("Port must be a number between 1 and 65535."))
                                .foregroundColor(.red)
                                .font(.footnote)
                        }
                        HStack {
                            Group {
                                if isSecured {
                                    HStack {
                                        Image(systemName: "p.circle.fill")
                                        SecureField(
                                            languageManager.tr("Password"), text: $config.password
                                        )
                                    }
                                } else {
                                    HStack {
                                        Image(systemName: "p.circle.fill")
                                        TextField(
                                            languageManager.tr("Password"), text: $config.password
                                        )
                                        .autocorrectionDisabled()
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

                    }

                    Section {
                        HStack {
                            Image(systemName: "network")
                            TextField(
                                languageManager.tr("DNS"), text: $config.dns,
                                prompt: Text(languageManager.tr("DNS Server"))
                            )
                            .autocorrectionDisabled()
                        }
                    } footer: {
                        Text(languageManager.tr("DNS server address separated by comma."))
                    }

                    Section {
                        if let error = config.passwordStorageError {
                            Text(languageManager.tr(error))
                                .foregroundColor(.red)
                                .font(.footnote)
                            Button(languageManager.tr("Retry")) { config.retryPasswordStorage() }
                        }
                    }

                }.formStyle(.grouped)

            }
            .onAppear {
                portText = String(config.port)
                portInvalid = !(1...65535).contains(config.port)
            }

        }

    }

    #Preview {
        @Previewable @State var config = VaultConfig()
        MacosConfigureView(config: config)
            .environmentObject(LanguageManager.shared)
    }

#endif
