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
                                languageManager.tr("Port"), value: $config.port,
                                formatter: NumberFormatter.noneSeparator)
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

                }.formStyle(.grouped)

            }

        }

    }

    #Preview {
        @Previewable @State var config = VaultConfig()
        MacosConfigureView(config: config)
            .environmentObject(LanguageManager.shared)
    }

#endif
