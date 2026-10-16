//
//  IosConfigureView.swift
//  Vault
//
//

import SwiftUI

#if os(iOS)

    struct IosConfigureView: View {
        @Binding var selectedTab: Int
        @EnvironmentObject var config: VaultConfig
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
                                .textInputAutocapitalization(.never)
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
                                        .textInputAutocapitalization(
                                            .never)
                                    }
                                } else {
                                    HStack {
                                        Image(systemName: "p.circle.fill")
                                        TextField(
                                            languageManager.tr("Password"), text: $config.password
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

                    }

                    Section {
                        HStack {
                            Image(systemName: "network")
                            TextField(
                                languageManager.tr("DNS"), text: $config.dns,
                                prompt: Text(languageManager.tr("DNS Server"))
                            )
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)

                        }
                    } footer: {
                        Text(languageManager.tr("DNS server address separated by comma."))
                    }

                }.formStyle(.grouped)

            }.navigationBarBackButtonHidden(true)
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

    private func hideKeyboard() {
        #if os(iOS)
            UIApplication.shared.sendAction(
                #selector(UIResponder.resignFirstResponder),
                to: nil,
                from: nil,
                for: nil
            )
        #endif
    }

    #Preview {
        @Previewable @State var selectedTab: Int = 0
        let config = VaultConfig()
        IosConfigureView(selectedTab: $selectedTab).environmentObject(config)
            .environmentObject(LanguageManager.shared)
    }

#endif
