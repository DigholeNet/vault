//
//  IosMainView.swift
//  Vault
//
//

import SwiftUI

#if os(iOS)
    struct IosMainView: View {

        var vpnManager: VpnManager
        @State private var selectedTab = 0
        @EnvironmentObject var appData: AppData
        @EnvironmentObject var languageManager: LanguageManager

        var body: some View {
            TabView(selection: $selectedTab) {
                NavigationView {
                    IosStatusView(vpnManager: vpnManager)
                }.tabItem {
                    Label(languageManager.tr("Status"), systemImage: "bolt.heart")
                }.tag(0)

                NavigationStack {
                    IosConfigureView(selectedTab: $selectedTab)
                }.tabItem {
                    Label(languageManager.tr("Configure"), systemImage: "server.rack")
                }.tag(1)

                NavigationView {
                    IosAboutView(selectedTab: $selectedTab)
                }.tabItem {
                    Label(languageManager.tr("About"), systemImage: "questionmark.app")
                }.tag(2)
            }
            .alert(
                languageManager.tr("Server Not Configured"),
                isPresented: $appData.showConfigureGuide
            ) {
                Button(languageManager.tr("Configure")) { selectedTab = 1 }
                Button(languageManager.tr("Cancel"), role: .cancel) {}
            } message: {
                Text(
                    languageManager.tr("Please fill in the server host and password before connecting.")
                )
            }
        }
    }

    #Preview {
        let config = VaultConfig()
        let appData = AppData()
        let vpnManager = VpnManager(
            config: config, appData: appData)
        IosMainView(vpnManager: vpnManager).environmentObject(
            appData
        ).environmentObject(config)
        .environmentObject(LanguageManager.shared)
    }
#endif
