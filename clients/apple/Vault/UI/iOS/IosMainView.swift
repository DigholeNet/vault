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
            NavigationStack {
                IosStatusView(vpnManager: vpnManager)
            }.tabItem {
                Label(languageManager.tr("Status"), systemImage: "bolt.heart")
                    .environment(\.symbolVariants, .none)
            }.tag(0)

            NavigationStack {
                IosConfigureView(selectedTab: $selectedTab)
            }.tabItem {
                Label(languageManager.tr("Configure"), systemImage: "gearshape")
                    .environment(\.symbolVariants, .none)
            }.tag(1)

            NavigationStack {
                IosDiagnosticsView(vpnManager: vpnManager)
            }.tabItem {
                Label(languageManager.tr("Diagnostics"), systemImage: "stethoscope")
                    .environment(\.symbolVariants, .none)
            }.tag(2)

            NavigationStack {
                IosAboutView()
            }.tabItem {
                Label(languageManager.tr("About"), systemImage: "info.circle")
                    .environment(\.symbolVariants, .none)
            }.tag(3)
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
        config: config, appData: appData
    )
    IosMainView(vpnManager: vpnManager).environmentObject(
        appData
    ).environmentObject(config)
        .environmentObject(LanguageManager.shared)
}
#endif
