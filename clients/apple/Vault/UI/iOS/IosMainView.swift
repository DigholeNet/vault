import SwiftUI

#if os(iOS)
private enum IosTab: CaseIterable {
    case status, configure, diagnostics, about

    var titleKey: String {
        switch self {
        case .status: "Status"
        case .configure: "Configure"
        case .diagnostics: "Diagnostics"
        case .about: "About"
        }
    }

    var symbol: String {
        switch self {
        case .status: "chart.bar.xaxis"
        case .configure: "slider.horizontal.3"
        case .diagnostics: "waveform.path.ecg"
        case .about: "info.circle"
        }
    }
}

struct IosMainView: View {
    var vpnManager: VpnManager
    @State private var selectedTab = IosTab.status
    @State private var opensNewProfile = false
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        TabView(selection: $selectedTab) {
            ForEach(IosTab.allCases, id: \.self) { tab in
                NavigationStack {
                    tabContent(tab)
                }
                .tabItem { Label(languageManager.tr(tab.titleKey), systemImage: tab.symbol) }
                .tag(tab)
            }
        }
        .background(IosKeyboardDismissal().allowsHitTesting(false))
        .onChange(of: selectedTab) { _, _ in IosKeyboardDismissal.dismiss() }
        .tint(VaultTheme.primary)
        .alert(
            languageManager.tr("Server Not Configured"),
            isPresented: $appData.showConfigureGuide
        ) {
            Button(languageManager.tr("Configure")) { selectedTab = .configure }
            Button(languageManager.tr("Cancel"), role: .cancel) {}
        } message: {
            Text(languageManager.tr("Please fill in the server host and password before connecting."))
        }
    }

    @ViewBuilder
    private func tabContent(_ tab: IosTab) -> some View {
        switch tab {
        case .status:
            IosStatusView(vpnManager: vpnManager) {
                opensNewProfile = true
                selectedTab = .configure
            }
        case .configure:
            IosConfigureView(vpnManager: vpnManager, opensNewProfile: $opensNewProfile)
        case .diagnostics:
            IosDiagnosticsView(vpnManager: vpnManager)
        case .about:
            IosAboutView()
        }
    }
}

#Preview {
    let config = VaultConfig()
    let appData = AppData()
    let vpnManager = VpnManager(config: config, appData: appData)
    IosMainView(vpnManager: vpnManager)
        .environmentObject(appData)
        .environmentObject(config)
        .environmentObject(LanguageManager.shared)
}
#endif
