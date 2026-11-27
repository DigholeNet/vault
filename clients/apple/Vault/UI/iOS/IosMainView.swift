import SwiftUI

#if os(iOS)
private enum IosTab: Int, CaseIterable, Identifiable {
    case status = 0, configure, diagnostics, about

    var id: Int { rawValue }

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
    @State private var selectedTab = 0
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        ZStack(alignment: .bottom) {
            Group {
                switch selectedTab {
                case 1:
                    NavigationStack {
                        IosConfigureView(selectedTab: $selectedTab, vpnManager: vpnManager)
                    }
                case 2:
                    NavigationStack {
                        IosDiagnosticsView(vpnManager: vpnManager)
                    }
                case 3:
                    NavigationStack {
                        IosAboutView()
                    }
                default:
                    NavigationStack {
                        IosStatusView(vpnManager: vpnManager, onOpenDiagnostics: { selectedTab = 2 })
                    }
                }
            }
            .padding(.bottom, 76)

            bottomNavigation
        }
        .tint(VaultTheme.primary)
        .alert(
            languageManager.tr("Server Not Configured"),
            isPresented: $appData.showConfigureGuide
        ) {
            Button(languageManager.tr("Configure")) { selectedTab = 1 }
            Button(languageManager.tr("Cancel"), role: .cancel) {}
        } message: {
            Text(languageManager.tr("Please fill in the server host and password before connecting."))
        }
    }

    private var bottomNavigation: some View {
        HStack(spacing: 0) {
            ForEach(IosTab.allCases) { item in
                let selected = selectedTab == item.rawValue
                Button {
                    selectedTab = item.rawValue
                } label: {
                    VStack(spacing: 5) {
                        Image(systemName: item.symbol)
                            .font(.system(size: 18, weight: .medium))
                            .frame(width: 56, height: 28)
                            .background(
                                selected ? VaultTheme.indigoSoft : Color.clear,
                                in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                            )
                        Text(languageManager.tr(item.titleKey))
                            .font(.system(size: 10, weight: selected ? .semibold : .regular))
                    }
                    .foregroundStyle(selected ? VaultTheme.primary : VaultTheme.textDisabled)
                    .frame(maxWidth: .infinity)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .frame(height: 66)
        .background(VaultTheme.surface, in: RoundedRectangle(cornerRadius: 25, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 25, style: .continuous)
                .strokeBorder(VaultTheme.outline)
        }
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
        .background(VaultTheme.background.ignoresSafeArea(edges: .bottom))
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
