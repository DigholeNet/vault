//
//  IosStatusView.swift
//  Vault
//
//

import SwiftUI
import VaultCore

#if os(iOS)
struct IosStatusView: View {
    var vpnManager: VpnManager
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager

    var parsedIPs: (ipv4: String?, ipv6: String?) {
        appData.assignedIp.parsedIPv4AndIPv6()
    }

    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack {
                    Spacer()

                    VStack(spacing: 20) {
                        // VPN Status
                        Text(VpnStatusUtil.getStatus(appData.vpnStatus))
                            .bold()
                            .foregroundStyle(.primary)
                            .font(.system(size: 32))

                        Spacer().frame(height: 40)

                        Toggle("", isOn: Binding(
                            get: { appData.vpnOn },
                            set: { enabled in
                                if appData.vpnStatus == .disconnecting { vpnManager.disconnect() }
                                else if enabled { vpnManager.connect() }
                                else { vpnManager.disconnect() }
                            }
                        ))
                        .toggleStyle(CustomToggleStyle())
                        .disabled(
                            !appData.canToggleConnection
                        )

                        if let error = appData.connectionError {
                            Text(languageManager.tr(error)).foregroundStyle(.red)
                        }

                        if appData.vpnStatus == .connected, appData.vpnOn, let since = appData.connectedSince {
                            ConnectionDurationView(since: since)
                        }

                        if appData.vpnStatus == .connected {
                            let ips = parsedIPs
                            let hasTunnelIps = ips.ipv4 != nil || ips.ipv6 != nil

                            if !appData.publicIp.isEmpty || hasTunnelIps {
                                VStack(alignment: .leading, spacing: 14) {
                                    if !appData.publicIp.isEmpty {
                                        StatusAddressRow(
                                            title: "WAN", address: appData.publicIp,
                                            symbol: "network", color: .accentColor
                                        )
                                    }

                                    if !appData.publicIp.isEmpty, hasTunnelIps {
                                        Divider()
                                    }

                                    if hasTunnelIps {
                                        VStack(alignment: .leading, spacing: 8) {
                                            if let ipv4 = ips.ipv4 {
                                                StatusAddressRow(
                                                    title: "IPv4", address: ipv4, symbol: "server.rack", color: .blue
                                                )
                                            }
                                            if let ipv6 = ips.ipv6 {
                                                StatusAddressRow(
                                                    title: "IPv6", address: ipv6, symbol: "server.rack", color: .green
                                                )
                                            }
                                        }
                                    }
                                }
                                .padding(14)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
                                .padding(.horizontal, 20)
                                .padding(.top, 16)
                            }

                            HStack(spacing: 0) {
                                TrafficColumn(
                                    title: "Uplink", symbol: "arrow.up.circle.fill", color: .blue,
                                    packets: appData.packetsSent, bytes: appData.bytesSent,
                                    rate: appData.bytesSentPerSecond
                                )
                                Divider().frame(height: 70)
                                TrafficColumn(
                                    title: "Downlink", symbol: "arrow.down.circle.fill", color: .green,
                                    packets: appData.packetsReceived, bytes: appData.bytesReceived,
                                    rate: appData.bytesReceivedPerSecond
                                )
                            }
                            .padding(.horizontal, 20)
                            .padding(.top, 24)
                            .padding(.bottom, 16)
                        }
                    }
                    .frame(maxWidth: .infinity)

                    Spacer()
                }.frame(minHeight: geometry.size.height)
            }
        }
    }
}

private struct StatusAddressRow: View {
    let title: String
    let address: String
    let symbol: String
    let color: Color

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .font(.system(size: 13))
                .foregroundColor(color)
                .frame(width: 16)
            Text(verbatim: title)
                .font(.system(size: 12))
                .foregroundColor(.secondary)
                .fixedSize(horizontal: true, vertical: false)
            Text(verbatim: address)
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .lineLimit(1)
                .minimumScaleFactor(0.55)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .trailing)
        }
    }
}

private struct TrafficColumn: View {
    let title: String
    let symbol: String
    let color: Color
    let packets: UInt64
    let bytes: UInt64
    let rate: UInt64
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        VStack(spacing: 6) {
            HStack(spacing: 4) {
                Image(systemName: symbol)
                    .foregroundColor(color)
                    .font(.system(size: 18))
                Text(languageManager.tr(title))
                    .font(.system(size: 13))
                    .foregroundColor(.gray)
            }
            Text(PacketStats.formatBytes(rate) + "/s")
                .font(.system(size: 15, weight: .semibold, design: .monospaced))
                .foregroundColor(color)
            Text(PacketStats.formatBytes(bytes))
                .font(.system(size: 11))
                .foregroundColor(.gray)
            Text(languageManager.tr("Packets") + " \(packets)")
                .font(.system(size: 11))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
    }
}

struct CustomToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button(
            action: {
                configuration.isOn.toggle()
            },
            label: {
                Image(
                    systemName: configuration.isOn
                        ? "personalhotspot" : "personalhotspot.slash"
                )
                .renderingMode(.template)
                .foregroundColor(configuration.isOn ? .green : .red)
                .font(.system(size: 50))
                .frame(width: 88, height: 88)
                .background(Color(uiColor: .systemBackground), in: Circle())
                .contentShape(Circle())
            }
        )
        .accessibilityLabel(LanguageManager.shared.tr(configuration.isOn ? "Disconnect" : "Connect"))
        .accessibilityIdentifier("vpn.connection")
        .buttonStyle(ConnectionIconButtonStyle())
        .frame(width: 88, height: 88)
    }
}

private struct ConnectionIconButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .shadow(
                color: .black.opacity(configuration.isPressed ? 0.08 : 0.15),
                radius: configuration.isPressed ? 3 : 8,
                x: 0,
                y: configuration.isPressed ? 1 : 4
            )
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }
}

#Preview {
    let config = VaultConfig()
    let appData = AppData()
    let vpnManager = VpnManager(
        config: config, appData: appData
    )
    IosStatusView(vpnManager: vpnManager)
        .environmentObject(appData)
        .environmentObject(config)
        .environmentObject(LanguageManager.shared)
}
#endif
