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

                        Spacer().frame(height: 10)

                        // Connection Info & Statistics (combined, no background)
                        if appData.vpnStatus == .connected {
                            let ips = parsedIPs

                            VStack(spacing: 16) {
                                // IP Addresses Section
                                if ips.ipv4 != nil || ips.ipv6 != nil {
                                    VStack(alignment: .leading, spacing: 6) {
                                        if let ipv4 = ips.ipv4 {
                                            HStack(spacing: 8) {
                                                Image(systemName: "server.rack")
                                                    .foregroundColor(.blue)
                                                    .font(.system(size: 14))
                                                Text(verbatim: "IPv4:")
                                                    .font(.system(size: 14))
                                                    .foregroundColor(.gray)
                                                Text(ipv4)
                                                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                                                    .foregroundColor(.primary)
                                            }
                                        }

                                        if let ipv6 = ips.ipv6 {
                                            HStack(spacing: 8) {
                                                Image(systemName: "server.rack")
                                                    .foregroundColor(.green)
                                                    .font(.system(size: 14))
                                                Text(verbatim: "IPv6:")
                                                    .font(.system(size: 14))
                                                    .foregroundColor(.gray)
                                                Text(ipv6)
                                                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                                                    .foregroundColor(.primary)
                                                    .fixedSize(horizontal: false, vertical: true)
                                            }
                                        }
                                    }
                                }

                                if ips.ipv4 != nil || ips.ipv6 != nil {
                                    Divider()
                                        .padding(.horizontal, 10)
                                }

                                // Statistics Section - Same width as IP section
                                HStack(spacing: 0) {
                                    // Sent Stats - takes half width
                                    VStack(spacing: 6) {
                                        HStack(spacing: 4) {
                                            Image(systemName: "arrow.up.circle.fill")
                                                .foregroundColor(.blue)
                                                .font(.system(size: 18))
                                            Text(languageManager.tr("Uplink"))
                                                .font(.system(size: 13))
                                                .foregroundColor(.gray)
                                        }

                                        Text("\(appData.packetsSent)")
                                            .font(.system(size: 15, weight: .semibold, design: .monospaced))

                                        Text(PacketStats.formatBytes(appData.bytesSent))
                                            .font(.system(size: 11))
                                            .foregroundColor(.gray)

                                        HStack(spacing: 2) {
                                            Text("+")
                                                .font(.system(size: 10))
                                                .foregroundColor(.blue)
                                            Text(PacketStats.formatBytes(appData.bytesSentPerSecond) + "/s")
                                                .font(.system(size: 10, design: .monospaced))
                                                .foregroundColor(.blue)
                                        }
                                        .padding(.top, 2)
                                    }
                                    .frame(maxWidth: .infinity)

                                    Divider()
                                        .frame(height: 70)

                                    // Received Stats - takes half width
                                    VStack(spacing: 6) {
                                        HStack(spacing: 4) {
                                            Image(systemName: "arrow.down.circle.fill")
                                                .foregroundColor(.green)
                                                .font(.system(size: 18))
                                            Text(languageManager.tr("Downlink"))
                                                .font(.system(size: 13))
                                                .foregroundColor(.gray)
                                        }

                                        Text("\(appData.packetsReceived)")
                                            .font(.system(size: 15, weight: .semibold, design: .monospaced))

                                        Text(PacketStats.formatBytes(appData.bytesReceived))
                                            .font(.system(size: 11))
                                            .foregroundColor(.gray)

                                        HStack(spacing: 2) {
                                            Text("+")
                                                .font(.system(size: 10))
                                                .foregroundColor(.green)
                                            Text(PacketStats.formatBytes(appData.bytesReceivedPerSecond) + "/s")
                                                .font(.system(size: 10, design: .monospaced))
                                                .foregroundColor(.green)
                                        }
                                        .padding(.top, 2)
                                    }
                                    .frame(maxWidth: .infinity)
                                }
                            }
                            .padding(.horizontal, 20)
                            .padding(.vertical, 16)
                        }
                    }
                    .frame(maxWidth: .infinity)

                    Spacer()
                }.frame(minHeight: geometry.size.height)
            }
        }
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
