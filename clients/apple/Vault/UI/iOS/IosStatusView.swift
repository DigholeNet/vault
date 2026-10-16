//
//  IosStatusView.swift
//  Vault
//
//

import Network
import SwiftUI
import VaultCore

#if os(iOS)
    struct IosStatusView: View {
        var vpnManager: VpnManager
        @EnvironmentObject var appData: AppData
        @EnvironmentObject var config: VaultConfig
        @EnvironmentObject var languageManager: LanguageManager

        func onError() {
            appData.vpnOn = false
        }

        var parsedIPs: (ipv4: String?, ipv6: String?) {
            config.ip.parsedIPv4AndIPv6()
        }

        var body: some View {
            GeometryReader { _ in
                VStack {
                    Spacer()

                    VStack(spacing: 20) {
                        // VPN Status
                        Text(VpnStatusUtil.getStatus(appData.vpnStatus))
                            .bold()
                            .foregroundColor(.black)
                            .font(.system(size: 32))

                        Spacer().frame(height: 40)

                        Toggle("", isOn: $appData.vpnOn)
                            .onChange(of: appData.vpnOn) {
                                // appData.vpnOn is also written by
                                // updateVPNStatus() to sync with the system
                                // status. Only treat it as user intent when
                                // it diverges from the actual status,
                                // otherwise a status sync would re-trigger
                                // connect()/disconnect().
                                if appData.vpnOn {
                                    guard appData.vpnStatus == VpnStatus.off
                                    else { return }
                                    vpnManager.connect(onError: onError)
                                } else {
                                    guard
                                        appData.vpnStatus == VpnStatus.on
                                            || appData.vpnStatus
                                                == VpnStatus.connecting
                                    else { return }
                                    vpnManager.disconnect()
                                }
                            }
                            .toggleStyle(CustomToggleStyle())
                            .disabled(
                                appData.vpnStatus == VpnStatus.disconnecting
                            )

                        Spacer().frame(height: 30)

                        // Connection Info & Statistics (combined, no background)
                        if appData.vpnStatus == .on || appData.vpnStatus == .disconnecting {
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
                                                Text(languageManager.tr("IPv4:"))
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
                                                Text(languageManager.tr("IPv6:"))
                                                    .font(.system(size: 14))
                                                    .foregroundColor(.gray)
                                                Text(ipv6)
                                                    .font(.system(size: 14, weight: .semibold, design: .monospaced))
                                                    .foregroundColor(.primary)
                                                    .lineLimit(1)
                                                    .minimumScaleFactor(0.8)
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
                                            Text(languageManager.tr("Sent"))
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
                                            Text(languageManager.tr("Received"))
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
                }
            )
            .buttonStyle(PlainButtonStyle())
            .frame(width: 80, height: 80)
        }
    }

    #Preview {
        let config = VaultConfig()
        let appData = AppData()
        let vpnManager = VpnManager(
            config: config, appData: appData)
        IosStatusView(vpnManager: vpnManager)
            .environmentObject(appData)
            .environmentObject(config)
            .environmentObject(LanguageManager.shared)
    }
#endif
