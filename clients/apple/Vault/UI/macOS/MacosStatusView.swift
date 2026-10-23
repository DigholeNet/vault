//
//  MacosStatusView.swift
//  Vault
//
//

import Network
import SwiftUI
import VaultCore

#if os(macOS)
    struct MacosStatusView: View {
        @EnvironmentObject var appData: AppData
        @EnvironmentObject var config: VaultConfig
        @EnvironmentObject var languageManager: LanguageManager

        var parsedIPs: (ipv4: String?, ipv6: String?) {
            config.ip.parsedIPv4AndIPv6()
        }

        var body: some View {
            VStack(spacing: 24) {
                Spacer()

                // Connection Info & Statistics
                let ips = parsedIPs

                VStack(spacing: 20) {
                    // IP Addresses Section
                    if ips.ipv4 != nil || ips.ipv6 != nil {
                        VStack(alignment: .leading, spacing: 8) {
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
                                    Spacer()
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
                                    Spacer()
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 20)
                    }

                    if ips.ipv4 != nil || ips.ipv6 != nil {
                        Divider()
                            .padding(.horizontal, 20)
                    }
                    HStack(spacing: 0) {
                        // Sent Stats
                        VStack(spacing: 8) {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.up.circle.fill")
                                    .foregroundColor(.blue)
                                    .font(.system(size: 20))
                                Text(languageManager.tr("Sent"))
                                    .font(.system(size: 14))
                                    .foregroundColor(.gray)
                            }

                            Text("\(appData.packetsSent)")
                                .font(.system(size: 18, weight: .semibold, design: .monospaced))

                            Text(PacketStats.formatBytes(appData.bytesSent))
                                .font(.system(size: 12))
                                .foregroundColor(.gray)

                            HStack(spacing: 2) {
                                Text("+")
                                    .font(.system(size: 11))
                                    .foregroundColor(.blue)
                                Text(PacketStats.formatBytes(appData.bytesSentPerSecond) + "/s")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.blue)
                            }
                            .padding(.top, 2)
                        }
                        .frame(maxWidth: .infinity)

                        Divider()
                            .frame(height: 80)

                        // Received Stats
                        VStack(spacing: 8) {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.down.circle.fill")
                                    .foregroundColor(.green)
                                    .font(.system(size: 20))
                                Text(languageManager.tr("Received"))
                                    .font(.system(size: 14))
                                    .foregroundColor(.gray)
                            }

                            Text("\(appData.packetsReceived)")
                                .font(.system(size: 18, weight: .semibold, design: .monospaced))

                            Text(PacketStats.formatBytes(appData.bytesReceived))
                                .font(.system(size: 12))
                                .foregroundColor(.gray)

                            HStack(spacing: 2) {
                                Text("+")
                                    .font(.system(size: 11))
                                    .foregroundColor(.green)
                                Text(PacketStats.formatBytes(appData.bytesReceivedPerSecond) + "/s")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.green)
                            }
                            .padding(.top, 2)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .padding(.horizontal, 20)
                }
                .padding(.vertical, 20)

                Spacer()
            }
            .frame(minWidth: 400, minHeight: 250)
            .padding(20)
        }
    }

    #Preview {
        let appData = AppData()
        let config = VaultConfig()
        MacosStatusView()
            .environmentObject(appData)
            .environmentObject(config)
            .environmentObject(LanguageManager.shared)
    }
#endif
