#if os(macOS)
import AppKit
import SwiftUI
import VaultCore

struct MacosStatusView: View {
    let vpnManager: VpnManager
    @EnvironmentObject var languageManager: LanguageManager
    @State private var tab = 0
    @StateObject private var model = DiagnosticsViewModel()
    @State private var followsTail = true
    @State private var windowVisible = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $tab) {
                    Text(languageManager.tr("Connection Diagnostics")).tag(0)
                    Text(languageManager.tr("Runtime Logs")).tag(1)
                }.pickerStyle(.segmented).labelsHidden().frame(width: 260)
                Spacer()
                if tab == 0 { MacosDiagnosticsAction(vpnManager: vpnManager, model: model) }
            }.padding(20)
            Divider()
            if tab == 0 { MacosConnectionDiagnostics(vpnManager: vpnManager, model: model) } else { logs }
            Divider()
            HStack {
                if tab == 1 {
                    Toggle(languageManager.tr("Auto-scroll"), isOn: $followsTail).toggleStyle(.switch).controlSize(.small)
                }
                Spacer()
                if tab == 1 {
                    if let message = model.logMessage {
                        Text(languageManager.tr(message)).font(.caption).foregroundStyle(.secondary)
                    }
                    Button {
                        Task { await model.clearLogs(using: vpnManager) }
                    } label: {
                        Label(languageManager.tr(model.clearingLogs ? "Clearing…" : "Clear"), systemImage: "trash")
                    }.disabled(model.clearingLogs)
                }
                Button { copy(tab == 0 ? model.diagnosticText : model.filteredLogText) } label: {
                    Label(languageManager.tr("Copy"), systemImage: "doc.on.doc")
                }
                .disabled(tab == 0 ? model.result == nil : model.filteredLogText.isEmpty)
            }.padding(16)
        }
        .onAppear {
            windowVisible = NSApp.windows.first { $0.identifier?.rawValue == "status" }?
                .occlusionState.contains(.visible) ?? false
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didChangeOcclusionStateNotification)) { notification in
            guard let window = notification.object as? NSWindow, window.identifier?.rawValue == "status" else { return }
            windowVisible = window.occlusionState.contains(.visible)
        }
        .task(id: tab == 1 && windowVisible) {
            guard tab == 1, windowVisible else { return }
            await model.refreshLogs(using: vpnManager)
        }
    }

    private var logs: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $model.logFilter) {
                    Text(languageManager.tr("All")).tag("all")
                    Text(languageManager.tr("Application")).tag("app")
                    Text(languageManager.tr("Tunnel")).tag("ne")
                }.pickerStyle(.segmented).labelsHidden().frame(width: 230)
                TextField(languageManager.tr("Search logs"), text: $model.logSearch)
                    .textFieldStyle(.roundedBorder)
            }.padding(16)
            if model.loadingLogs {
                ProgressView(languageManager.tr("Loading logs..."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.filteredLogText.isEmpty {
                Text(languageManager.tr("No matching logs."))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else { LogTextView(text: model.filteredLogText, followsTail: followsTail) }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

// Observe traffic state only while the diagnostics tab is visible. Runtime Logs
// must not redraw when the provider publishes its per-second byte counters.
private struct MacosDiagnosticsAction: View {
    let vpnManager: VpnManager
    @ObservedObject var model: DiagnosticsViewModel
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        if model.running {
            Button(languageManager.tr(model.cancelRequested ? "Cancelling…" : "Cancel")) {
                model.cancel(using: vpnManager)
            }.disabled(model.cancelRequested)
        } else {
            Button {
                model.run(using: vpnManager, connected: appData.vpnStatus == .connected)
            } label: {
                Label(languageManager.tr(model.result == nil ? "Run Diagnostics" : "Run Again"), systemImage: "arrow.clockwise")
            }.disabled(appData.vpnStatus != .connected)
        }
    }
}

private struct MacosConnectionDiagnostics: View {
    let vpnManager: VpnManager
    @ObservedObject var model: DiagnosticsViewModel
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager
    private var result: DiagnosticsResult? { model.result }
    private var running: Bool { model.running }
    private var startedAt: TimeInterval? { model.startedAt }
    private var progressReceived: TimeInterval { model.progressReceived }
    private var completedAt: Date? { model.completedAt }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                if running || result != nil {
                    resultHeader
                    sessionAddresses
                    checkTable
                    Text(languageManager.tr(DiagnosticsPresentation.pingNote))
                        .font(.caption).foregroundStyle(.secondary)
                    if !DiagnosticsPresentation.pingProbes(result).isEmpty {
                        DisclosureGroup(languageManager.tr("Ping samples")) {
                            ForEach(DiagnosticsPresentation.pingProbes(result), id: \.id) { probe in
                                Text(probe.displayDetail).font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(probe.succeeded ? Color.primary : .secondary)
                                    .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    if running {
                        Text(languageManager
                            .tr(result?
                                .activeCheck == "icmp" ? "Completing optional tunnel observations…" :
                                "Results update as each check completes."))
                            .font(.body).foregroundStyle(.secondary)
                    }
                    if let result, !result.lines.isEmpty {
                        DisclosureGroup(languageManager.tr("Target Details")) {
                            let domains = result.domains ?? []
                            ForEach(domains, id: \.self) { domain in
                                DisclosureGroup(domain) {
                                    if let probes = result.probes, probes.contains(where: { $0.domain == domain }) {
                                        VStack(alignment: .leading, spacing: 12) {
                                            ForEach(probes.filter { $0.domain == domain }, id: \.id) { probe in
                                                HStack(alignment: .top, spacing: 8) {
                                                    Image(systemName: probe.succeeded ? "checkmark.circle.fill" : "xmark.circle.fill")
                                                        .foregroundStyle(probe.succeeded ? Color.green : .red)
                                                    VStack(alignment: .leading, spacing: 4) {
                                                        Text(languageManager.tr(DiagnosticsPresentation.label(for: probe.stage)))
                                                            .font(.body.weight(.medium))
                                                        Text(probe.displayDetail).font(.system(.body, design: .monospaced))
                                                            .foregroundStyle(.secondary).textSelection(.enabled)
                                                            .fixedSize(horizontal: false, vertical: true)
                                                        if let tls = probe.tlsDurationMs {
                                                            Text("TLS  \(tls) ms").font(.system(.body, design: .monospaced))
                                                                .foregroundStyle(.secondary)
                                                        }
                                                    }
                                                    Spacer(minLength: 8)
                                                    Text("\(probe.durationMs) ms").font(.system(.body, design: .monospaced))
                                                }
                                            }
                                        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                                            .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 6))
                                    } else {
                                        Text(result.lines.filter { $0.contains(domain) }.joined(separator: "\n"))
                                            .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                                            .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 8)
                                    }
                                }.padding(.vertical, 5)
                            }
                            if !running && !result.summary.hasPrefix("OK") {
                                Text(result.summary).font(.body).foregroundStyle(.secondary)
                                    .textSelection(.enabled).padding(.top, 8)
                            }
                        }.font(.body)
                    }
                } else {
                    VStack(spacing: 16) {
                        Image(systemName: "stethoscope").font(.system(size: 42)).foregroundStyle(.blue)
                        Text(languageManager.tr("Check your connection")).font(.system(size: 15, weight: .semibold))
                        Text(languageManager.tr(appData.vpnStatus == .connected
                                ? "Test tunnel DNS, TCP, HTTPS, and application access. Durations are measured in milliseconds."
                                : "Connect the VPN before running diagnostics. Logs are available while disconnected."))
                            .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 450)
                        Button(languageManager.tr("Run Diagnostics"), action: diagnose)
                            .buttonStyle(.borderedProminent).disabled(appData.vpnStatus != .connected)
                    }.frame(maxWidth: .infinity).padding(.vertical, 70)
                }
            }.padding(24)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var resultHeader: some View {
        HStack(alignment: .top, spacing: 14) {
            if running { ProgressView().controlSize(.large).padding(8) } else {
                Image(systemName: passed ? "checkmark.circle.fill" : (incomplete ? "clock.fill" : "exclamationmark.circle.fill"))
                    .font(.system(size: 28)).foregroundStyle(passed ? Color.green : (incomplete ? .orange : .red))
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(languageManager.tr(DiagnosticsPresentation.resultTitle(result, running: running)))
                    .font(.system(size: 14, weight: .semibold))
                if running, let startedAt {
                    TimelineView(.periodic(from: .now, by: 0.1)) { _ in
                        Text(languageManager
                            .tr("Elapsed") + "  \(max(0, Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1000))) ms")
                            .font(.body).monospacedDigit().foregroundStyle(.secondary)
                    }
                    ProgressView(
                        value: Double(result?.checks?.count ?? 0),
                        total: Double(DiagnosticsPresentation.visibleChecks(result).count)
                    )
                    .frame(maxWidth: 300)
                } else {
                    HStack(spacing: 10) {
                        if let completedAt { Text(completedAt, style: .time) }
                        if let duration = result?.durationMs { Text(languageManager.tr("Total duration") + "  \(duration) ms") }
                    }.font(.body).monospacedDigit().foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
    }

    private var sessionAddresses: some View {
        let active = appData.vpnStatus == .connected || appData.isRecovering
        let addresses = appData.assignedIp.parsedIPv4AndIPv6()
        let hasTunnelAddresses = addresses.ipv4 != nil || addresses.ipv6 != nil
        return VStack(alignment: .leading, spacing: 10) {
            if active, !appData.publicIp.isEmpty {
                MacosStatusAddressRow(
                    title: "WAN", address: appData.publicIp, symbol: "network", color: .accentColor
                )
                Divider()
            }
            if active, hasTunnelAddresses {
                VStack(spacing: 8) {
                    if let ipv4 = addresses.ipv4 {
                        MacosStatusAddressRow(title: "IPv4", address: ipv4, symbol: "server.rack", color: .blue)
                    }
                    if let ipv6 = addresses.ipv6 {
                        MacosStatusAddressRow(title: "IPv6", address: ipv6, symbol: "server.rack", color: .green)
                    }
                }
            } else {
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "server.rack")
                        .font(.system(size: 13)).foregroundStyle(.secondary).frame(width: 16)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(languageManager.tr("Tunnel")).font(.system(size: 12)).foregroundStyle(.secondary)
                        Text(languageManager.tr(active ? "Waiting for server-assigned addresses…" : "Disconnected"))
                            .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                }
            }
        }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
    }

    private var checkTable: some View {
        VStack(spacing: 0) {
            HStack {
                Text(languageManager.tr("Check"))
                Spacer()
                Text(languageManager.tr("Result")).frame(width: 80)
                Text(languageManager.tr("Average duration")).frame(width: 100, alignment: .trailing)
            }.font(.body).foregroundStyle(.secondary).padding(12).background(.quaternary.opacity(0.4))
            ForEach(DiagnosticsPresentation.visibleChecks(result), id: \.self) { id in
                let row = DiagnosticsPresentation.checkRow(id, result: result, running: running)
                HStack(spacing: 8) {
                    if row.active { ProgressView().controlSize(.mini).frame(width: 14) } else {
                        Image(systemName: row.state == .passed ? "checkmark.circle.fill"
                            : (row.state == .failed ? "xmark.circle.fill" : "minus.circle"))
                            .foregroundStyle(row.state == .passed ? Color.green : (row.state == .failed ? Color.red : .secondary))
                            .frame(width: 14)
                    }
                    Text(languageManager.tr(checkLabel(id))).font(.body)
                    Spacer()
                    Text(languageManager.tr(row.resultText))
                        .font(.body).monospacedDigit().foregroundStyle(.secondary).frame(width: 80)
                    if row.state != nil {
                        Text(row.durationMs.map { "\($0) ms" } ?? "—")
                            .font(.system(.body, design: .monospaced)).frame(width: 100, alignment: .trailing)
                            .help(languageManager.tr(DiagnosticsPresentation.pingCheckIDs.contains(id)
                                    ? "Mean round-trip time of received replies." : "Mean request time, including failures and retries."))
                    } else if row.active {
                        TimelineView(.periodic(from: .now, by: 0.1)) { _ in
                            Text("\(max(0, Int((ProcessInfo.processInfo.systemUptime - progressReceived) * 1000))) ms")
                                .font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
                        }.frame(width: 100, alignment: .trailing)
                    } else { Text("—").foregroundStyle(.secondary).frame(width: 100, alignment: .trailing) }
                }.padding(12)
                if id != DiagnosticsPresentation.visibleChecks(result).last { Divider() }
            }
        }.clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.quaternary))
    }

    private var passed: Bool { model.passed }
    private var incomplete: Bool { model.incomplete }
    private func checkLabel(_ id: String) -> String { DiagnosticsPresentation.label(for: id) }
    private func diagnose() { model.run(using: vpnManager, connected: appData.vpnStatus == .connected) }
}
#endif
