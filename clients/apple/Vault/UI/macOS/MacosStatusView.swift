#if os(macOS)
import AppKit
import SwiftUI
import VaultCore

struct MacosStatusView: View {
    let vpnManager: VpnManager
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager
    @State private var tab = 0
    @StateObject private var model = DiagnosticsViewModel()
    private var result: DiagnosticsResult? { model.result }
    private var running: Bool { model.running }
    private var cancelRequested: Bool { model.cancelRequested }
    private var startedAt: TimeInterval? { model.startedAt }
    private var progressReceived: TimeInterval { model.progressReceived }
    private var completedAt: Date? { model.completedAt }
    private var logText: String { model.logText }
    private var loadingLogs: Bool { model.loadingLogs }
    @State private var logFilter = "all"
    @State private var search = ""
    @State private var followsTail = true

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $tab) {
                    Text(languageManager.tr("Connection Diagnostics")).tag(0)
                    Text(languageManager.tr("Runtime Logs")).tag(1)
                }.pickerStyle(.segmented).labelsHidden().frame(width: 260)
                Spacer()
                if tab == 0 {
                    if running {
                        Button(languageManager.tr(cancelRequested ? "Cancelling…" : "Cancel")) {
                            model.cancel(using: vpnManager)
                        }.disabled(cancelRequested)
                    } else {
                        Button(action: diagnose) {
                            Label(languageManager.tr(result == nil ? "Run Diagnostics" : "Run Again"), systemImage: "arrow.clockwise")
                        }.disabled(appData.vpnStatus != .connected)
                    }
                }
            }.padding(20)
            Divider()
            if tab == 0 { diagnostics }
            else { logs }
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
                Button { copy(tab == 0 ? diagnosticText : filteredLogs) } label: {
                    Label(languageManager.tr("Copy"), systemImage: "doc.on.doc")
                }
                .disabled(tab == 0 ? result == nil : filteredLogs.isEmpty)
            }.padding(16)
        }
        .task(id: tab) {
            guard tab == 1 else { return }
            await model.refreshLogs(using: vpnManager)
        }
    }

    private var diagnostics: some View {
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
            if running { ProgressView().controlSize(.large).padding(8) }
            else {
                Image(systemName: passed ? "checkmark.circle.fill" : (incomplete ? "clock.fill" : "exclamationmark.circle.fill"))
                    .font(.system(size: 28)).foregroundStyle(passed ? Color.green : (incomplete ? .orange : .red))
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(languageManager
                    .tr(running ? "Checking connection…" :
                        (passed ? "Connectivity checks passed" : (incomplete ? "Diagnostics incomplete" : "Connectivity issues found"))))
                    .font(.system(size: 14, weight: .semibold))
                if running, let startedAt {
                    TimelineView(.periodic(from: .now, by: 0.1)) { context in
                        Text(languageManager
                            .tr("Elapsed") + "  \(max(0, Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1000))) ms")
                            .font(.body).monospacedDigit().foregroundStyle(.secondary)
                    }
                    ProgressView(value: Double(result?.checks?.count ?? 0), total: Double(DiagnosticsPresentation.checkIDs.count))
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
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "network").foregroundStyle(.secondary)
            Text(appData.vpnStatus == .connected || appData.isRecovering
                ?
                (appData.assignedIp.isEmpty ? languageManager.tr("Waiting for server-assigned addresses…") : appData.assignedIp
                    .replacingOccurrences(
                        of: "/",
                        with: "  ·  "
                    ))
                : languageManager.tr("Disconnected"))
                .font(.system(.body, design: .monospaced)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
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
            ForEach(DiagnosticsPresentation.checkIDs, id: \.self) { id in
                let check = result?.checks?.first { $0.id == id }
                let active = running && (result?.activeCheck ?? "dns") == id && check == nil
                HStack(spacing: 8) {
                    if active { ProgressView().controlSize(.mini).frame(width: 14) }
                    else {
                        Image(systemName: check?
                            .state == .passed ? "checkmark.circle.fill" : (check?.state == .failed ? "xmark.circle.fill" : "minus.circle"))
                            .foregroundStyle(check?.state == .passed ? Color.green : (check?.state == .failed ? Color.red : .secondary))
                            .frame(width: 14)
                    }
                    Text(languageManager.tr(checkLabel(id))).font(.body)
                    Spacer()
                    Text(check.map { $0.attempted == 0 ? languageManager.tr("Not measured") : "\($0.passed)/\($0.attempted)" }
                        ?? languageManager.tr(active ? "Checking" : (running ? "Waiting" : "Not measured")))
                        .font(.body).monospacedDigit().foregroundStyle(.secondary).frame(width: 80)
                    if let check {
                        Text(check.sampleCount == 0 || check.attempted == 0 ? "—" : "\(check.durationMs) ms")
                            .font(.system(.body, design: .monospaced)).frame(width: 100, alignment: .trailing)
                            .help(languageManager.tr(DiagnosticsPresentation.pingCheckIDs.contains(id)
                                    ? "Mean round-trip time of received replies." : "Mean request time, including failures and retries."))
                    } else if active {
                        TimelineView(.periodic(from: .now, by: 0.1)) { context in
                            Text("\(max(0, Int((ProcessInfo.processInfo.systemUptime - progressReceived) * 1000))) ms")
                                .font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
                        }.frame(width: 100, alignment: .trailing)
                    } else { Text("—").foregroundStyle(.secondary).frame(width: 100, alignment: .trailing) }
                }.padding(12)
                if id != DiagnosticsPresentation.checkIDs.last { Divider() }
            }
        }.clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.quaternary))
    }

    private var logs: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("", selection: $logFilter) {
                    Text(languageManager.tr("All")).tag("all")
                    Text(languageManager.tr("Application")).tag("app")
                    Text(languageManager.tr("Tunnel")).tag("ne")
                }.pickerStyle(.segmented).labelsHidden().frame(width: 230)
                TextField(languageManager.tr("Search logs"), text: $search)
                    .textFieldStyle(.roundedBorder)
            }.padding(16)
            if loadingLogs { ProgressView(languageManager.tr("Loading logs...")).frame(maxWidth: .infinity, maxHeight: .infinity) }
            else if filteredLogs.isEmpty {
                Text(languageManager.tr("No matching logs.")).foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else { LogTextView(text: filteredLogs, followsTail: followsTail) }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var filteredLogs: String {
        DiagnosticsPresentation.filteredLogs(logText, source: logFilter, search: search)
    }

    private var passed: Bool { model.passed }
    private var incomplete: Bool { model.incomplete }
    private var diagnosticText: String { model.diagnosticText }
    private func checkLabel(_ id: String) -> String { DiagnosticsPresentation.label(for: id) }
    private func diagnose() { model.run(using: vpnManager, connected: appData.vpnStatus == .connected) }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
#endif
