import SwiftUI
import VaultCore

#if os(iOS)
struct IosDiagnosticsView: View {
    let vpnManager: VpnManager
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager
    @StateObject private var model = DiagnosticsViewModel()
    @State private var tab = 0

    private func tr(_ key: String) -> String { languageManager.tr(key) }

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                Text(tr("Connection Checks")).tag(0)
                Text(tr("Runtime Logs")).tag(1)
            }.pickerStyle(.segmented).labelsHidden().padding()
            if tab == 0 { checks }
            else { logs }
        }
        .background(Color(uiColor: .systemGroupedBackground))
        .navigationTitle(tr("Diagnostics"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if tab == 0 {
                    if model.running { ProgressView().accessibilityLabel(tr("Running Diagnostics...")) }
                    else {
                        Button(tr(model.result == nil ? "Start" : "Run Again")) {
                            model.run(using: vpnManager, connected: appData.vpnStatus == .connected)
                        }.disabled(appData.vpnStatus != .connected)
                    }
                }
            }
        }
        .task(id: tab) {
            if tab == 1 { await model.refreshLogs(using: vpnManager) }
        }
    }

    private var checks: some View {
        List {
            Section {
                if model.running || model.result != nil { resultHeader }
                else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(tr("Check your connection")).font(.headline)
                        Text(tr(appData.vpnStatus == .connected
                            ? "Test tunnel DNS, TCP, HTTPS, and application access. Durations are measured in milliseconds."
                            : "Connect the VPN before running diagnostics. Logs are available while disconnected."))
                            .foregroundStyle(.secondary)
                    }.padding(.vertical, 4)
                }
            }
            Section {
                ForEach(DiagnosticsPresentation.checkIDs, id: \.self) { id in checkRow(id) }
            } header: {
                HStack { Text(tr("Check")); Spacer(); Text(tr(DiagnosticsPresentation.durationHeading(model.result))) }
            } footer: {
                Text(tr("Request durations include failures and retries; Ping RTT includes replies only."))
                    .font(.footnote)
            }
            Section(tr("Ping samples")) {
                Text(tr(DiagnosticsPresentation.pingNote)).font(.caption).foregroundStyle(.secondary)
                ForEach(DiagnosticsPresentation.pingProbes(model.result)) { probe in
                    Text(probe.detail).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        .foregroundStyle(probe.succeeded ? Color.primary : .secondary)
                }
            }
            if let result = model.result, !model.running {
                if !model.passed {
                    Section {
                        Text(result.summary).font(.footnote).textSelection(.enabled)
                            .foregroundStyle(.secondary)
                    }
                }
                if let domains = result.domains, !domains.isEmpty {
                    Section(tr("Target Details")) {
                        ForEach(domains, id: \.self) { domain in
                            NavigationLink {
                                IosDiagnosticsDetailView(result: result, domain: domain)
                            } label: {
                                HStack {
                                    let state = DiagnosticsPresentation.domainState(result, domain: domain)
                                    Image(systemName: state == .passed ? "checkmark.circle.fill"
                                        : (state == .failed ? "exclamationmark.circle.fill" : "minus.circle"))
                                        .foregroundStyle(state == .passed ? Color.green
                                            : (state == .failed ? .orange : .secondary))
                                    Text(domain)
                                }
                            }
                        }
                    }
                }

            }
        }.font(.subheadline).listStyle(.insetGrouped)
    }

    private var resultHeader: some View {
        HStack(alignment: .top, spacing: 12) {
            if model.running { ProgressView().padding(.top, 4) }
            else {
                Image(systemName: model.passed ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                    .font(.title2).foregroundStyle(model.passed ? Color.green : .orange)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text(tr(model.running ? "Checking connection…" : (model.passed ? "Connectivity checks passed"
                    : (model.incomplete ? "Diagnostics incomplete" : "Connectivity issues found"))))
                    .font(.headline)
                if model.running, let startedAt = model.startedAt {
                    TimelineView(.periodic(from: .now, by: 0.1)) { _ in
                        Text(tr("Elapsed") + "  \(max(0, Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1000))) ms")
                            .monospacedDigit().foregroundStyle(.secondary)
                    }
                    ProgressView(value: Double(model.result?.checks?.count ?? 0), total: Double(DiagnosticsPresentation.checkIDs.count))
                } else if let duration = model.result?.durationMs {
                    Text(tr("Total duration") + "  \(duration) ms").monospacedDigit().foregroundStyle(.secondary)
                }
            }
        }.padding(.vertical, 4)
    }

    private func checkRow(_ id: String) -> some View {
        let check = model.result?.checks?.first { $0.id == id }
        let active = model.running && (model.result?.activeCheck ?? "dns") == id && check == nil
        return HStack(spacing: 10) {
            if active { ProgressView().frame(width: 22) }
            else {
                Image(systemName: check?.state == .passed ? "checkmark.circle.fill"
                    : (check?.state == .failed ? "exclamationmark.circle.fill" : "minus.circle.fill"))
                    .foregroundStyle(check?.state == .passed ? Color.green : (check?.state == .failed ? .orange : .gray))
                    .frame(width: 22)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(tr(DiagnosticsPresentation.label(for: id)))
                Text(check.map { $0.attempted == 0 ? tr("Not measured") : "\($0.passed)/\($0.attempted)" }
                    ?? tr(active ? "Checking" : (model.running ? "Waiting" : "Not measured")))
                    .font(.footnote).foregroundStyle(.secondary).monospacedDigit()
            }
            Spacer(minLength: 4)
            if let check, check.attempted > 0, check.sampleCount != 0 {
                Text("\(check.durationMs) ms").monospacedDigit().fixedSize()
            } else { Text("—").foregroundStyle(.secondary) }
        }.padding(.vertical, 3)
    }

    private var logs: some View {
        VStack(spacing: 12) {
            if model.loadingLogs {
                ProgressView(tr("Loading logs...")).frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.logText.isEmpty {
                Text(tr("No log content found.")).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                LogTextView(text: model.logText)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }
            if let message = model.logMessage { Text(tr(message)).font(.caption).foregroundStyle(.secondary) }
            HStack(spacing: 6) {
                Spacer()
                Button {
                    Task { await model.clearLogs(using: vpnManager) }
                } label: {
                    Label(tr(model.clearingLogs ? "Clearing…" : "Clear"), systemImage: "trash")
                        .frame(minHeight: 20)
                }
                .disabled(model.clearingLogs || model.loadingLogs || model.logText.isEmpty)
                Button {
                    UIPasteboard.general.string = model.logText
                } label: {
                    Label(tr("Copy"), systemImage: "doc.on.doc")
                        .frame(minHeight: 20)
                }
                .disabled(model.clearingLogs || model.loadingLogs || model.logText.isEmpty)
            }
            .font(.caption.weight(.medium))
            .buttonStyle(.bordered)
            .buttonBorderShape(.roundedRectangle(radius: 8))
            .controlSize(.small)
            .tint(.accentColor)
        }.padding(.horizontal).padding(.bottom, 12)
    }
}

private struct IosDiagnosticsDetailView: View {
    let result: DiagnosticsResult
    let domain: String
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        List {
            ForEach((result.probes ?? []).filter { $0.domain == domain }) { probe in
                Section {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: probe.succeeded ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                            .foregroundStyle(probe.succeeded ? Color.green : .orange)
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(alignment: .top) {
                                Text(languageManager.tr(DiagnosticsPresentation.label(for: probe.stage)))
                                Spacer(minLength: 4)
                                Text("\(probe.durationMs) ms").monospacedDigit().fixedSize()
                            }
                            Text(probe.detail).font(.footnote).foregroundStyle(.secondary).textSelection(.enabled)
                            if let tls = probe.tlsDurationMs {
                                Text("TLS  \(tls) ms").font(.footnote).monospacedDigit().foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            if (result.probes ?? []).filter({ $0.domain == domain }).isEmpty {
                Text(result.lines.filter { $0.contains(domain) }.joined(separator: "\n"))
                    .font(.footnote).textSelection(.enabled)
            }
        }.font(.subheadline).navigationTitle(domain).navigationBarTitleDisplayMode(.inline)
    }
}

#endif
