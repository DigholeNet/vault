import SwiftUI
import VaultCore

#if os(iOS)
struct IosDiagnosticsView: View {
    let vpnManager: VpnManager
    @Environment(\.scenePhase) private var scenePhase
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager
    @StateObject private var model = DiagnosticsViewModel()
    @State private var tab = 0
    @State private var copiedLogs = false

    private func tr(_ key: String) -> String { languageManager.tr(key) }

    var body: some View {
        VStack(spacing: 0) {
            VaultPageHeader(
                title: tr("Diagnostics"),
                subtitle: tr("Diagnose connections and troubleshoot network issues.")
            )
            .padding(.horizontal, 20)

            diagnosticTabs
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 12)

            if tab == 0 { checks } else { logs }
        }
        .vaultScreenBackground()
        .navigationBarHidden(true)
        .task(id: tab == 1 && scenePhase == .active) {
            guard tab == 1, scenePhase == .active else { return }
            await model.refreshLogs(using: vpnManager)
        }
    }

    private var diagnosticTabs: some View {
        HStack(spacing: 0) {
            diagnosticTab(title: tr("Connection Checks"), index: 0)
            diagnosticTab(title: tr("Runtime Logs"), index: 1)
        }
        .padding(4)
        .background(VaultTheme.surfaceMuted, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private func diagnosticTab(title: String, index: Int) -> some View {
        let selected = tab == index
        return Button {
            tab = index
        } label: {
            Text(title)
                .font(.system(size: 12, weight: selected ? .bold : .regular))
                .foregroundStyle(selected ? VaultTheme.primary : VaultTheme.textSecondary)
                .frame(maxWidth: .infinity, minHeight: 38)
                .background(
                    selected ? VaultTheme.surface : Color.clear,
                    in: RoundedRectangle(cornerRadius: 13, style: .continuous)
                )
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var checks: some View {
        ScrollView {
            VStack(spacing: 16) {
                Text(tr("Test VPN DNS, TCP and HTTPS, plus application access."))
                    .font(.system(size: 13))
                    .foregroundStyle(VaultTheme.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                VStack(alignment: .leading, spacing: 12) {
                    Text(tr("Test targets"))
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(VaultTheme.textPrimary)
                    ProbeDomainsEditor()
                }
                .vaultCard()

                if model.running || model.result != nil {
                    resultHeader.vaultCard()
                } else {
                    VaultInfoCallout(
                        title: tr("Check your connection"),
                        detail: tr(appData.vpnStatus == .connected
                            ? "Test tunnel DNS, TCP, HTTPS, and application access. Durations are measured in milliseconds."
                            :
                            "Run application access checks without connecting. Tunnel checks are available after connecting. Logs remain available.")
                    )
                }

                Button {
                    model.run(using: vpnManager)
                } label: {
                    Label(
                        tr(model.running ? "Running Diagnostics..." : (model.result == nil ? "Start" : "Run Again")),
                        systemImage: "waveform.path.ecg"
                    )
                }
                .buttonStyle(VaultPrimaryButtonStyle())
                .disabled(model.running)

                VStack(spacing: 12) {
                    ForEach(DiagnosticsPresentation.visibleChecks(model.result), id: \.self) { id in
                        let probes = (model.result?.probes ?? []).filter { $0.stage == id }
                        if probes.isEmpty {
                            checkRow(id).vaultCard()
                        } else {
                            DisclosureGroup {
                                VStack(alignment: .leading, spacing: 12) {
                                    if DiagnosticsPresentation.pingCheckIDs.contains(id) {
                                        Text(tr(DiagnosticsPresentation.pingNote))
                                            .font(.system(size: 12)).foregroundStyle(VaultTheme.textSecondary)
                                    }
                                    ForEach(probes, id: \.id) { probe in
                                        VStack(alignment: .leading, spacing: 6) {
                                            HStack {
                                                Text(probe.domain)
                                                Spacer()
                                                Text("\(probe.durationMs) ms").monospacedDigit()
                                            }
                                            Text(probe.displayDetail)
                                                .foregroundStyle(VaultTheme.textSecondary)
                                                .textSelection(.enabled)
                                            if let tls = probe.tlsDurationMs {
                                                Text("TLS  \(tls) ms")
                                                    .monospacedDigit().foregroundStyle(VaultTheme.textSecondary)
                                            }
                                        }
                                        .font(.system(size: 12))
                                    }
                                }
                                .padding(.top, 12)
                            } label: {
                                checkRow(id)
                            }
                            .tint(VaultTheme.primary)
                            .vaultCard()
                        }
                    }
                }

                if let result = model.result, !model.running {
                    if !model.passed {
                        Text(result.summary)
                            .font(.system(size: 12))
                            .textSelection(.enabled)
                            .foregroundStyle(VaultTheme.textSecondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if let domains = result.domains, !domains.isEmpty {
                        VStack(spacing: 12) {
                            ForEach(domains, id: \.self) { domain in
                                NavigationLink {
                                    IosDiagnosticsDetailView(result: result, domain: domain)
                                } label: {
                                    HStack {
                                        let state = DiagnosticsPresentation.domainState(result, domain: domain)
                                        Image(systemName: state == .passed ? "checkmark.circle.fill"
                                            : (state == .failed ? "exclamationmark.circle.fill" : "minus.circle"))
                                            .foregroundStyle(state == .passed ? VaultTheme.primary
                                                : (state == .failed ? .orange : VaultTheme.textSecondary))
                                        Text(domain).foregroundStyle(VaultTheme.textPrimary)
                                        Spacer()
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 12))
                                            .foregroundStyle(VaultTheme.textDisabled)
                                    }
                                    .vaultCard()
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }

                Text(tr("Request durations include failures and retries; Ping RTT includes replies only."))
                    .font(.system(size: 12))
                    .foregroundStyle(VaultTheme.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
    }

    private var resultHeader: some View {
        HStack(alignment: .top, spacing: 12) {
            if model.running {
                ProgressView().padding(.top, 4)
            } else {
                Image(systemName: model.passed ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                    .font(.title2).foregroundStyle(model.passed ? VaultTheme.primary : .orange)
            }
            VStack(alignment: .leading, spacing: 8) {
                Text(tr(DiagnosticsPresentation.resultTitle(model.result, running: model.running)))
                    .font(.system(size: 15, weight: .bold))
                    .foregroundStyle(VaultTheme.textPrimary)
                if model.running, let startedAt = model.startedAt {
                    TimelineView(.periodic(from: .now, by: 0.1)) { _ in
                        Text(tr("Elapsed") + "  \(max(0, Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1000))) ms")
                            .monospacedDigit().foregroundStyle(VaultTheme.textSecondary)
                    }
                    ProgressView(
                        value: Double(model.result?.checks?.count ?? 0),
                        total: Double(DiagnosticsPresentation.visibleChecks(model.result).count)
                    )
                    .tint(VaultTheme.primary)
                } else if let duration = model.result?.durationMs {
                    Text(tr("Total duration") + "  \(duration) ms")
                        .monospacedDigit().foregroundStyle(VaultTheme.textSecondary)
                }
            }
        }
    }

    private func checkRow(_ id: String) -> some View {
        let row = DiagnosticsPresentation.checkRow(id, result: model.result, running: model.running)
        return HStack(spacing: 10) {
            if row.active {
                ProgressView().frame(width: 22)
            } else {
                Image(systemName: row.state == .passed ? "checkmark.circle.fill"
                    : (row.state == .failed ? "exclamationmark.circle.fill" : "minus.circle.fill"))
                    .foregroundStyle(row.state == .passed ? VaultTheme.primary
                        : (row.state == .failed ? .orange : VaultTheme.textDisabled))
                    .frame(width: 22)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(tr(DiagnosticsPresentation.label(for: id)))
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(VaultTheme.textPrimary)
                Text(tr(row.resultText))
                    .font(.system(size: 12))
                    .foregroundStyle(row.state == .passed ? VaultTheme.primary : VaultTheme.textSecondary)
                    .monospacedDigit()
            }
            Spacer(minLength: 4)
            if let duration = row.durationMs {
                Text("\(duration) ms")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(VaultTheme.textSecondary)
                    .fixedSize()
            } else {
                Text("—").foregroundStyle(VaultTheme.textDisabled)
            }
        }
    }

    private var logs: some View {
        VStack(spacing: 12) {
            Group {
                if model.loadingLogs {
                    ProgressView(tr("Loading logs..."))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if model.logText.isEmpty {
                    Text(tr("No log content found."))
                        .foregroundStyle(VaultTheme.textDisabled)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(VaultTheme.surfaceMuted)
                } else {
                    LogTextView(text: model.logText)
                }
            }
            .layoutPriority(-1)
            .background(VaultTheme.surface)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(VaultTheme.outline)
            }

            Text(copiedLogs ? tr("Copied to clipboard.") : tr("Select log text to copy details for troubleshooting."))
                .font(.system(size: 12))
                .foregroundStyle(copiedLogs ? VaultTheme.primary : VaultTheme.textSecondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let message = model.logMessage {
                Text(tr(message)).font(.caption).foregroundStyle(VaultTheme.textSecondary)
            }
            HStack(spacing: 12) {
                Button {
                    Task { await model.clearLogs(using: vpnManager) }
                } label: {
                    Label(tr(model.clearingLogs ? "Clearing…" : "Clear"), systemImage: "trash")
                }
                .buttonStyle(VaultSecondaryButtonStyle())
                .disabled(model.clearingLogs || model.loadingLogs || model.logText.isEmpty)
                Button {
                    UIPasteboard.general.string = model.logText
                    copiedLogs = true
                    Task {
                        try? await Task.sleep(for: .seconds(2))
                        copiedLogs = false
                    }
                } label: {
                    Label(tr("Copy"), systemImage: "doc.on.doc")
                }
                .buttonStyle(VaultSecondaryButtonStyle())
                .disabled(model.clearingLogs || model.loadingLogs || model.logText.isEmpty)
            }
        }
        .padding(.horizontal, 20)
        .padding(.bottom, 8)
    }
}

private struct IosDiagnosticsDetailView: View {
    let result: DiagnosticsResult
    let domain: String
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        List {
            ForEach((result.probes ?? []).filter { $0.domain == domain }, id: \.id) { probe in
                Section {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: probe.succeeded ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                            .foregroundStyle(probe.succeeded ? VaultTheme.primary : .orange)
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(alignment: .top) {
                                Text(languageManager.tr(DiagnosticsPresentation.label(for: probe.stage)))
                                Spacer(minLength: 4)
                                Text("\(probe.durationMs) ms").monospacedDigit().fixedSize()
                            }
                            Text(probe.displayDetail)
                                .font(.footnote).foregroundStyle(VaultTheme.textSecondary).textSelection(.enabled)
                            if let tls = probe.tlsDurationMs {
                                Text("TLS  \(tls) ms")
                                    .font(.footnote).monospacedDigit().foregroundStyle(VaultTheme.textSecondary)
                            }
                        }
                    }
                }
                .listRowBackground(VaultTheme.surface)
            }
            if (result.probes ?? []).filter({ $0.domain == domain }).isEmpty {
                Text(result.lines.filter { $0.contains(domain) }.joined(separator: "\n"))
                    .font(.footnote).textSelection(.enabled)
                    .listRowBackground(VaultTheme.surface)
            }
        }
        .font(.subheadline)
        .scrollContentBackground(.hidden)
        .vaultScreenBackground()
        .navigationTitle(domain)
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarHidden(false)
    }
}
#endif
