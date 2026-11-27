import SwiftUI
import VaultCore

#if os(iOS)
struct IosDiagnosticsView: View {
    let vpnManager: VpnManager
    @Environment(\.scenePhase) private var scenePhase
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager
    @State private var pageWidth: CGFloat = .infinity
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    private var pageInset: CGFloat { pageWidth <= 360 ? 16 : 20 }

    @StateObject private var model = DiagnosticsViewModel()
    @State private var tab = 0
    @State private var lastCopy: Date?
    @State private var expandedChecks: Set<String> = []
    @State private var confirmsLogClear = false

    private func tr(_ key: String) -> String { languageManager.tr(key) }

    var body: some View {
        VStack(spacing: 0) {
            VaultPageHeader(
                title: tr("Diagnostics"),
                subtitle: tr("Diagnose connections and troubleshoot network issues.")
            )
            .padding(.horizontal, pageInset)

            diagnosticTabs
                .padding(.horizontal, pageInset)
                .padding(.top, 16)
                .padding(.bottom, 16)

            if tab == 0 { checks } else { logs }
        }
        .onGeometryChange(for: CGFloat.self, of: { $0.size.width }) { pageWidth = $0 }
        .vaultScreenBackground()
        .navigationBarHidden(true)
        .vaultLogClearConfirmation(isPresented: $confirmsLogClear) {
            Task { await model.clearLogs(using: vpnManager) }
        }
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
            if !selected { IosKeyboardDismissal.dismiss() }
            tab = index
        } label: {
            Text(title)
                .font(.caption.weight(selected ? .bold : .regular))
                .foregroundStyle(selected ? VaultTheme.primary : VaultTheme.textSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 4)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity, minHeight: 44)
                .background(
                    selected ? VaultTheme.surface : Color.clear,
                    in: RoundedRectangle(cornerRadius: 13, style: .continuous)
                )
                .contentShape(Rectangle())
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
                        .font(.subheadline.bold())
                        .foregroundStyle(VaultTheme.textPrimary)
                    ProbeDomainsEditor(stacked: true)
                }
                .vaultCard(padding: 18)

                if model.running || model.result != nil || appData.vpnStatus != .connected {
                    resultHeader
                }

                Button {
                    IosKeyboardDismissal.dismiss()
                    if model.running {
                        model.cancel(using: vpnManager)
                    } else {
                        expandedChecks.removeAll()
                        model.run(using: vpnManager)
                    }
                } label: {
                    if model.running {
                        Text(runTitle)
                    } else {
                        Label(runTitle, systemImage: "waveform.path.ecg").imageScale(.large)
                    }
                }
                .buttonStyle(DiagnosticButtonStyle(
                    kind: model.cancelRequested ? .cancelling : (model.running ? .cancel : .primary)
                ))
                .accessibilityIdentifier("diagnostics.run")
                .disabled(model.cancelRequested)

                if let result = model.result, result.snapshot != nil {
                    VStack(spacing: 12) {
                        ForEach(DiagnosticsPresentation.visibleChecks(result), id: \.self) { id in
                            checkCard(id, result: result)
                        }
                    }
                }

                if let result = model.result, !model.running {
                    if !model.passed && !model.wasCancelled {
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
                                        VaultStatusIcon(
                                            kind: state == .passed ? .passed : (state == .failed ? .failed : .skipped),
                                            size: 22
                                        )
                                            .foregroundStyle(state == .passed ? VaultTheme.primary
                                                : (state == .failed ? VaultTheme.danger : VaultTheme.textSecondary))
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

                if model.result?.snapshot != nil {
                    Text(tr("Request durations include failures and retries; Ping RTT includes replies only."))
                        .font(.caption)
                        .foregroundStyle(VaultTheme.textSecondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(.horizontal, pageInset)
            .padding(.bottom, 20)
        }
        .scrollDismissesKeyboard(.interactively)
    }

    private var runTitle: String {
        if model.running { return tr(model.cancelRequested ? "Cancelling…" : "Cancel checks") }
        if model.result != nil { return tr("Run Again") }
        return tr(appData.vpnStatus == .connected ? "Start" : "Start Direct Checks")
    }

    private var resultHeader: some View {
        let idle = !model.running && model.result == nil
        let hasIssue = !idle && !model.running && !model.wasCancelled && !model.passed
        let neutral = idle || model.wasCancelled
        let issueTint = model.incomplete ? VaultTheme.diagnosticWarning : VaultTheme.danger
        let issueSurface = model.incomplete ? diagnosticWarningSurface : VaultTheme.failureSurface
        let tint = neutral || model.cancelRequested ? VaultTheme.textSecondary
            : (hasIssue ? issueTint : VaultTheme.primaryDark)
        return HStack(alignment: .center, spacing: 12) {
            if model.running {
                ProgressView().tint(VaultTheme.primary).frame(width: 28, height: 28)
            } else {
                Group {
                    if neutral {
                        Image(systemName: "info.circle")
                            .symbolRenderingMode(.monochrome)
                            .font(.system(size: 18, weight: .semibold))
                    } else {
                        VaultStatusIcon(kind: hasIssue ? .failed : .passed, size: 24)
                    }
                }
                    .foregroundStyle(model.passed ? VaultTheme.primary : tint)
                    .frame(width: 28, height: 28)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(tr(idle ? "Direct checks and runtime logs are available" :
                    model.statusTitle))
                    .font(.footnote.bold())
                    .foregroundStyle(model.passed || model.wasCancelled ? VaultTheme.textPrimary : tint)
                if idle {
                    Text(tr("Connect to run the full tunnel checks."))
                        .font(.caption)
                        .foregroundStyle(VaultTheme.textSecondary)
                } else if model.wasCancelled {
                    Text(tr("Completed results are still available."))
                        .font(.caption)
                        .foregroundStyle(VaultTheme.textSecondary)
                } else if model.running, !model.cancelRequested, let startedAt = model.startedAt {
                    TimelineView(.periodic(from: .now, by: 0.1)) { _ in
                        let elapsed = max(0, Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1000))
                        Text(tr("Elapsed") + "  \(elapsed) ms")
                            .font(.caption).monospacedDigit().foregroundStyle(VaultTheme.primary)
                    }
                    let planned = model.result?.snapshot?.plannedChecks.count ?? 0
                    if planned > 0 {
                        ProgressView(value: Double(model.result?.checks?.count ?? 0), total: Double(planned))
                            .tint(VaultTheme.primary)
                    }
                } else if !model.running, let result = model.result, let snapshot = result.snapshot {
                    let count = snapshot.plannedChecks.count
                    let passed = snapshot.checks.filter { $0.state == .passed }.count
                    let failed = snapshot.checks.filter { $0.state == .failed }.count
                    let seconds = (Double(snapshot.durationMs) / 1_000).formatted(.number.precision(.fractionLength(1)))
                    Text(hasIssue
                        ? languageManager.tr("%lld/%lld checks passed · %lld failed", Int64(passed), Int64(count), Int64(failed))
                        : languageManager.tr("%lld checks · %@ s", Int64(count), seconds))
                        .font(.caption).monospacedDigit()
                        .foregroundStyle(hasIssue ? tint : VaultTheme.textSecondary)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, minHeight: 62, alignment: .leading)
        .background(
            idle ? VaultTheme.surfaceMuted : (hasIssue ? issueSurface : VaultTheme.surface),
            in: RoundedRectangle(cornerRadius: 18)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 18).strokeBorder(VaultTheme.outline)
        }
    }

    private let diagnosticWarningSurface = Color(vaultLight: "FFFBEB", dark: "372A19")

    private func checkCard(_ id: String, result: DiagnosticsResult) -> some View {
        let row = DiagnosticsPresentation.checkRow(id, result: result, running: model.running && !model.cancelRequested)
        let probes = result.probes?.filter { $0.stage == id } ?? []
        let expanded = expandedChecks.contains(id) && !probes.isEmpty

        return VStack(alignment: .leading, spacing: 0) {
            if probes.isEmpty {
                checkRow(id, row: row, expandable: false, expanded: false)
            } else {
                Button {
                    if expanded { expandedChecks.remove(id) } else { expandedChecks.insert(id) }
                } label: {
                    checkRow(id, row: row, expandable: true, expanded: expanded)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityValue(expanded ? tr("Expanded") : tr("Collapsed"))
            }

            if expanded {
                Divider().overlay(VaultTheme.outline)
                VStack(alignment: .leading, spacing: 8) {
                    if DiagnosticsPresentation.pingCheckIDs.contains(id) {
                        Text(tr(DiagnosticsPresentation.pingNote)).foregroundStyle(VaultTheme.textSecondary)
                    }
                    ForEach(probes, id: \.id) { probe in
                        probeLines(probe)
                    }
                }
                .font(.caption)
                .padding(.vertical, 8)
            }
        }
        .padding(.horizontal, 16)
        .background(VaultTheme.surface, in: RoundedRectangle(cornerRadius: 18))
        .overlay {
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(expanded ? Color(vaultLight: "C7D2FE", dark: "505779") : VaultTheme.outline)
        }
    }

    private func checkRow(
        _ id: String, row: DiagnosticsPresentation.CheckRow, expandable: Bool, expanded: Bool
    ) -> some View {
        let passed = row.state == .passed
        let tint = passed ? VaultTheme.primary : (row.state == .failed ? VaultTheme.danger : VaultTheme.textSecondary)
        let duration = row.durationMs.map { "\($0) ms" }
        let result = row.hasMeasurements ? languageManager.tr("%@ passed", row.resultText) : tr(row.resultText)
        return HStack(spacing: 10) {
            Group {
                if row.active {
                    ProgressView().controlSize(.small)
                } else {
                    VaultStatusIcon(kind: passed ? .passed : (row.state == .failed ? .failed : .skipped), size: 22)
                }
            }
            .foregroundStyle(tint)
            .frame(width: 26, height: 26)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 4) {
                Text(tr(DiagnosticsPresentation.label(for: id)))
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(VaultTheme.textPrimary)
                Text([result, duration].compactMap { $0 }.joined(separator: " · "))
                    .font(.caption).monospacedDigit()
                    .foregroundStyle(tint)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            if expandable {
                Image(systemName: expanded ? "chevron.down" : "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(VaultTheme.textDisabled)
                    .accessibilityHidden(true)
            }
        }
        .padding(.vertical, 10)
        .frame(minHeight: 68)
    }

    private func probeLines(_ probe: DiagnosticProbe) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            probeLine("\(probe.domain) · \(probe.displayDetail)", duration: probe.durationMs)
            if let tls = probe.tlsDurationMs {
                probeLine(tr("TLS handshake"), duration: tls)
            }
        }
    }

    private func probeLine(_ detail: String, duration: UInt64) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(detail).foregroundStyle(VaultTheme.textSecondary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Text("\(duration) ms").monospacedDigit()
                .foregroundStyle(VaultTheme.textPrimary)
                .fixedSize()
        }
        .fontDesign(.monospaced)
    }

    private var logs: some View {
        VStack(spacing: 8) {
            Group {
                if model.loadingLogs || model.clearingLogs {
                    ProgressView(tr(model.clearingLogs ? "Clearing…" : "Loading logs..."))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if model.logText.isEmpty {
                    Text(tr("No log content found."))
                        .foregroundStyle(VaultTheme.textSecondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(VaultTheme.background)
                } else {
                    LogTextView(text: model.logText).padding(.vertical, 14)
                }
            }
            .layoutPriority(-1)
            .background(VaultTheme.surface)
            .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(VaultTheme.outline)
            }

            HStack(spacing: 6) {
                if lastCopy != nil {
                    VaultStatusIcon(kind: .passed, size: 16)
                }
                Text(tr(lastCopy != nil ? "Copied to clipboard." : "Select log text to copy details for troubleshooting."))
                    .font(.caption)
            }
            .foregroundStyle(lastCopy != nil ? VaultTheme.primary : VaultTheme.textSecondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            if let message = model.logMessage {
                Text(tr(message)).font(.caption).foregroundStyle(VaultTheme.textSecondary)
            }
            let actionLayout = dynamicTypeSize.isAccessibilitySize
                ? AnyLayout(VStackLayout(spacing: 8))
                : AnyLayout(HStackLayout(spacing: 16))
            actionLayout {
                Button(role: .destructive) {
                    confirmsLogClear = true
                } label: {
                    Text(tr("Clear"))
                }
                .buttonStyle(DiagnosticButtonStyle(kind: .destructive))
                .disabled(model.clearingLogs || model.loadingLogs || model.logText.isEmpty)
                Button {
                    UIPasteboard.general.string = model.logText
                    lastCopy = .now
                } label: {
                    Text(tr("Copy"))
                }
                .buttonStyle(DiagnosticButtonStyle(kind: .tonal))
                .disabled(model.clearingLogs || model.loadingLogs || model.logText.isEmpty)
            }
        }
        .padding(.horizontal, pageInset)
        .padding(.bottom, 8)
        .task(id: lastCopy) {
            guard lastCopy != nil else { return }
            do {
                try await Task.sleep(for: .seconds(2))
                lastCopy = nil
            } catch { return }
        }
    }
}

private struct DiagnosticButtonStyle: ButtonStyle {
    enum Kind { case primary, cancel, cancelling, tonal, destructive }
    var kind: Kind
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        let runAction = kind == .primary || kind == .cancel || kind == .cancelling
        let (fill, text): (Color, Color) = switch kind {
        case .primary: (VaultTheme.primary, VaultTheme.onPrimary)
        case .cancelling: (VaultTheme.surfaceMuted, VaultTheme.textSecondary)
        case .destructive: (VaultTheme.surfaceMuted, VaultTheme.danger)
        case .cancel, .tonal: (VaultTheme.indigoSoft, VaultTheme.primaryDark)
        }
        return configuration.label
            .font(.caption.weight(.semibold))
            .foregroundStyle(isEnabled || kind == .cancelling ? text : VaultTheme.textDisabled)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity, minHeight: runAction ? 50 : 44)
            .background(fill, in: RoundedRectangle(cornerRadius: runAction ? 16 : 14))
            .contentShape(Rectangle())
            .opacity(configuration.isPressed ? 0.78 : 1)
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
                        VaultStatusIcon(kind: probe.succeeded ? .passed : .failed, size: 20)
                            .foregroundStyle(probe.succeeded ? VaultTheme.primary : VaultTheme.danger)
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
