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
    @State private var confirmsLogClear = false
    @State private var lastLogCopy: Date?

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                Text(languageManager.tr("Connection Diagnostics")).tag(0)
                Text(languageManager.tr("Runtime Logs")).tag(1)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 286)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            Divider().overlay(VaultTheme.outline)
            if tab == 0 {
                MacosConnectionDiagnostics(vpnManager: vpnManager, model: model)
            } else {
                logs
            }
            Divider().overlay(VaultTheme.outline)
            HStack(spacing: 12) {
                if tab == 1 {
                    Toggle(languageManager.tr("Auto-scroll"), isOn: $followsTail)
                        .toggleStyle(.switch)
                        .controlSize(.small)
                }
                Spacer()
                if tab == 1 {
                    if lastLogCopy != nil {
                        HStack(spacing: 4) {
                            VaultStatusIcon(kind: .passed, size: 16)
                            Text(languageManager.tr("Copied to clipboard.")).font(.caption)
                        }
                        .foregroundStyle(VaultTheme.primary)
                    } else if let message = model.logMessage {
                        Text(languageManager.tr(message))
                            .font(.caption)
                            .foregroundStyle(VaultTheme.textSecondary)
                    }
                    Button {
                        confirmsLogClear = true
                    } label: {
                        Label(languageManager.tr(model.clearingLogs ? "Clearing…" : "Clear"), systemImage: "trash")
                    }
                    .buttonStyle(VaultSecondaryButtonStyle(isDestructive: true))
                    .frame(width: 130)
                    .disabled(model.clearingLogs || model.filteredLogText.isEmpty)
                }
                Button { copy(tab == 0 ? model.diagnosticText : model.filteredLogText) } label: {
                    Label(languageManager.tr("Copy"), systemImage: "doc.on.doc")
                }
                .buttonStyle(VaultSecondaryButtonStyle())
                .frame(width: 130)
                .disabled(tab == 0 ? model.result == nil : model.filteredLogText.isEmpty)
            }
            .padding(16)
        }
        .background(VaultTheme.background)
        .tint(VaultTheme.primary)
        .task(id: lastLogCopy) {
            guard lastLogCopy != nil else { return }
            do {
                try await Task.sleep(for: .seconds(2))
                lastLogCopy = nil
            } catch { return }
        }
        .vaultLogClearConfirmation(isPresented: $confirmsLogClear) {
            Task { await model.clearLogs(using: vpnManager) }
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
            HStack(spacing: 16) {
                Picker("", selection: $model.logFilter) {
                    Text(languageManager.tr("All")).tag("all")
                    Text(languageManager.tr("Application")).tag("app")
                    Text(languageManager.tr("Tunnel")).tag("ne")
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 260)
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(VaultTheme.textDisabled)
                    TextField(languageManager.tr("Search logs"), text: $model.logSearch)
                        .textFieldStyle(.plain)
                }
                .padding(.horizontal, 12)
                .frame(minHeight: 36)
                .background(VaultTheme.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(VaultTheme.outline)
                }
            }
            .padding(16)
            Group {
                if model.loadingLogs {
                    ProgressView(languageManager.tr("Loading logs..."))
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(VaultTheme.surfaceMuted)
                } else if model.filteredLogText.isEmpty {
                    Text(languageManager.tr("No matching logs."))
                        .foregroundStyle(VaultTheme.textSecondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .background(VaultTheme.surfaceMuted)
                } else {
                    LogTextView(text: model.filteredLogText, followsTail: followsTail)
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .padding(.horizontal, 16)
            .padding(.bottom, 16)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        if NSPasteboard.general.setString(text, forType: .string), tab == 1 {
            lastLogCopy = .now
        }
    }
}

// Observe traffic state only while the diagnostics tab is visible. Runtime Logs
// must not redraw when the provider publishes its per-second byte counters.
private struct MacosDiagnosticsAction: View {
    let vpnManager: VpnManager
    @ObservedObject var model: DiagnosticsViewModel
    @EnvironmentObject var languageManager: LanguageManager

    var body: some View {
        if model.running {
            Button(languageManager.tr(model.cancelRequested ? "Cancelling…" : "Cancel checks")) {
                model.cancel(using: vpnManager)
            }
            .buttonStyle(VaultSecondaryButtonStyle(isPending: model.cancelRequested))
            .frame(width: 180)
            .disabled(model.cancelRequested)
        } else {
            Button {
                model.run(using: vpnManager)
            } label: {
                Label(languageManager.tr(model.result == nil ? "Run Diagnostics" : "Run Again"), systemImage: "arrow.clockwise")
            }
            .buttonStyle(VaultPrimaryButtonStyle())
            .frame(width: 180)
            .disabled(model.running)
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
            VStack(alignment: .leading, spacing: 18) {
                ProbeDomainsEditor().vaultCard()
                if running || result != nil {
                    VStack(alignment: .leading, spacing: 16) {
                        resultHeader
                        MacosDiagnosticsAction(vpnManager: vpnManager, model: model)
                    }
                    .vaultCard()
                    sessionAddresses.vaultCard(padding: 14)
                    checkTable
                    Text(languageManager.tr(DiagnosticsPresentation.pingNote))
                        .font(.system(size: 12))
                        .foregroundStyle(VaultTheme.textSecondary)
                    if !DiagnosticsPresentation.pingProbes(result).isEmpty {
                        DisclosureGroup(languageManager.tr("Ping samples")) {
                            ForEach(DiagnosticsPresentation.pingProbes(result), id: \.id) { probe in
                                Text(probe.displayDetail)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(VaultTheme.textSecondary)
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                    if running && !model.cancelRequested {
                        Text(languageManager.tr(result?.activeCheck == "icmp"
                                ? "Completing optional tunnel observations…"
                                : "Results update as each check completes."))
                            .font(.system(size: 13))
                            .foregroundStyle(VaultTheme.textSecondary)
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
                                                    VaultStatusIcon(kind: probe.succeeded ? .passed : .failed, size: 20)
                                                        .foregroundStyle(probe.succeeded ? VaultTheme.primary : VaultTheme.danger)
                                                    VStack(alignment: .leading, spacing: 4) {
                                                        Text(languageManager.tr(DiagnosticsPresentation.label(for: probe.stage)))
                                                            .font(.body.weight(.medium))
                                                        Text(probe.displayDetail)
                                                            .font(.system(.body, design: .monospaced))
                                                            .foregroundStyle(VaultTheme.textSecondary)
                                                            .textSelection(.enabled)
                                                            .fixedSize(horizontal: false, vertical: true)
                                                        if let tls = probe.tlsDurationMs {
                                                            Text("TLS  \(tls) ms")
                                                                .font(.system(.body, design: .monospaced))
                                                                .foregroundStyle(VaultTheme.textSecondary)
                                                        }
                                                    }
                                                    Spacer(minLength: 8)
                                                    Text("\(probe.durationMs) ms")
                                                        .font(.system(.body, design: .monospaced))
                                                }
                                            }
                                        }
                                        .padding(12)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .background(VaultTheme.surfaceSubtle, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                                    } else {
                                        Text(result.lines.filter { $0.contains(domain) }.joined(separator: "\n"))
                                            .font(.system(.body, design: .monospaced))
                                            .textSelection(.enabled)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .padding(.vertical, 8)
                                    }
                                }
                                .padding(.vertical, 5)
                            }
                            if !running && !model.wasCancelled && !result.summary.hasPrefix("OK") {
                                Text(result.summary)
                                    .font(.body)
                                    .foregroundStyle(VaultTheme.textSecondary)
                                    .textSelection(.enabled)
                                    .padding(.top, 8)
                            }
                        }
                        .font(.body)
                    }
                } else {
                    VStack(spacing: 18) {
                        VaultIconTile(systemName: "waveform.path.ecg", size: 64)
                        VaultInfoCallout(
                            title: languageManager.tr("Check your connection"),
                            detail: languageManager.tr(appData.vpnStatus == .connected
                                ? "Test tunnel DNS, TCP, HTTPS, and application access. Durations are measured in milliseconds."
                                :
                                "Run application access checks without connecting. Tunnel checks are available after connecting. Logs remain available.")
                        )
                        MacosDiagnosticsAction(vpnManager: vpnManager, model: model)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 48)
                }
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var resultHeader: some View {
        HStack(alignment: .top, spacing: 14) {
            if running && !model.cancelRequested {
                ProgressView().controlSize(.large).padding(8)
            } else if model.wasCancelled || model.cancelRequested {
                Image(systemName: "info.circle")
                    .symbolRenderingMode(.monochrome)
                    .font(.system(size: 28))
                    .foregroundStyle(VaultTheme.textSecondary)
                    .frame(width: 34, height: 34)
                    .accessibilityHidden(true)
            } else {
                VaultStatusIcon(kind: passed ? .passed : .failed, size: 34)
                    .foregroundStyle(passed ? VaultTheme.primary
                        : (incomplete ? VaultTheme.diagnosticWarning : VaultTheme.danger))
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(languageManager.tr(model.statusTitle))
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(VaultTheme.textPrimary)
                if model.wasCancelled {
                    Text(languageManager.tr("Completed results are still available."))
                        .foregroundStyle(VaultTheme.textSecondary)
                } else if running, !model.cancelRequested, let startedAt {
                    TimelineView(.periodic(from: .now, by: 0.1)) { _ in
                        Text(languageManager
                            .tr("Elapsed") + "  \(max(0, Int((ProcessInfo.processInfo.systemUptime - startedAt) * 1000))) ms")
                            .font(.body)
                            .monospacedDigit()
                            .foregroundStyle(VaultTheme.textSecondary)
                    }
                    ProgressView(
                        value: Double(result?.checks?.count ?? 0),
                        total: Double(DiagnosticsPresentation.visibleChecks(result).count)
                    )
                    .tint(VaultTheme.primary)
                    .frame(maxWidth: 300)
                } else if !running {
                    HStack(spacing: 10) {
                        if let completedAt { Text(completedAt, style: .time) }
                        if let duration = result?.durationMs {
                            Text(languageManager.tr("Total duration") + "  \(duration) ms")
                        }
                    }
                    .font(.body)
                    .monospacedDigit()
                    .foregroundStyle(VaultTheme.textSecondary)
                }
            }
            Spacer()
        }
    }

    private var sessionAddresses: some View {
        let active = appData.vpnStatus == .connected || appData.isRecovering
        let addresses = appData.assignedIp.parsedIPv4AndIPv6()
        return VStack(alignment: .leading, spacing: 12) {
            if active, !appData.publicIp.isEmpty {
                VaultAddressRow(title: "WAN", address: appData.publicIp, symbol: "globe", truncatesMiddle: true)
                Divider().overlay(VaultTheme.outline)
            }
            if let ipv4 = addresses.ipv4, active {
                VaultAddressRow(title: "IPv4", address: ipv4, symbol: "server.rack")
            }
            if let ipv6 = addresses.ipv6, active {
                VaultAddressRow(title: "IPv6", address: ipv6, symbol: "server.rack")
            }
            if addresses.ipv4 == nil && addresses.ipv6 == nil {
                HStack(spacing: 8) {
                    Image(systemName: "server.rack").foregroundStyle(VaultTheme.textSecondary)
                    Text(languageManager.tr(active ? "Waiting for server-assigned addresses…" : "Disconnected"))
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(VaultTheme.textSecondary)
                        .textSelection(.enabled)
                }
            }
        }
    }

    private var checkTable: some View {
        VStack(spacing: 0) {
            HStack {
                Text(languageManager.tr("Check"))
                Spacer()
                Text(languageManager.tr("Result")).frame(width: 80)
                Text(languageManager.tr("Average duration")).frame(width: 100, alignment: .trailing)
            }
            .font(.system(size: 13, weight: .semibold))
            .foregroundStyle(VaultTheme.textSecondary)
            .padding(14)
            .background(VaultTheme.surfaceMuted)
            ForEach(DiagnosticsPresentation.visibleChecks(result), id: \.self) { id in
                let row = DiagnosticsPresentation.checkRow(id, result: result, running: running && !model.cancelRequested)
                HStack(spacing: 8) {
                    if row.active {
                        ProgressView().controlSize(.mini).frame(width: 22)
                    } else {
                        VaultStatusIcon(
                            kind: row.state == .passed ? .passed : (row.state == .failed ? .failed : .skipped),
                            size: 22
                        )
                            .foregroundStyle(row.state == .passed ? VaultTheme.primary
                                : (row.state == .failed ? VaultTheme.danger : VaultTheme.textSecondary))
                    }
                    Text(languageManager.tr(checkLabel(id))).font(.body)
                    Spacer()
                    Text(languageManager.tr(row.resultText))
                        .font(.body)
                        .monospacedDigit()
                        .foregroundStyle(VaultTheme.textSecondary)
                        .frame(width: 80)
                    if row.state != nil {
                        Text(row.durationMs.map { "\($0) ms" } ?? "—")
                            .font(.system(.body, design: .monospaced))
                            .frame(width: 100, alignment: .trailing)
                            .help(languageManager.tr(DiagnosticsPresentation.pingCheckIDs.contains(id)
                                    ? "Mean round-trip time of received replies."
                                    : "Mean request time, including failures and retries."))
                    } else if row.active {
                        TimelineView(.periodic(from: .now, by: 0.1)) { _ in
                            Text("\(max(0, Int((ProcessInfo.processInfo.systemUptime - progressReceived) * 1000))) ms")
                                .font(.system(.body, design: .monospaced))
                                .foregroundStyle(VaultTheme.textSecondary)
                        }
                        .frame(width: 100, alignment: .trailing)
                    } else {
                        Text("—")
                            .foregroundStyle(VaultTheme.textDisabled)
                            .frame(width: 100, alignment: .trailing)
                    }
                }
                .padding(14)
                if id != DiagnosticsPresentation.visibleChecks(result).last {
                    Divider().overlay(VaultTheme.outline)
                }
            }
        }
        .background(VaultTheme.surface)
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(VaultTheme.outline)
        }
    }

    private var passed: Bool { model.passed }
    private var incomplete: Bool { model.incomplete }
    private func checkLabel(_ id: String) -> String { DiagnosticsPresentation.label(for: id) }
}
#endif
