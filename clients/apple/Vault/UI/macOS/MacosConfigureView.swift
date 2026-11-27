#if os(macOS)
import AppKit
import ServiceManagement
import SwiftUI
import VaultCore

struct MacosConfigureView: View {
    enum Page: String, CaseIterable, Identifiable {
        case general = "General", profiles = "Profiles", status = "Status", about = "About"
        var id: String { rawValue }
        var symbol: String {
            switch self {
            case .general: "sun.max"
            case .profiles: "server.rack"
            case .status: "network"
            case .about: "info.circle"
            }
        }
    }

    private enum EditTarget: Hashable {
        case new
        case profile(String)
    }

    @ObservedObject var config: VaultConfig
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager
    @ObservedObject private var preferences = MacosPreferences.shared

    @State private var page: Page = .general
    @State private var draft = ConnectionDraft()
    @State private var savedDraft = ConnectionDraft()
    @State private var originalName: String?
    @State private var revealsPassword = false
    @State private var feedback: String?
    @State private var isError = false
    @State private var loaded = false
    @State private var confirmDelete = false
    @State private var confirmDiscard = false
    @State private var pendingTarget: EditTarget?

    private var dirty: Bool { draft != savedDraft }
    private var validationError: String? { draft.validationError() }
    private var isActiveProfile: Bool {
        guard let originalName else { return false }
        if originalName == appData.switchingProfileName { return true }
        guard appData.vpnStatus != .disconnected else { return false }
        let activeName = appData.runningProfileName ?? appData.requestedProfileName ?? config.selectedProfileName
        return activeName == originalName
    }

    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Page.allCases) { item in
                    Button { page = item } label: {
                        Label(languageManager.tr(item.rawValue), systemImage: item.symbol)
                            .font(.system(size: 15, weight: page == item ? .semibold : .regular))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 16)
                            .frame(minHeight: 36)
                            .padding(.vertical, 2)
                            .background(
                                page == item ? VaultTheme.indigoSoft : .clear,
                                in: RoundedRectangle(cornerRadius: 14, style: .continuous)
                            )
                            .foregroundStyle(page == item ? VaultTheme.primary : VaultTheme.textSecondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(page == item ? .isSelected : [])
                    .keyboardShortcut(KeyEquivalent(Character(String((Page.allCases.firstIndex(of: item) ?? 0) + 1))))
                }
                Spacer()
            }
            .padding(16)
            .frame(width: 150)
            .frame(maxHeight: .infinity)
            .background(VaultTheme.surfaceMuted)
            Divider().overlay(VaultTheme.outline)
            VStack(alignment: .leading, spacing: 0) {
                Group {
                    if page == .about {
                        ScrollView { about }
                    } else {
                        Form {
                            switch page {
                            case .profiles: profiles
                            case .status: status
                            case .general: general
                            case .about: EmptyView()
                            }
                        }
                        .formStyle(.grouped)
                        .scrollContentBackground(.hidden)
                    }
                }
                if page == .profiles, let feedback {
                    Text(languageManager.tr(feedback))
                        .font(.system(size: 12))
                        .foregroundStyle(isError ? VaultTheme.danger : VaultTheme.textSecondary)
                        .textSelection(.enabled)
                        .padding(.horizontal, 28)
                        .padding(.bottom, 10)
                }
                if page == .profiles {
                    HStack {
                        Spacer()
                        Button(languageManager.tr("Save"), action: save)
                            .buttonStyle(VaultPrimaryButtonStyle())
                            .keyboardShortcut("s")
                            .frame(width: 140)
                            .disabled(validationError != nil)
                    }
                    .padding(.horizontal, 28)
                    .padding(.bottom, 20)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(page == .about ? VaultTheme.surface : VaultTheme.background)
        }
        .background(VaultTheme.background)
        .tint(VaultTheme.primary)
        .onAppear {
            guard !loaded else { return }
            loaded = true
            load(config.selectedProfileName.map(EditTarget.profile) ?? .new)
            if config.profiles.isEmpty { page = .profiles }
            preferences.refreshLoginStatus()
        }
        .onChange(of: config.selectedProfileName) { _, name in
            guard loaded else { return }
            if let name, name != originalName {
                requestEdit(.profile(name))
            } else if name == nil && originalName != nil {
                requestEdit(.new)
            }
        }
        .onChange(of: languageManager.language) { _, _ in WindowManager.shared.refreshTitles() }
        .alert(languageManager.tr("Login item could not be updated"), isPresented: Binding(
            get: { preferences.launchError != nil }, set: { if !$0 { preferences.launchError = nil } }
        )) {
            Button(languageManager.tr("Open System Settings")) { SMAppService.openSystemSettingsLoginItems() }
            Button(languageManager.tr("OK"), role: .cancel) {}
        } message: {
            Text(languageManager.tr(preferences.launchError ?? ""))
        }
        .confirmationDialog(languageManager.tr("Delete this profile?"), isPresented: $confirmDelete) {
            Button(languageManager.tr("Delete"), role: .destructive, action: deleteProfile)
            Button(languageManager.tr("Cancel"), role: .cancel) {}
        }
        .confirmationDialog(languageManager.tr("Discard unsaved changes?"), isPresented: $confirmDiscard) {
            Button(languageManager.tr("Discard"), role: .destructive) {
                if let pendingTarget { load(pendingTarget) }
                pendingTarget = nil
            }
            Button(languageManager.tr("Cancel"), role: .cancel) { pendingTarget = nil }
        }
    }

    private var profiles: some View {
        Group {
            Section {
                HStack {
                    Picker(languageManager.tr("Profile"), selection: Binding(
                        get: { originalName ?? "" },
                        set: { requestEdit(.profile($0)) }
                    )) {
                        ForEach(config.profiles, id: \.name) { profile in
                            Text(profile.name).tag(profile.name)
                        }
                    }
                    .disabled(config.profiles.isEmpty)
                    Button { requestEdit(.new) } label: {
                        Image(systemName: "plus")
                    }
                    .controlSize(.large)
                    .help(languageManager.tr("Add Profile"))
                    .accessibilityLabel(languageManager.tr("Add Profile"))
                    Button(role: .destructive) { confirmDelete = true } label: {
                        Image(systemName: "trash")
                    }
                    .controlSize(.large)
                    .help(languageManager.tr("Delete Profile"))
                    .accessibilityLabel(languageManager.tr("Delete Profile"))
                    .disabled(originalName == nil || isActiveProfile)
                }
                if let profile = config.profiles.first(where: { $0.name == originalName }) {
                    HStack {
                        ProfileServerLabel(host: profile.host, port: profile.port)
                        Spacer()
                        if profile.name == config.selectedProfileName {
                            HStack(spacing: 4) {
                                VaultStatusIcon(kind: .passed, size: 20)
                                Text(languageManager.tr("In use"))
                                    .font(.caption.weight(.semibold))
                            }
                            .foregroundStyle(VaultTheme.primary)
                            .accessibilityElement(children: .combine)
                            .accessibilityLabel(languageManager.tr("Used for connection"))
                        }
                    }
                }
            }
            Section(languageManager.tr("Connection")) {
                TextField(languageManager.tr("Profile Name"), text: $draft.name)
                    .disabled(isActiveProfile)
                TextField(languageManager.tr("Server"), text: $draft.host, prompt: Text("vpn.example.com"))
                    .autocorrectionDisabled()
                TextField(languageManager.tr("Port"), text: $draft.port)
                HStack {
                    Group {
                        if revealsPassword {
                            TextField(languageManager.tr("Password"), text: $draft.password)
                        } else {
                            SecureField(languageManager.tr("Password"), text: $draft.password)
                        }
                    }
                    Button { revealsPassword.toggle() } label: {
                        Image(systemName: revealsPassword ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.plain).help(languageManager.tr("Show or hide password"))
                }
                TextField(languageManager.tr("MTU"), text: $draft.mtu, prompt: Text("1280–1427"))
            }
            Section(languageManager.tr("DNS Servers")) {
                TextField(languageManager.tr("IPv4 DNS"), text: $draft.dnsIpv4, prompt: Text("1.1.1.1, 8.8.8.8"))
                    .autocorrectionDisabled()
                TextField(languageManager.tr("IPv6 DNS"), text: $draft.dnsIpv6, prompt: Text("2001:4860:4860::8888, 2001:4860:4860::8844"))
                    .autocorrectionDisabled()
                Text(languageManager.tr("Leave empty for defaults. Only assigned tunnel families are used."))
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let error = config.passwordStorageError {
                Section {
                    Text(languageManager.tr(error)).foregroundStyle(.red)
                    Button(languageManager.tr("Retry")) {
                        config.retryPasswordStorage()
                        if let originalName, config.passwordStorageError == nil {
                            draft = config.draft(for: originalName)
                            savedDraft = draft
                        }
                    }
                }
            }
        }
    }

    private var status: some View {
        Group {
            Section {
                if appData.vpnStatus == .connected || appData.isRecovering {
                    let addresses = appData.assignedIp.parsedIPv4AndIPv6()
                    if let ipv4 = addresses.ipv4 { addressRow("IPv4", ipv4) }
                    if let ipv6 = addresses.ipv6 { addressRow("IPv6", ipv6) }
                    if addresses.ipv4 == nil && addresses.ipv6 == nil {
                        Text(languageManager.tr("Waiting for server-assigned addresses…"))
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text(languageManager.tr("Addresses are assigned by the server after connecting."))
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text(languageManager.tr("Tunnel Addresses"))
            } footer: {
                Text(languageManager.tr("Assigned by the server. Addresses may change after reconnecting."))
            }
            Section(languageManager.tr("Client Identifier")) {
                HStack {
                    Text(config.id).font(.system(.body, design: .monospaced))
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button(languageManager.tr("Copy")) { copy(config.id) }
                }
            }
        }
    }

    private var about: some View {
        MacosAboutView().frame(maxWidth: .infinity)
    }

    private var general: some View {
        Group {
            Section {
                Toggle(languageManager.tr("Launch at Login"), isOn: Binding(
                    get: { preferences.launchAtLogin }, set: { preferences.setLaunchAtLogin($0) }
                ))
                Toggle(languageManager.tr("Connect when Vault opens"), isOn: $preferences.autoConnect)
                Toggle(languageManager.tr("Show in Dock"), isOn: $preferences.showInDock)
                Picker(languageManager.tr("Language"), selection: $languageManager.language) {
                    ForEach(AppLanguage.allCases) { language in
                        Text(language.displayName).tag(language)
                    }
                }
            } footer: {
                Text(languageManager.tr("Closing a window keeps the VPN running. Quit ends the connection."))
                    .font(.body)
            }
        }
    }

    private func addressRow(_ family: String, _ value: String) -> some View {
        HStack {
            Text(family).foregroundStyle(.secondary).frame(width: 45, alignment: .leading)
            Text(value).font(.system(.body, design: .monospaced)).textSelection(.enabled)
            Spacer()
            Button(languageManager.tr("Copy")) { copy(value) }
        }
    }

    private func requestEdit(_ target: EditTarget) {
        if case .profile(let name) = target, name == originalName { return }
        guard dirty else {
            load(target)
            return
        }
        pendingTarget = target
        confirmDiscard = true
    }

    private func load(_ target: EditTarget) {
        switch target {
        case .new:
            originalName = nil
            draft = ConnectionDraft()
        case .profile(let name):
            originalName = name
            draft = config.draft(for: name)
        }
        savedDraft = draft
        feedback = nil
        isError = false
    }

    private func save() {
        feedback = nil
        isError = true
        if let originalName, draft.normalized.name != originalName, isActiveProfile {
            feedback = "Disconnect before renaming or deleting the running profile."
            return
        }
        if let error = config.saveProfile(draft, originalName: originalName) {
            feedback = error
            return
        }
        let name = draft.normalized.name
        originalName = name
        draft = config.draft(for: name)
        savedDraft = draft
        isError = false
        feedback = "Saved. Changes apply the next time you connect."
    }

    private func deleteProfile() {
        guard let originalName else { return }
        if isActiveProfile {
            feedback = "Disconnect before renaming or deleting the running profile."
            isError = true
            return
        }
        config.deleteProfile(originalName)
        load(config.selectedProfileName.map(EditTarget.profile) ?? .new)
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

struct MacosWelcomeView: View {
    @EnvironmentObject var languageManager: LanguageManager
    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            HStack(spacing: 12) {
                MacosAppIcon(size: 40)
                Text("Vault").font(.system(size: 20, weight: .semibold))
            }
            Text(languageManager.tr("Get started with Vault")).font(.system(size: 15, weight: .semibold))
            VStack(alignment: .leading, spacing: 14) {
                step("1", "Configure your server", "Enter the server address, port, and password.")
                step("2", "Approve the VPN", "macOS will ask permission to add a VPN configuration.")
                step("3", "Connect", "Connect from the menu bar. Closing this window keeps Vault available.")
            }
            HStack {
                Spacer()
                Button(languageManager.tr("Configure Server")) {
                    WindowManager.shared.showWindow(withIdentifier: "configure")
                }.buttonStyle(.borderedProminent)
            }
        }
        .frame(minWidth: 504, maxWidth: .infinity, alignment: .leading)
        .padding(28)
    }

    private func step(_ number: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(number).font(.headline).frame(width: 25, height: 25)
                .background(.blue.opacity(0.1), in: Circle()).foregroundStyle(.blue)
            VStack(alignment: .leading, spacing: 3) {
                Text(languageManager.tr(title)).font(.body.weight(.medium))
                Text(languageManager.tr(detail)).font(.body).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
#endif
