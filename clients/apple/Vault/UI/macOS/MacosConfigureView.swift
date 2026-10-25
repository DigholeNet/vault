#if os(macOS)
import AppKit
import ServiceManagement
import SwiftUI
import VaultCore

struct MacosConfigureView: View {
    enum Page: String, CaseIterable, Identifiable {
        case general = "General", connection = "Connection", network = "Network", advanced = "Advanced"
        var id: String { rawValue }
        var symbol: String {
            switch self {
            case .general: return "gearshape"
            case .connection: return "link"
            case .network: return "globe"
            case .advanced: return "slider.horizontal.3"
            }
        }
    }
    @ObservedObject var config: VaultConfig
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var languageManager: LanguageManager
    @ObservedObject private var preferences = MacosPreferences.shared
    @State private var page: Page = .connection
    @State private var draft = ConnectionDraft()
    @State private var revealsPassword = false
    @State private var feedback: String?
    @State private var isError = false
    @State private var loaded = false
    @State private var confirmReset = false
    private enum Control: Hashable {
        case section(Page), about, host, port, password, revealedPassword, reveal, dns, mtu, domains
        case launch, autoConnect, dock, language, copyV4, copyV6, copyID, retryPassword, restore, save
    }
    @FocusState private var focusedControl: Control?
    @State private var keyboardControl: Control? = .host

    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 5) {
                ForEach(Page.allCases) { item in
                    Button {
                        select(item)
                    } label: {
                        Label(languageManager.tr(item.rawValue), systemImage: item.symbol)
                            .font(.body.weight(page == item ? .medium : .regular))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 10).padding(.vertical, 9)
                            .background(page == item ? Color.accentColor.opacity(0.13) : .clear, in: RoundedRectangle(cornerRadius: 7))
                            .foregroundStyle(page == item ? Color.accentColor : .primary)
                    }.buttonStyle(.plain)
                    .keyboardShortcut(KeyEquivalent(Character(String((Page.allCases.firstIndex(of: item) ?? 0) + 1))))
                    .macosKeyboardAction(focus: $keyboardControl, id: .section(item)) { select(item) }
                    .accessibilityAddTraits(page == item ? .isSelected : [])
                }
                Spacer()
                Button {
                    WindowManager.shared.showWindow(withIdentifier: "about")
                } label: {
                    Label(languageManager.tr("About"), systemImage: "questionmark.app")
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                }
                .buttonStyle(.plain).font(.body).foregroundStyle(.secondary)
                .macosKeyboardAction(focus: $keyboardControl, id: .about) { WindowManager.shared.showWindow(withIdentifier: "about") }
            }
            .padding(12).frame(width: 150).frame(maxHeight: .infinity)
            .background(.quaternary.opacity(0.3))
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                Text(languageManager.tr(page.rawValue)).font(.system(size: 15, weight: .semibold)).padding([.horizontal, .top], 24)
                Form {
                    switch page {
                    case .general: general
                    case .connection: connection
                    case .network: network
                    case .advanced: advanced
                    }
                }.formStyle(.grouped)
                if let feedback {
                    Text(languageManager.tr(feedback))
                        .font(.body).foregroundStyle(isError ? Color.red : Color.secondary)
                        .textSelection(.enabled).padding(.horizontal, 24).padding(.bottom, 10)
                }
                if page != .general {
                    HStack {
                        if page == .advanced {
                            Button(languageManager.tr("Restore Defaults")) { confirmReset = true }
                                .macosKeyboardAction(focus: $keyboardControl, id: .restore) { confirmReset = true }
                        }
                        Spacer()
                        Button(languageManager.tr("Save"), action: save)
                            .buttonStyle(.borderedProminent).keyboardShortcut("s")
                            .macosKeyboardAction(focus: $keyboardControl, id: .save, action: save)
                    }.padding(.horizontal, 24).padding(.bottom, 20)
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .macosKeyboardNavigation { event in
            if event.type == .leftMouseDown {
                if let current = keyboardControl, !isTextControl(current) { keyboardControl = nil }
                return false
            }
            let modifiers = event.modifierFlags.intersection([.command, .control, .option, .shift])
            if event.keyCode == 48, modifiers.subtracting(.shift).isEmpty {
                moveKeyboardFocus(nextControl(after: keyboardControl, backwards: modifiers.contains(.shift)), window: event.window)
                return true
            }
            if event.keyCode == 53, modifiers.isEmpty { event.window?.performClose(nil); return true }
            if modifiers == .command, let key = event.charactersIgnoringModifiers {
                if let number = Int(key), (1...Page.allCases.count).contains(number) {
                    select(Page.allCases[number - 1]); event.window?.makeFirstResponder(nil)
                    return true
                }
                if key.lowercased() == "s", page != .general { save(); return true }
                if key.lowercased() == "w" { event.window?.performClose(nil); return true }
            }
            if modifiers.isEmpty, let current = keyboardControl {
                if case .section(let section) = current {
                    let index = Page.allCases.firstIndex(of: section) ?? 0
                    if event.keyCode == 125 || event.keyCode == 126 {
                        select(Page.allCases[(index + (event.keyCode == 126 ? Page.allCases.count - 1 : 1)) % Page.allCases.count])
                        return true
                    }
                    if event.keyCode == 124 { moveKeyboardFocus(firstControl, window: event.window); return true }
                }
                if current == .language, [123, 124, 125, 126].contains(event.keyCode) {
                    moveLanguage(by: event.keyCode == 123 || event.keyCode == 126 ? -1 : 1); return true
                }
                if !event.isARepeat, [36, 49, 76].contains(event.keyCode), !isTextControl(current) {
                    activate(current); return true
                }
            }
            return false
        }
        .onChange(of: focusedControl) { _, control in
            if let control { keyboardControl = control }
        }
        .onExitCommand { NSApp.keyWindow?.performClose(nil) }
        .onAppear {
            guard !loaded else { return }
            loaded = true
            draft = config.connectionDraft
            preferences.refreshLoginStatus()
            DispatchQueue.main.async { focusedControl = .host }
        }
        .onChange(of: languageManager.language) { _, _ in WindowManager.shared.refreshTitles() }
        .onChange(of: page) { _, _ in preferences.refreshLoginStatus() }
        .alert(languageManager.tr("Login item could not be updated"), isPresented: Binding(
            get: { preferences.launchError != nil }, set: { if !$0 { preferences.launchError = nil } })) {
                Button(languageManager.tr("Open System Settings")) { SMAppService.openSystemSettingsLoginItems() }
                Button(languageManager.tr("OK"), role: .cancel) {}
            } message: { Text(languageManager.tr(preferences.launchError ?? "")) }
        .confirmationDialog(languageManager.tr("Restore advanced defaults?"), isPresented: $confirmReset) {
            Button(languageManager.tr("Restore Defaults")) { draft.mtu = ""; draft.probeDomains = ""; feedback = "Defaults restored. Save to apply."; isError = false }
        }
    }

    private var general: some View {
        Group {
            Section {
                Toggle(languageManager.tr("Launch at Login"), isOn: Binding(
                    get: { preferences.launchAtLogin }, set: { preferences.setLaunchAtLogin($0) }))
                    .macosKeyboardAction(focus: $keyboardControl, id: .launch) { preferences.setLaunchAtLogin(!preferences.launchAtLogin) }
                Toggle(languageManager.tr("Connect when Vault opens"), isOn: $preferences.autoConnect)
                    .macosKeyboardAction(focus: $keyboardControl, id: .autoConnect) { preferences.autoConnect.toggle() }
                Toggle(languageManager.tr("Show in Dock"), isOn: $preferences.showInDock)
                    .macosKeyboardAction(focus: $keyboardControl, id: .dock) { preferences.showInDock.toggle() }
                Picker(languageManager.tr("Language"), selection: $languageManager.language) {
                    ForEach(AppLanguage.allCases) { Text($0.displayName).tag($0) }
                }
                .macosKeyboardAction(focus: $keyboardControl, id: .language) { moveLanguage(by: 1) }
            } footer: {
                Text(languageManager.tr("Closing a window keeps the VPN running. Quit ends the connection.")).font(.body)
            }
        }
    }
    private var connection: some View {
        Group {
            Section {
                TextField(languageManager.tr("Server"), text: $draft.host, prompt: Text("vpn.example.com"))
                    .autocorrectionDisabled()
                    .focused($focusedControl, equals: .host)
                    .onSubmit { focusedControl = .port }
                TextField(languageManager.tr("Port"), text: $draft.port)
                    .focused($focusedControl, equals: .port)
                    .onSubmit { focusedControl = passwordControl }
                HStack {
                    if revealsPassword {
                        TextField(languageManager.tr("Password"), text: $draft.password)
                            .focused($focusedControl, equals: .revealedPassword).onSubmit(save)
                    } else {
                        SecureField(languageManager.tr("Password"), text: $draft.password)
                            .focused($focusedControl, equals: .password).onSubmit(save)
                    }
                    Button { togglePasswordVisibility() } label: {
                        Image(systemName: revealsPassword ? "eye.slash" : "eye")
                    }.buttonStyle(.plain).help(languageManager.tr("Show or hide password"))
                    .accessibilityLabel(languageManager.tr("Show or hide password"))
                    .macosKeyboardAction(focus: $keyboardControl, id: .reveal, action: togglePasswordVisibility)
                }
            } footer: { Text(languageManager.tr("Changes apply the next time you connect.")).font(.body) }
            if let error = config.passwordStorageError {
                Section {
                    Text(languageManager.tr(error)).foregroundStyle(.red)
                    Button(languageManager.tr("Retry"), action: retryPasswordStorage)
                        .macosKeyboardAction(focus: $keyboardControl, id: .retryPassword) { retryPasswordStorage() }
                }
            }
        }
    }
    private var network: some View {
        Group {
            Section(languageManager.tr("DNS Servers")) {
                TextField(languageManager.tr("DNS"), text: $draft.dns, prompt: Text("1.1.1.1, 8.8.8.8"))
                    .autocorrectionDisabled().focused($focusedControl, equals: .dns).onSubmit(save)
                Text(languageManager.tr("DNS server address separated by comma.")).font(.body).foregroundStyle(.secondary)
            }
            Section(languageManager.tr("Tunnel Addresses")) {
                if appData.vpnStatus == .connected || appData.isRecovering {
                    let addresses = config.ip.parsedIPv4AndIPv6()
                    if let ipv4 = addresses.ipv4 { addressRow("IPv4", ipv4) }
                    if let ipv6 = addresses.ipv6 { addressRow("IPv6", ipv6) }
                    if addresses.ipv4 == nil && addresses.ipv6 == nil {
                        Text(languageManager.tr("Waiting for server-assigned addresses…")).foregroundStyle(.secondary)
                    }
                } else {
                    Text(languageManager.tr("Addresses are assigned by the server after connecting."))
                        .foregroundStyle(.secondary)
                }
                Text(languageManager.tr("Assigned by the server. Addresses may change after reconnecting."))
                    .font(.body).foregroundStyle(.secondary)
            }
        }
    }
    private var advanced: some View {
        Group {
            Section {
                TextField(languageManager.tr("MTU"), text: $draft.mtu, prompt: Text("1280–1427"))
                    .focused($focusedControl, equals: .mtu).onSubmit { focusedControl = .domains }
                Text(languageManager.tr("Leave empty for automatic MTU. Valid range: 1280–1427."))
                    .font(.body).foregroundStyle(.secondary)
                TextField(languageManager.tr("Probe Domains"), text: $draft.probeDomains, prompt: Text("www.google.com, github.com, t.co"))
                    .autocorrectionDisabled().focused($focusedControl, equals: .domains).onSubmit(save)
                Text(languageManager.tr("Diagnostic probe domains, separated by commas. Leave empty to use defaults."))
                    .font(.body).foregroundStyle(.secondary)
            }
            Section(languageManager.tr("Client Identifier")) {
                HStack {
                    Text(config.id).font(.system(.body, design: .monospaced))
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button(languageManager.tr("Copy")) { copy(config.id) }
                        .macosKeyboardAction(focus: $keyboardControl, id: .copyID) { copy(config.id) }
                }
                Text(languageManager.tr("Identifies this client. Usually no changes are needed."))
                    .font(.body).foregroundStyle(.secondary)
            }
        }
    }
    private func addressRow(_ family: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(family).font(.body).foregroundStyle(.secondary).frame(width: 35, alignment: .leading)
            Text(value).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true).frame(maxWidth: .infinity, alignment: .leading)
            Button { copy(value) } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.plain).help(languageManager.tr("Copy"))
                .accessibilityLabel(languageManager.tr("Copy") + " " + family)
                .macosKeyboardAction(focus: $keyboardControl, id: family == "IPv4" ? .copyV4 : .copyV6) { copy(value) }
        }
    }
    private var firstControl: Control {
        switch page {
        case .general: return .launch
        case .connection: return .host
        case .network: return .dns
        case .advanced: return .mtu
        }
    }
    private var focusOrder: [Control] {
        var order = Page.allCases.map(Control.section)
        switch page {
        case .general: order += [.launch, .autoConnect, .dock, .language]
        case .connection:
            order += [.host, .port, passwordControl, .reveal]
            if config.passwordStorageError != nil { order.append(.retryPassword) }
            order.append(.save)
        case .network:
            order.append(.dns)
            if appData.vpnStatus == .connected || appData.isRecovering {
                let ip = config.ip.parsedIPv4AndIPv6()
                if ip.ipv4 != nil { order.append(.copyV4) }
                if ip.ipv6 != nil { order.append(.copyV6) }
            }
            order.append(.save)
        case .advanced: order += [.mtu, .domains, .copyID, .restore, .save]
        }
        return order + [.about]
    }
    private func nextControl(after current: Control?, backwards: Bool) -> Control? {
        let order = focusOrder
        guard let current, let index = order.firstIndex(of: current) else {
            return backwards ? order.last : order.first
        }
        return order[(index + (backwards ? order.count - 1 : 1)) % order.count]
    }
    private func select(_ selected: Page) {
        page = selected
        feedback = nil
        focusedControl = nil
        keyboardControl = .section(selected)
    }
    private func isTextControl(_ control: Control) -> Bool {
        [.host, .port, .password, .revealedPassword, .dns, .mtu, .domains].contains(control)
    }
    private func moveKeyboardFocus(_ control: Control?, window: NSWindow?) {
        keyboardControl = control
        if let control, isTextControl(control) {
            focusedControl = control
        } else {
            focusedControl = nil
            window?.makeFirstResponder(nil)
        }
    }
    private func activate(_ control: Control) {
        switch control {
        case .section(let selected): select(selected)
        case .about: WindowManager.shared.showWindow(withIdentifier: "about")
        case .launch: preferences.setLaunchAtLogin(!preferences.launchAtLogin)
        case .autoConnect: preferences.autoConnect.toggle()
        case .dock: preferences.showInDock.toggle()
        case .language: moveLanguage(by: 1)
        case .reveal: togglePasswordVisibility()
        case .copyV4: if let ip = config.ip.parsedIPv4AndIPv6().ipv4 { copy(ip) }
        case .copyV6: if let ip = config.ip.parsedIPv4AndIPv6().ipv6 { copy(ip) }
        case .copyID: copy(config.id)
        case .retryPassword: retryPasswordStorage()
        case .restore: confirmReset = true
        case .save: save()
        default: break
        }
    }
    private func moveLanguage(by offset: Int) {
        let all = AppLanguage.allCases
        let index = all.firstIndex(of: languageManager.language) ?? 0
        languageManager.language = all[(index + offset + all.count) % all.count]
    }
    private var passwordControl: Control { revealsPassword ? .revealedPassword : .password }
    private func togglePasswordVisibility() {
        focusedControl = nil
        revealsPassword.toggle()
        let inputFocus = $focusedControl
        let target = passwordControl
        DispatchQueue.main.async { inputFocus.wrappedValue = target }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string)
    }
    private func retryPasswordStorage() {
        let unchanged = draft.password == config.password
        config.retryPasswordStorage()
        if unchanged, config.passwordStorageError == nil {
            draft.password = config.password
        }
    }

    private func save() {
        feedback = nil; isError = true
        let section: ConnectionDraft.Section
        switch page {
        case .general: return
        case .connection: section = .connection
        case .network: section = .network
        case .advanced: section = .advanced
        }
        if let error = config.save(draft, section: section) {
            feedback = error
            return
        }
        draft = draft.normalized
        isError = false
        feedback = "Saved. Changes apply the next time you connect."
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
        }.padding(28)
    }
    private func step(_ number: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(number).font(.headline).frame(width: 25, height: 25)
                .background(.blue.opacity(0.1), in: Circle()).foregroundStyle(.blue)
            VStack(alignment: .leading, spacing: 3) {
                Text(languageManager.tr(title)).font(.body.weight(.medium))
                Text(languageManager.tr(detail)).font(.body).foregroundStyle(.secondary)
            }
        }
    }
}
#endif
