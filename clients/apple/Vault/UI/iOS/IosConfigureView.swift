import SwiftUI
import VaultCore

#if os(iOS)
struct IosConfigureView: View {
    let vpnManager: VpnManager
    var opensNewProfile: Binding<Bool> = .constant(false)
    @EnvironmentObject var appData: AppData
    @EnvironmentObject var config: VaultConfig
    @EnvironmentObject var languageManager: LanguageManager

    @State private var isSecured = true
    @State private var draft = ConnectionDraft()
    @State private var originalName: String?
    @State private var isEditing = false
    @State private var feedback: String?
    @State private var confirmDelete = false
    @State private var pendingProfileSwitch: String?

    private var validationError: String? { draft.validationError() }
    private var isActiveProfile: Bool {
        originalName.map { vpnManager.isProfileActive($0) } ?? false
    }

    private func edit(_ name: String?) {
        originalName = name
        draft = name.map { config.draft(for: $0) } ?? ConnectionDraft()
        feedback = nil
        isEditing = true
    }

    private func save() {
        IosKeyboardDismissal.dismiss()
        if let originalName, draft.normalized.name != originalName, vpnManager.isProfileActive(originalName) {
            feedback = "Disconnect before renaming or deleting the running profile."
            return
        }
        if let error = config.saveProfile(draft, originalName: originalName) {
            feedback = error
            return
        }
        isEditing = false
        feedback = nil
    }

    var body: some View {
        Group {
            if isEditing { editor } else { profileList }
        }
        .vaultScreenBackground()
        .navigationBarHidden(true)
        .onChange(of: opensNewProfile.wrappedValue, initial: true) { _, open in
            guard open else { return }
            opensNewProfile.wrappedValue = false
            edit(nil)
        }
        .confirmationDialog(
            languageManager.tr("Delete this profile?"),
            isPresented: $confirmDelete,
            titleVisibility: .visible
        ) {
            Button(languageManager.tr("Delete"), role: .destructive) {
                if let originalName {
                    if vpnManager.isProfileActive(originalName) {
                        feedback = "Disconnect before renaming or deleting the running profile."
                        return
                    }
                    config.deleteProfile(originalName)
                }
                isEditing = false
            }
            Button(languageManager.tr("Cancel"), role: .cancel) {}
        }
        .confirmationDialog(
            languageManager.tr("Switch Profile?"),
            isPresented: Binding(
                get: { pendingProfileSwitch != nil },
                set: { if !$0 { pendingProfileSwitch = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let name = pendingProfileSwitch {
                Button(languageManager.tr("Disconnect and Connect")) {
                    pendingProfileSwitch = nil
                    vpnManager.requestProfileSelection(name)
                }
            }
            Button(languageManager.tr("Cancel"), role: .cancel) { pendingProfileSwitch = nil }
        } message: {
            if let name = pendingProfileSwitch {
                Text(languageManager.tr("The current tunnel will disconnect before connecting to") + " \(name).")
            }
        }
    }

    private var profileList: some View {
        ScrollView {
            VStack(spacing: 16) {
                HStack(alignment: .center, spacing: 12) {
                    VaultPageHeader(
                        title: languageManager.tr("Configure"),
                        subtitle: languageManager.tr("Choose the server for your next connection.")
                    )
                    Button { edit(nil) } label: {
                        VaultIconTile(systemName: "plus", size: 48)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(languageManager.tr("Add Profile"))
                }

                if config.profiles.isEmpty {
                    Button { edit(nil) } label: {
                        VStack(spacing: 12) {
                            VaultIconTile(systemName: "plus", size: 52)
                            Text(languageManager.tr("Add a profile to configure a Supernode."))
                                .font(.system(size: 13))
                                .foregroundStyle(VaultTheme.textSecondary)
                                .multilineTextAlignment(.center)
                        }
                        .frame(maxWidth: .infinity)
                        .vaultCard(padding: 28)
                    }
                    .buttonStyle(.plain)
                } else {
                    VStack(spacing: 12) {
                        ForEach(config.profiles, id: \VaultProfile.name) { profile in
                            profileRow(profile)
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 12) {
                    Text(languageManager.tr("Preferences"))
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(VaultTheme.textPrimary)
                    HStack(spacing: 14) {
                        VaultIconTile(systemName: "globe", size: 40)
                        Text(languageManager.tr("Language"))
                            .font(.system(size: 15, weight: .medium))
                        Spacer()
                        Picker(languageManager.tr("Language"), selection: $languageManager.language) {
                            ForEach(AppLanguage.allCases) { language in
                                Text(language.displayName).tag(language)
                            }
                        }
                        .labelsHidden()
                        .tint(VaultTheme.textSecondary)
                    }
                    .vaultCard()
                }

                VaultInfoCallout(
                    title: languageManager.tr("Save changes before connecting"),
                    detail: languageManager.tr("Server, DNS and MTU changes apply the next time you connect.")
                )
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
    }

    private func profileRow(_ profile: VaultProfile) -> some View {
        let selected = config.selectedProfileName == profile.name
        return HStack(spacing: 12) {
            Button { edit(profile.name) } label: {
                HStack(spacing: 12) {
                    VaultIconTile(systemName: "server.rack")
                    VStack(alignment: .leading, spacing: 5) {
                        Text(profile.name)
                            .font(.system(size: 16, weight: .bold))
                            .foregroundStyle(VaultTheme.textPrimary)
                        ProfileServerLabel(host: profile.host, port: profile.port)
                            .lineLimit(2)
                    }
                    Spacer(minLength: 0)
                }
            }
            .buttonStyle(.plain)
            if selected {
                VStack(spacing: 4) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 24))
                        .foregroundStyle(VaultTheme.primary)
                    Text(languageManager.tr("In use"))
                        .font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(VaultTheme.primary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel(languageManager.tr("Used for connection"))
            } else {
                Button(languageManager.tr("Use")) {
                    if appData.vpnStatus == .disconnected || profile.name == vpnManager.activeProfileName {
                        config.selectProfile(profile.name)
                    } else {
                        pendingProfileSwitch = profile.name
                    }
                }
                .buttonStyle(VaultSecondaryButtonStyle())
                .frame(width: 62)
            }
        }
        .vaultCard(padding: 14)
        .overlay {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(selected ? VaultTheme.primary.opacity(0.45) : Color.clear, lineWidth: 1)
        }
    }

    private var editor: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Button {
                    IosKeyboardDismissal.dismiss()
                    isEditing = false
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 17, weight: .semibold))
                        .frame(width: 44, height: 44)
                }
                .foregroundStyle(VaultTheme.textPrimary)
                Text(languageManager.tr("Profile Details"))
                    .font(.system(size: 28, weight: .bold))
                    .foregroundStyle(VaultTheme.textPrimary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                Spacer()
                Button(languageManager.tr("Save"), action: save)
                    .buttonStyle(VaultSecondaryButtonStyle())
                    .frame(width: 72)
                    .disabled(validationError != nil)
            }
            .padding(.horizontal, 12)
            .padding(.bottom, 8)

            ScrollView {
                VStack(spacing: 12) {
                    VaultSection(languageManager.tr("Basic information")) {
                        field(languageManager.tr("Profile Name")) {
                            TextField(languageManager.tr("Profile Name"), text: $draft.name)
                                .autocorrectionDisabled()
                                .disabled(isActiveProfile)
                        }
                        field(languageManager.tr("Device ID")) {
                            TextField("ID", text: $config.id).disabled(true)
                                .font(.system(size: 13, design: .monospaced))
                        }
                    }

                    VaultSection(languageManager.tr("Server")) {
                        field(languageManager.tr("Host")) {
                            TextField(languageManager.tr("Host"), text: $draft.host)
                                .autocorrectionDisabled().textInputAutocapitalization(.never)
                        }
                        field(languageManager.tr("Port")) {
                            TextField(languageManager.tr("Port"), text: Binding(
                                get: { draft.port },
                                set: { draft.port = String($0.filter { $0.isASCII && $0.isNumber }) }
                            ))
                            .keyboardType(.numberPad).autocorrectionDisabled()
                        }
                        field(languageManager.tr("Password")) {
                            HStack {
                                Group {
                                    if isSecured {
                                        SecureField(languageManager.tr("Password"), text: $draft.password)
                                    } else {
                                        TextField(languageManager.tr("Password"), text: $draft.password)
                                            .autocorrectionDisabled()
                                    }
                                }
                                .textInputAutocapitalization(.never)
                                Button { isSecured.toggle() } label: {
                                    Image(systemName: isSecured ? "eye.slash" : "eye")
                                }
                                .foregroundStyle(VaultTheme.textSecondary)
                            }
                        }
                    }

                    VaultSection("DNS") {
                        field(languageManager.tr("IPv4 DNS")) {
                            TextField(languageManager.tr("IPv4 DNS"), text: $draft.dnsIpv4)
                                .autocorrectionDisabled().textInputAutocapitalization(.never)
                        }
                        field(languageManager.tr("IPv6 DNS")) {
                            TextField(languageManager.tr("IPv6 DNS"), text: $draft.dnsIpv6)
                                .autocorrectionDisabled().textInputAutocapitalization(.never)
                        }
                        Text(languageManager.tr("Leave empty for defaults. Only assigned tunnel families are used."))
                            .font(.system(size: 12)).foregroundStyle(VaultTheme.textSecondary)
                    }

                    VaultSection(languageManager.tr("Advanced settings")) {
                        field(languageManager.tr("MTU")) {
                            TextField(languageManager.tr("MTU"), text: $draft.mtu)
                                .keyboardType(.numberPad).autocorrectionDisabled()
                        }
                    }

                    if let feedback {
                        message(languageManager.tr(feedback), error: true)
                    } else if let validationError {
                        message(languageManager.tr(validationError), error: true)
                    }
                    if let error = config.passwordStorageError {
                        VStack(alignment: .leading, spacing: 12) {
                            message(languageManager.tr(error), error: true)
                            Button(languageManager.tr("Retry")) {
                                config.retryPasswordStorage()
                                draft = config.draft(for: originalName)
                            }
                            .buttonStyle(VaultSecondaryButtonStyle())
                        }
                    }
                    if originalName != nil {
                        Button(languageManager.tr("Delete Profile"), role: .destructive) {
                            IosKeyboardDismissal.dismiss()
                            confirmDelete = true
                        }
                        .font(.system(size: 13, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: 44)
                        .foregroundStyle(VaultTheme.danger)
                        .disabled(isActiveProfile)
                    }
                    Text(languageManager.tr("Save changes before connecting."))
                        .font(.system(size: 12))
                        .foregroundStyle(VaultTheme.textSecondary)
                        .frame(maxWidth: .infinity)
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 20)
            }
            .scrollDismissesKeyboard(.interactively)
            .onSubmit { IosKeyboardDismissal.dismiss() }
        }
    }

    private func field<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11))
                .foregroundStyle(VaultTheme.textSecondary)
            content()
                .font(.system(size: 14))
                .foregroundStyle(VaultTheme.textPrimary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VaultTheme.surfaceSubtle, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(VaultTheme.outline)
        }
    }

    private func message(_ text: String, error: Bool) -> some View {
        Text(text)
            .font(.system(size: 12))
            .foregroundStyle(error ? VaultTheme.danger : VaultTheme.textSecondary)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}
#endif
