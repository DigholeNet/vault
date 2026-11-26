//
//  IosConfigureView.swift
//  Vault
//

import SwiftUI
import VaultCore

#if os(iOS)

struct IosConfigureView: View {
    @Binding var selectedTab: Int
    let vpnManager: VpnManager
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
            if isEditing {
                editor
            } else {
                profileList
            }
        }
        .navigationBarBackButtonHidden(true)
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
        Form {
            Section {
                if config.profiles.isEmpty {
                    Text(languageManager.tr("Add a profile to configure a Supernode."))
                        .foregroundStyle(.secondary)
                }
                ForEach(config.profiles, id: \VaultProfile.name) { (profile: VaultProfile) in
                    HStack {
                        Button {
                            edit(profile.name)
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(profile.name).foregroundStyle(.primary)
                                    Text(verbatim: "\(profile.host):\(profile.port)")
                                        .font(.footnote).foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                        }
                        .buttonStyle(.plain)
                        if config.selectedProfileName == profile.name {
                            Image(systemName: "checkmark").foregroundStyle(Color.accentColor)
                                .accessibilityLabel(languageManager.tr("Used for connection"))
                        } else {
                            Button(languageManager.tr("Use")) {
                                if appData.vpnStatus == .disconnected || profile.name == vpnManager.activeProfileName {
                                    config.selectProfile(profile.name)
                                } else {
                                    pendingProfileSwitch = profile.name
                                }
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(Color.accentColor)
                            .accessibilityLabel(languageManager.tr("Used for connection"))
                        }
                    }
                }
            }
            Section {
                Picker(languageManager.tr("Language"), selection: $languageManager.language) {
                    ForEach(AppLanguage.allCases) { language in
                        Text(language.displayName).tag(language)
                    }
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button { edit(nil) } label: { Image(systemName: "plus") }
                    .accessibilityLabel(languageManager.tr("Add Profile"))
            }
        }
    }

    private var editor: some View {
        Form {
            Section {
                TextField(languageManager.tr("Profile Name"), text: $draft.name)
                    .autocorrectionDisabled()
                    .disabled(isActiveProfile)
            }
            Section {
                HStack {
                    Image(systemName: "accessibility")
                    TextField("ID", text: $config.id).disabled(true)
                }
            }
            Section {
                HStack {
                    Image(systemName: "externaldrive.connected.to.line.below")
                    TextField(languageManager.tr("Host"), text: $draft.host)
                        .autocorrectionDisabled().textInputAutocapitalization(.never)
                }
                HStack {
                    Image(systemName: "number.circle")
                    TextField(languageManager.tr("Port"), text: Binding(
                        get: { draft.port },
                        set: { draft.port = String($0.filter { $0.isASCII && $0.isNumber }) }
                    ))
                    .keyboardType(.numberPad).autocorrectionDisabled()
                }
                HStack {
                    Image(systemName: "p.circle.fill")
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
                }
            }
            Section {
                TextField(languageManager.tr("IPv4 DNS"), text: $draft.dnsIpv4)
                    .autocorrectionDisabled().textInputAutocapitalization(.never)
                TextField(languageManager.tr("IPv6 DNS"), text: $draft.dnsIpv6)
                    .autocorrectionDisabled().textInputAutocapitalization(.never)
            } footer: {
                Text(languageManager.tr("Leave empty for defaults. Only assigned tunnel families are used."))
            }
            Section {
                TextField(languageManager.tr("MTU"), text: $draft.mtu)
                    .keyboardType(.numberPad).autocorrectionDisabled()
            }
            if let feedback {
                Section { Text(languageManager.tr(feedback)).foregroundStyle(.red) }
            } else if let validationError {
                Section { Text(languageManager.tr(validationError)).foregroundStyle(.red) }
            }
            if let error = config.passwordStorageError {
                Section {
                    Text(languageManager.tr(error)).foregroundStyle(.red)
                    Button(languageManager.tr("Retry")) {
                        config.retryPasswordStorage()
                        draft = config.draft(for: originalName)
                    }
                }
            }
            if originalName != nil {
                Section {
                    Button(languageManager.tr("Delete Profile"), role: .destructive) {
                        confirmDelete = true
                    }
                    .disabled(isActiveProfile)
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigationBarLeading) {
                Button { isEditing = false } label: { Image(systemName: "chevron.left") }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button(languageManager.tr("Save"), action: save).disabled(validationError != nil)
            }
        }
    }
}

#endif
