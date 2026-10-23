//
//  MacosMenuView.swift
//  Vault
//
//

import Network
import SwiftUI
import VaultCore

#if os(macOS)
    struct MacosMenuView: View {
        @State private var hasInitialized = false
        var vpnManager: VpnManager

        @EnvironmentObject var appData: AppData
        @EnvironmentObject var config: VaultConfig
        @EnvironmentObject var languageManager: LanguageManager

        var windowManager = WindowManager.shared

        func onError() {
            appData.vpnOn = false
        }
        var body: some View {

            VStack {
                Button(
                    languageManager.tr(
                        "Vault: %@ (v %@)",
                        VpnStatusUtil.getStatus(appData.vpnStatus),
                        Bundle.main.appVersionShort
                    )
                ) {}.disabled(
                    true
                )

                Divider()

                let turnLabel = languageManager.tr(
                    (appData.vpnStatus == .on || appData.vpnStatus == .connecting)
                        ? "Turn Off" : "Turn On"
                )
                Button(turnLabel) {
                    if appData.vpnStatus == .on || appData.vpnStatus == .connecting {
                        vpnManager.disconnect()
                    } else {
                        vpnManager.connect(onError: onError)
                    }
                }.disabled(
                    appData.vpnStatus == VpnStatus.disconnecting
                )

                Button(languageManager.tr("Status ...")) {
                    windowManager.showWindow(withIdentifier: "status")
                }
                .keyboardShortcut("s")

                Button(languageManager.tr("Configure ...")) {
                    windowManager.showWindow(withIdentifier: "configure")
                }.keyboardShortcut("c")

                Divider()
                Button(languageManager.tr("About ...")) {
                    windowManager.showWindow(withIdentifier: "about")
                }

                Divider()
                Button(languageManager.tr("Quit")) {
                    // disconnect() is an async chain (disable on-demand ->
                    // save -> stopVPNTunnel); terminating immediately usually
                    // wins the race and leaves the tunnel up. Wait for the
                    // status to settle to .off first, with a timeout so Quit
                    // can never hang.
                    vpnManager.disconnect()
                    terminateWhenDisconnected()
                }.keyboardShortcut("q")

            }.onAppear {
                if !hasInitialized {
                    initializeOnce()
                    hasInitialized = true
                }
            }
            .onChange(of: appData.showConfigureGuide) { show in
                // connect() without server configuration asks us to guide
                // the user — open the configure window.
                if show {
                    appData.showConfigureGuide = false
                    windowManager.showWindow(withIdentifier: "configure")
                }
            }
            .onChange(of: languageManager.language) {
                // Window titles are plain NSWindow strings outside SwiftUI's
                // render loop — refresh them on language change.
                windowManager.setTitle(languageManager.tr("Status"), for: "status")
                windowManager.setTitle(languageManager.tr("About"), for: "about")
            }
        }

        /// Poll the VPN status until the tunnel reports fully down, then
        /// terminate. The ~3s cap guarantees the app exits even if the
        /// tunnel never reaches .off (e.g. it was still mid-connect or the
        /// status observer is gone).
        private func terminateWhenDisconnected(attemptsRemaining: Int = 30) {
            if vpnManager.vpnStatus == .off || attemptsRemaining <= 0 {
                NSApplication.shared.terminate(nil)
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                terminateWhenDisconnected(attemptsRemaining: attemptsRemaining - 1)
            }
        }

        private func initializeOnce() {
            let statusWindowController = createWindowController(
                title: LanguageManager.shared.tr("Status"),
                id: "status",
                width: 400,
                height: 300,
                contentView: NSHostingView(
                    rootView: MacosStatusView()
                        .environmentObject(appData)
                        .environmentObject(config)
                        .environmentObject(LanguageManager.shared)
                )
            )
            windowManager.register(statusWindowController, with: "status")

            let configureWindowController = createWindowController(
                title: "Vault",
                id: "configure",
                width: 500,
                height: 400,
                contentView: NSHostingView(
                    rootView: MacosConfigureView(config: config)
                        .environmentObject(LanguageManager.shared)
                )
            )

            windowManager.register(configureWindowController, with: "configure")

            let aboutWindowController = createWindowController(
                title: LanguageManager.shared.tr("About"),
                id: "about",
                width: 400,
                height: 300,
                contentView: NSHostingView(
                    rootView: MacosAboutView()
                        .environmentObject(LanguageManager.shared)
                )
            )

            windowManager.register(aboutWindowController, with: "about")

        }

        func createWindowController(
            title: String,
            id: String,
            width: Int,
            height: Int,
            contentView: NSView
        ) -> NSWindowController {
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: width, height: height),
                styleMask: [.titled, .closable],
                backing: .buffered,
                defer: false
            )
            window.center()
            window.setFrameAutosaveName(id)
            window.isReleasedWhenClosed = false
            window.title = title
            window.level = .normal
            window.contentView = contentView
            let windowController = NSWindowController(window: window)
            return windowController
        }
    }

    #Preview {
        let appData = AppData()
        let config = VaultConfig()
        let vpnManager = VpnManager(config: config, appData: appData)
        MacosMenuView(vpnManager: vpnManager)
            .environmentObject(appData).environmentObject(config)
            .environmentObject(LanguageManager.shared)
    }

#endif
