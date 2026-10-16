//
//  VaultApp.swift
//  Vault
//
//

import SwiftUI
import VaultCore

#if os(macOS)
    class AppDelegate: NSObject, NSApplicationDelegate {
        func applicationDidFinishLaunching(_ notification: Notification) {
            NSApp.setActivationPolicy(.prohibited)
        }
    }
#endif

@main
struct VaultApp: App {
    #if os(macOS)
        @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    #endif

    let appData = AppData()
    let config = VaultConfig()
    let vpnManager: VpnManager

    init() {
        // Warm up the shared file logger during app launch. Resolving the
        // App Group container URL on first access can be slow, so doing it
        // here makes the first "View Logs" tap feel instant.
        _ = FileLogger.shared.currentLogPath

        vpnManager = VpnManager(config: config, appData: appData)
        vpnManager.startObservingStatus()
    }

    var body: some Scene {

        #if os(macOS)
            MenuBarExtra("", image: "MenuIcon") {
                MacosMenuView(vpnManager: vpnManager)
                    .environmentObject(appData).environmentObject(config)
                    .environmentObject(LanguageManager.shared)
            }
        #else

            WindowGroup {
                IosMainView(vpnManager: vpnManager).environmentObject(appData)
                    .environmentObject(config)
                    .environmentObject(LanguageManager.shared)
            }
        #endif

    }
}
