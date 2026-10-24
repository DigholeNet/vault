import SwiftUI
import VaultCore

#if os(macOS)
final class AppDelegate: NSObject, NSApplicationDelegate {
    static var onLaunch: (() -> Void)?
    static var vpnManager: VpnManager?
    private var terminating = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        MacosPreferences.shared.applyActivationPolicy()
        Self.onLaunch?()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let manager = Self.vpnManager else { return .terminateNow }
        guard !terminating else { return .terminateLater }
        terminating = true
        // Even an idle profile may still have an on-demand rule after a failure.
        manager.disconnect { succeeded in
            self.terminating = false
            NSApp.reply(toApplicationShouldTerminate: succeeded)
            if !succeeded {
                let alert = NSAlert()
                alert.messageText = LanguageManager.shared.tr("Unable to disconnect. Please try again.")
                alert.runModal()
            }
        }
        return .terminateLater
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { WindowManager.shared.showWindow(withIdentifier: "configure") }
        return true
    }
}

struct MacosAppCommands: Commands {
    let vpnManager: VpnManager
    @ObservedObject var appData: AppData
    let config: VaultConfig
    @ObservedObject private var languageManager = LanguageManager.shared
    var body: some Commands {
        CommandGroup(replacing: .appSettings) {
            Button(languageManager.tr("Settings…")) { WindowManager.shared.showWindow(withIdentifier: "configure") }
                .keyboardShortcut(",")
        }
        CommandGroup(replacing: .appInfo) {}
        CommandGroup(after: .newItem) {
            Button(languageManager.tr("Close")) { NSApp.keyWindow?.performClose(nil) }
                .keyboardShortcut("w")
        }
        CommandGroup(after: .appSettings) {
            Button(languageManager.tr(appData.vpnStatus == .on || appData.vpnStatus == .connecting ? "Disconnect" : "Connect")) {
                if appData.vpnStatus == .on || appData.vpnStatus == .connecting {
                    vpnManager.disconnect()
                } else if config.host.isEmpty || config.password.isEmpty {
                    WindowManager.shared.showWindow(withIdentifier: "configure")
                } else {
                    vpnManager.connect()
                }
            }
            .keyboardShortcut(.return, modifiers: .command)
            .disabled(appData.vpnStatus == .disconnecting)
            Button(languageManager.tr("Diagnostics & Logs")) { WindowManager.shared.showWindow(withIdentifier: "status") }
                .keyboardShortcut("d", modifiers: [.command, .shift])
        }
        CommandGroup(replacing: .appTermination) {
            Button(languageManager.tr("Quit")) { NSApp.terminate(nil) }.keyboardShortcut("q")
        }
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
        _ = FileLogger.shared.currentLogPath
        let manager = VpnManager(config: config, appData: appData)
        vpnManager = manager
        #if os(macOS)
        let data = appData
        let configuration = config
        WindowManager.shared.configure(vpnManager: manager, appData: data, config: configuration)
        AppDelegate.vpnManager = manager
        AppDelegate.onLaunch = {
            manager.startObservingStatus {
                if configuration.host.isEmpty || configuration.password.isEmpty {
                    if !UserDefaults.standard.bool(forKey: "macWelcomeShown") {
                        UserDefaults.standard.set(true, forKey: "macWelcomeShown")
                        WindowManager.shared.showWindow(withIdentifier: "welcome")
                    }
                } else if MacosPreferences.shared.autoConnect && manager.vpnStatus == .off {
                    manager.connect()
                }
            }
        }
        #else
        manager.startObservingStatus()
        #endif
    }

    var body: some Scene {
        #if os(macOS)
        MenuBarExtra {
            MacosMenuView(vpnManager: vpnManager)
                .environmentObject(appData).environmentObject(config).environmentObject(LanguageManager.shared)
        } label: {
            MacosMenuLabel(appData: appData).environmentObject(LanguageManager.shared)
        }
        .menuBarExtraStyle(.window)
        .commands {
            MacosAppCommands(vpnManager: vpnManager, appData: appData, config: config)
            TextEditingCommands()
        }
        #else
        WindowGroup {
            IosMainView(vpnManager: vpnManager).environmentObject(appData)
                .environmentObject(config).environmentObject(LanguageManager.shared)
        }
        #endif
    }
}
