#if os(macOS)
import AppKit
import SwiftUI

/// Owns long-lived windows independently of the menu bar popover lifecycle.
final class WindowManager {
    static let shared = WindowManager()
    private var controllers: [String: NSWindowController] = [:]
    private var factories: [String: () -> NSWindowController] = [:]
    private var didConfigure = false
    private init() {}

    func configure(vpnManager: VpnManager, appData: AppData, config: VaultConfig) {
        guard !didConfigure else { return }
        didConfigure = true
        factories["configure"] = { [unowned self] in
            makeWindow(
                id: "configure",
                title: "Vault Settings",
                size: NSSize(width: 660, height: 480),
                minimum: NSSize(width: 600, height: 430),
                content:
                MacosConfigureView(config: config)
                    .environmentObject(appData).environmentObject(LanguageManager.shared)
            )
        }
        factories["status"] = { [unowned self] in
            makeWindow(
                id: "status",
                title: "Diagnostics & Logs",
                size: NSSize(width: 960, height: 720),
                minimum: NSSize(width: 960, height: 720),
                content:
                MacosStatusView(vpnManager: vpnManager)
                    .environmentObject(appData).environmentObject(config).environmentObject(LanguageManager.shared)
            )
        }
        factories["about"] = { [unowned self] in
            makeWindow(
                id: "about",
                title: "About",
                size: NSSize(width: 420, height: 440),
                minimum: NSSize(width: 420, height: 440),
                resizable: false,
                content:
                MacosAboutView().environmentObject(LanguageManager.shared)
            )
        }
        factories["welcome"] = { [unowned self] in
            makeWindow(
                id: "welcome",
                title: "Welcome to Vault",
                size: NSSize(width: 480, height: 360),
                minimum: NSSize(width: 480, height: 360),
                resizable: false,
                content:
                MacosWelcomeView().environmentObject(LanguageManager.shared)
            )
        }
    }

    private func makeWindow<Content: View>(
        id: String,
        title: String,
        size: NSSize,
        minimum: NSSize,
        resizable: Bool = true,
        content: Content
    ) -> NSWindowController {
        var style: NSWindow.StyleMask = [.titled, .closable, .miniaturizable]
        if resizable { style.insert(.resizable) }
        let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: style, backing: .buffered, defer: false)
        window.title = LanguageManager.shared.tr(title)
        window.minSize = minimum
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: content)
        let frameName = "vault-\(id)-\(["status", "about"].contains(id) ? "v3" : "v2")"
        if !window.setFrameUsingName(frameName) { window.center() }
        window.setFrameAutosaveName(frameName)
        return NSWindowController(window: window)
    }

    func showWindow(withIdentifier id: String) {
        if controllers[id] == nil { controllers[id] = factories[id]?() }
        guard let window = controllers[id]?.window else { return }
        MacosPreferences.shared.applyActivationPolicy()
        NSApp.activate(ignoringOtherApps: true)
        if window.isMiniaturized { window.deminiaturize(nil) }
        window.makeKeyAndOrderFront(nil)
    }

    func refreshTitles() {
        for (
            id,
            title
        ) in ["configure": "Vault Settings", "status": "Diagnostics & Logs", "about": "About", "welcome": "Welcome to Vault"] {
            controllers[id]?.window?.title = LanguageManager.shared.tr(title)
        }
    }
}
#endif
