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
                size: NSSize(width: 800, height: 620),
                minimum: NSSize(width: 680, height: 520),
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
        factories["welcome"] = { [unowned self] in
            makeWindow(
                id: "welcome",
                title: "Welcome to Vault",
                size: NSSize(width: 560, height: 360),
                minimum: NSSize(width: 560, height: 360),
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
        window.identifier = NSUserInterfaceItemIdentifier(id)
        window.title = LanguageManager.shared.tr(title)
        window.isReleasedWhenClosed = false
        if id == "configure" {
            // The window owns the size across settings pages with different ideal sizes.
            let container = NSView()
            let hostingView = NSHostingView(rootView: content)
            hostingView.sizingOptions = []
            hostingView.translatesAutoresizingMaskIntoConstraints = false
            container.addSubview(hostingView)
            NSLayoutConstraint.activate([
                hostingView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
                hostingView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
                hostingView.topAnchor.constraint(equalTo: container.topAnchor),
                hostingView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
            ])
            window.contentView = container
            window.minSize = minimum
            window.setContentSize(size)
        } else {
            window.minSize = minimum
            window.contentViewController = NSHostingController(rootView: content)
        }
        let frameName = "vault-\(id)-\(["configure", "status", "about"].contains(id) ? "v3" : "v2")"
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
