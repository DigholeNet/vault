#if os(macOS)
import AppKit
import ServiceManagement
import SwiftUI

/// Reuse the installed app icon; the menu bar separately uses MenuIcon.
struct MacosAppIcon: View {
    var size: CGFloat
    // Load the AppIcon compiled into this bundle, rather than the process's
    // NSApplicationIcon (which can be generic for a menu-bar-only app).
    private static let bundledIcon: NSImage? = {
        guard let name = Bundle.main.object(forInfoDictionaryKey: "CFBundleIconFile") as? String else { return nil }
        let filename = name as NSString
        let ext = filename.pathExtension.isEmpty ? "icns" : filename.pathExtension
        let resource = filename.pathExtension.isEmpty ? name : filename.deletingPathExtension
        guard let url = Bundle.main.url(forResource: resource, withExtension: ext) else { return nil }
        return NSImage(contentsOf: url)
    }()

    var body: some View {
        Group {
            if let icon = Self.bundledIcon ?? NSImage(named: "AppIcon") {
                Image(nsImage: icon).resizable()
            }
        }
        .scaledToFit()
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

final class MacosPreferences: ObservableObject {
    static let shared = MacosPreferences()
    @Published var autoConnect: Bool {
        didSet { UserDefaults.standard.set(autoConnect, forKey: "macAutoConnect") }
    }
    @Published var showInDock: Bool {
        didSet {
            UserDefaults.standard.set(showInDock, forKey: "macShowInDock")
            applyActivationPolicy()
        }
    }
    @Published private(set) var launchAtLogin = false
    @Published var launchError: String?

    private init() {
        autoConnect = UserDefaults.standard.bool(forKey: "macAutoConnect")
        showInDock = UserDefaults.standard.bool(forKey: "macShowInDock")
        refreshLoginStatus()
    }

    func applyActivationPolicy() {
        NSApp.setActivationPolicy(showInDock ? .regular : .accessory)
    }

    func refreshLoginStatus() {
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            refreshLoginStatus()
            if SMAppService.mainApp.status == .requiresApproval {
                launchError = "Approve Vault in System Settings → General → Login Items."
            }
        } catch {
            launchError = error.localizedDescription
            refreshLoginStatus()
        }
    }
}
#endif
