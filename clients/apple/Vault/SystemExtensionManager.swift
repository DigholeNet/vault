//
//  SystemExtensionManager.swift
//  Vault
//
//
//  macOS only: manages activation of the VaultSystemExtension packet-tunnel
//  system extension. Developer ID distribution on macOS requires Network
//  Extension providers to ship as system extensions; activation needs user
//  approval and the app must run from /Applications.
//

#if os(macOS)
import AppKit
import Foundation
import SystemExtensions
import VaultCore
import os.log

enum SystemExtensionError: LocalizedError {
    case needsUserApproval
    case requiresReboot

    var errorDescription: String? {
        switch self {
        case .needsUserApproval:
            return LanguageManager.shared.tr(
                "System extension approval required: System Settings → General → Login Items & Extensions"
            )
        case .requiresReboot:
            return LanguageManager.shared.tr(
                "The system extension will take effect after a restart."
            )
        }
    }
}

final class SystemExtensionManager: NSObject {
    static let shared = SystemExtensionManager()

    /// The sysex target's bundle ID is the app bundle ID plus a fixed suffix
    /// (`$(APP_BUNDLE_ID_PREFIX).VaultSystemExtension` in the project).
    static let extensionBundleIdentifier: String = {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            fatalError("Vault.app has no bundle identifier")
        }
        return "\(bundleID).VaultSystemExtension"
    }()

    /// Posted when activation is blocked on user approval in System Settings.
    static let needsApprovalNotification = Notification.Name("VaultSystemExtensionNeedsApproval")

    /// Non-nil while an activation request is in flight.
    private var pendingCompletion: ((Result<Void, Error>) -> Void)?

    /// Submit an activation request. If the extension is already installed and
    /// current, the request completes immediately without user interaction.
    /// While a request is in flight (e.g. awaiting user approval) further
    /// calls are ignored — the original completion fires once resolved.
    func ensureActivated(completion: @escaping (Result<Void, Error>) -> Void) {
        guard pendingCompletion == nil else {
            Logger.network.noticeAndFile("System extension activation already in progress, ignoring")
            return
        }
        pendingCompletion = completion
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func finish(with result: Result<Void, Error>) {
        let completion = pendingCompletion
        pendingCompletion = nil
        completion?(result)
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        Logger.network.noticeAndFile(
            "Replacing system extension \(existing.bundleShortVersion) (\(existing.bundleVersion)) with \(ext.bundleShortVersion) (\(ext.bundleVersion))"
        )
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Logger.network.noticeAndFile("System extension needs user approval in System Settings")
        NotificationCenter.default.post(
            name: Self.needsApprovalNotification,
            object: nil
        )
        // Take the user to the approval UI. The pending request completes
        // (didFinishWithResult) once the user approves there.
        if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            Logger.network.noticeAndFile("System extension activated")
            finish(with: .success(()))
        case .willCompleteAfterReboot:
            Logger.network.noticeAndFile("System extension will complete after reboot")
            finish(with: .failure(SystemExtensionError.requiresReboot))
        @unknown default:
            finish(with: .failure(SystemExtensionError.requiresReboot))
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsError = error as NSError
        Logger.network.errorAndFile(
            "System extension activation failed: \(nsError.domain) code \(nsError.code): \(error.localizedDescription)"
        )
        finish(with: .failure(error))
    }
}
#endif
