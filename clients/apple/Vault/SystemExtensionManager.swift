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

    /// Current connection waiter; the OS request may outlive its cancellation.
    private var pendingCompletion: ((Result<Void, Error>) -> Void)?
    private var activationInFlight = false
    private var awaitingUserApproval = false
    private let submitRequest: (OSSystemExtensionRequest) -> Void
    private let openApprovalSettings: () -> Void

    init(
        submitRequest: @escaping (OSSystemExtensionRequest) -> Void = { OSSystemExtensionManager.shared.submitRequest($0) },
        openApprovalSettings: @escaping () -> Void = {
            if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                NSWorkspace.shared.open(url)
            }
        }
    ) {
        self.submitRequest = submitRequest
        self.openApprovalSettings = openApprovalSettings
        super.init()
    }

    /// Submit an activation request. If the extension is already installed and
    /// current, the request completes immediately without user interaction.
    /// Calls are ignored while a connection is already waiting for activation.
    /// After that wait is cancelled, a retry reuses any in-flight OS request
    /// and reopens approval settings if user approval is still required.
    func ensureActivated(completion: @escaping (Result<Void, Error>) -> Void) {
        guard pendingCompletion == nil else {
            Logger.network.noticeAndFile("System extension activation already in progress, ignoring")
            return
        }
        pendingCompletion = completion
        // The OS request may outlive a cancelled connection. Reuse it on retry.
        guard !activationInFlight else {
            if awaitingUserApproval { promptForApproval() }
            return
        }
        activationInFlight = true
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionBundleIdentifier,
            queue: .main
        )
        request.delegate = self
        submitRequest(request)
    }

    func cancelActivationWait() {
        let completion = pendingCompletion
        pendingCompletion = nil
        completion?(.failure(CancellationError()))
    }

    private func finish(with result: Result<Void, Error>) {
        activationInFlight = false
        awaitingUserApproval = false
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
        // Remember this even when the connection was cancelled before the callback.
        awaitingUserApproval = true
        promptForApproval()
    }

    private func promptForApproval() {
        guard pendingCompletion != nil else { return }
        Logger.network.noticeAndFile("System extension needs user approval in System Settings")
        NotificationCenter.default.post(
            name: Self.needsApprovalNotification,
            object: nil
        )
        openApprovalSettings()
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
