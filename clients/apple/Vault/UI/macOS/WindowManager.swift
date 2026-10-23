//
//  WindowManager.swift
//  Vault
//
//
import SwiftUI

#if os(macOS)
    class WindowManager {

        static let shared = WindowManager()

        private var windowControllers: [String: NSWindowController] = [:]

        private init() {}

        func register<T: NSWindowController>(
            _ controller: T,
            with identifier: String
        ) {
            windowControllers[identifier] = controller
        }

        func setTitle(_ title: String, for identifier: String) {
            windowControllers[identifier]?.window?.title = title
        }

        func showWindow(withIdentifier identifier: String) {
            guard let targetController = windowControllers[identifier] else {
                return
            }

            for (id, controller) in windowControllers where id != identifier {
                controller.window?.orderOut(nil)
            }

            if targetController.window == nil {
                targetController.showWindow(nil)
            }

            if let window = targetController.window {
                NSApp.setActivationPolicy(.regular)
                NSApp.activate(ignoringOtherApps: true)
                window.makeKeyAndOrderFront(nil)
            }
        }
    }
#endif
