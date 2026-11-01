//
//  main.swift
//  VaultSystemExtension
//
//
//  System extension entry point (macOS only). The tunnel logic lives in the
//  shared TunnelProvider group (PacketTunnelProvider.swift).
//

import Foundation
import NetworkExtension
import VaultCore

let entryUptime = ProcessInfo.processInfo.systemUptime
FileLogger.shared.processTag = "ne"
FileLogger.shared.logSync("System extension main entered pid=\(ProcessInfo.processInfo.processIdentifier)", level: "NOTICE")
autoreleasepool {
    FileLogger.shared.logSync("Calling startSystemExtensionMode", level: "NOTICE")
    NEProvider.startSystemExtensionMode()
    let elapsed = Int((ProcessInfo.processInfo.systemUptime - entryUptime) * 1000)
    FileLogger.shared.logSync("startSystemExtensionMode returned sinceEntryMs=\(elapsed)", level: "NOTICE")
}

dispatchMain()
