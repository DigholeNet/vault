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

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
