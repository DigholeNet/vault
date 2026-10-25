//
//  Extension.swift
//  VaultCore
//
//
import Foundation
import os.log
import Security

// Single-letter names (v/c/b) are deliberate in the byte-level parsing helpers
// below; readability would suffer from longer names there.
// swiftlint:disable identifier_name

extension Logger {
    // Hardcoded instead of Bundle.main.bundleIdentifier: reading it performs
    // disk I/O (and may be flagged when it first happens on the main
    // thread), and inside the network extension Bundle.main is the .appex
    // whose identifier differs from the app's.
    private static let subsystem = "net.dighole.vault"

    public static let network = Logger(
        subsystem: subsystem,
        category: "network"
    )
}

extension Array {
    @inlinable
    init(reserveCapacity: Int) {
        self = [Element]()
        self.reserveCapacity(reserveCapacity)
    }
}

/// The app group identifier configured at build time: `APP_GROUP_ID` in
/// `Config/Shared.xcconfig`, injected into each target's Info.plist as
/// `VaultAppGroupID`. Empty in SwiftPM builds/tests (no host Info.plist
/// there); consumers treat that as "no app group" and degrade gracefully.
private let kConfiguredAppGroup: String =
    Bundle.main.object(forInfoDictionaryKey: "VaultAppGroupID") as? String ?? ""

#if os(macOS)
// macOS uses a system extension distributed via Developer ID, which requires
// team-prefixed app group identifiers (and NEMachServiceName derives from it).
// The identifier is resolved from the process's own code-signing entitlements
// so no team ID is hardcoded in source; it always matches the team that
// signed the build (including TEAM_ID overrides in scripts/package-apple.sh).
public let kAppGroupIdentifier: String = signingAppGroup() ?? kConfiguredAppGroup

/// Returns the configured app group granted to this process by its code
/// signature, including any team-identifier prefix.
private func signingAppGroup() -> String? {
    guard !kConfiguredAppGroup.isEmpty else { return nil }
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess,
          let code else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(
        code,
        SecCSFlags(rawValue: kSecCSSigningInformation),
        &info
    ) == errSecSuccess,
        let dict = info as? [String: Any],
        let entitlements = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
        let groups = entitlements["com.apple.security.application-groups"] as? [String]
    else { return nil }
    return groups.first { $0.hasSuffix(kConfiguredAppGroup) }
}
#else
public let kAppGroupIdentifier = kConfiguredAppGroup
#endif

extension Array where Element == UInt8 {
    public init?(hex: String) {
        self.init(reserveCapacity: hex.unicodeScalars.lazy.underestimatedCount)
        var buffer: UInt8?
        var skip = hex.hasPrefix("0x") ? 2 : 0
        for char in hex.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                return nil
            }
            let v: UInt8
            let c: UInt8 = UInt8(char.value)
            switch c {
            case let c where c <= 57:
                v = c - 48
            case let c where c >= 65 && c <= 70:
                v = c - 55
            case let c where c >= 97:
                v = c - 87
            default:
                removeAll()
                return
            }
            if let b = buffer {
                append(b << 4 | v)
                buffer = nil
            } else {
                buffer = v
            }
        }
        if let b = buffer {
            append(b)
        }
    }
}
