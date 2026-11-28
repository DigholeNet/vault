// SPDX-License-Identifier: MIT
import Foundation
import VaultCore

#if os(macOS)
enum ConnectionAction {
    case connect, disconnect, configure

    init(status: VpnStatus, configured: Bool) {
        self = status != .disconnected ? .disconnect : (configured ? .connect : .configure)
    }
}

extension AppData {
    var connectionActionTitle: String {
        switch vpnStatus {
        case .connected: return "Disconnect"
        case .connecting: return isRecovering ? "Disconnect" : "Cancel Connection"
        case .disconnecting: return connectionError == nil ? "Disconnecting…" : "Disconnect"
        case .disconnected:
            if needsVPNPermission { return "Authorize VPN" }
            return connectionError == nil ? "Connect" : "Retry"
        }
    }
}
#endif

extension String {
    /// Splits a supernode-assigned address string ("ipv4" or "ipv4/ipv6")
    /// into its parts; empty parts become nil.
    func parsedIPv4AndIPv6() -> (ipv4: String?, ipv6: String?) {
        guard !self.isEmpty else { return (nil, nil) }

        let components = self.split(separator: "/", omittingEmptySubsequences: false)
        let ipv4 = !components.isEmpty ? String(components[0]).trimmingCharacters(in: .whitespaces) : nil
        let ipv6 = components.count > 1 ? String(components[1]).trimmingCharacters(in: .whitespaces) : nil

        return (
            ipv4?.isEmpty == false ? ipv4 : nil,
            ipv6?.isEmpty == false ? ipv6 : nil
        )
    }
}
