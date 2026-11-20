// SPDX-License-Identifier: MIT
import Foundation
import os.log
import VaultCore

extension PacketTunnelProvider {
    /// Resolve and order all addresses with the same core policy used by reconnects.
    func resolveAllAddresses(_ hostname: String, port: UInt16) -> [String] {
        do {
            return try resolveServerCandidates(host: hostname, port: Int32(port))
        } catch {
            Logger.network.error("Unable to resolve \(hostname): \(error.localizedDescription)")
            return []
        }
    }
}
