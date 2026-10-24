// SPDX-License-Identifier: MIT
package net.dighole.vault

/**
 * Sealed class representing VPN status events emitted by [VaultVpnService]
 * and consumed by UI components (e.g. [StatusFragment]).
 *
 * Replaces global broadcast-based communication with a type-safe in-process flow,
 * eliminating broadcast receiver overhead and exported-broadcast risks.
 */
sealed class VpnStatusEvent {
    data class Connected(val ipv4: String, val ipv6: String) : VpnStatusEvent()
    data object Reconnecting : VpnStatusEvent()
    data object Disconnected : VpnStatusEvent()
    data class Error(val message: String?) : VpnStatusEvent()
    data class TrafficStats(
        val bytesSent: Long,
        val bytesReceived: Long,
        val sendSpeed: Long,
        val receiveSpeed: Long,
        val packetsSent: Long = 0,
        val packetsReceived: Long = 0
    ) : VpnStatusEvent()
}
