// SPDX-License-Identifier: MIT
package net.dighole.vault

import java.util.Locale

internal object StatusPresentation {
    fun duration(elapsedMs: Long): String {
        val seconds = elapsedMs.coerceAtLeast(0) / 1000
        return String.format(Locale.ROOT, "%02d:%02d:%02d", seconds / 3600, (seconds / 60) % 60, seconds % 60)
    }

    fun bytes(count: Long): String {
        val units = listOf("B", "KB", "MB", "GB", "TB")
        var value = count.coerceAtLeast(0).toDouble()
        var unit = 0
        while (value >= 1024 && unit < units.lastIndex) { value /= 1024; unit++ }
        return String.format(Locale.ROOT, "%.2f %s", value, units[unit])
    }
}

/** One clock per VPN session, independent of Activity/Fragment recreation and recovery. */
internal class ConnectionClock {
    @Volatile var startedAt: Long? = null
        private set

    @Synchronized fun connected(now: Long): Long = startedAt ?: now.also { startedAt = it }
    @Synchronized fun disconnected() { startedAt = null }
}

/** Shared by event delivery and restoring a screen from the cached VPN status. */
internal data class VpnUiState(
    val isConnected: Boolean = false,
    val isConnecting: Boolean = false,
    val ipv4: String = "",
    val ipv6: String = ""
) {
    fun applying(event: VpnStatusEvent): VpnUiState = when (event) {
        is VpnStatusEvent.Connecting -> VpnUiState(isConnecting = true)
        is VpnStatusEvent.Connected -> VpnUiState(isConnected = true, ipv4 = event.ipv4, ipv6 = event.ipv6)
        // A reconnecting service remains available to disconnect, and keeps its assigned addresses.
        is VpnStatusEvent.Reconnecting -> copy(isConnected = true, isConnecting = true)
        is VpnStatusEvent.Disconnected, is VpnStatusEvent.Error -> VpnUiState()
        is VpnStatusEvent.TrafficStats -> this
    }
}
