// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.app.Application
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import net.dighole.vaultcore.uniffi.setLogFilePath

/**
 * Application class providing a process-level [CoroutineScope] for components
 * that outlive individual Activities/Services (e.g. DataStore I/O).
 */
class VaultApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        // Rolling file log must be up before any logger writes to it.
        VaultFileLogger.init(this)
        // Route Rust core/bridge records (including the panic hook) into the
        // same vault.log the Kotlin side writes to.
        VaultFileLogger.currentLogPath?.let { path ->
            try {
                setLogFilePath(path)
            } catch (e: UnsatisfiedLinkError) {
                Log.w(TAG, "vault-bridge native library unavailable", e)
            }
        }
    }

    /**
     * Application-wide coroutine scope bound to the process lifetime.
     * When the OS kills the process all coroutines are terminated automatically;
     * no explicit cancellation is required.
     */
    val applicationScope: CoroutineScope by lazy {
        CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    /**
     * Process-wide event bus for VPN status updates.
     * Replaces global broadcasts with a type-safe, zero-copy in-process flow.
     * Extra buffer capacity prevents event loss during brief UI pauses.
     */
    val vpnStatusEvents: MutableSharedFlow<VpnStatusEvent> =
        MutableSharedFlow(replay = 1, extraBufferCapacity = 64)

    /**
     * The most recently emitted VPN status event.
     * Used to immediately restore UI state after configuration changes
     * (rotation, locale switch, process death) without waiting for a new event.
     */
    @Volatile
    var currentVpnStatus: VpnStatusEvent? = null
        private set

    /**
     * Emit a VPN status event and update the cached current status.
     * TrafficStats events are not cached so they do not overwrite
     * the connection state (Connected/Disconnected/Error).
     */
    private val connectionClock = ConnectionClock()
    val connectedAt: Long? get() = connectionClock.startedAt

    @Volatile var latestTrafficStats: VpnStatusEvent.TrafficStats? = null
        private set

    fun ensureConnectionStarted(): Long = connectionClock.connected(android.os.SystemClock.elapsedRealtime())

    @Synchronized
    fun emitVpnStatusEvent(event: VpnStatusEvent) {
        when (event) {
            is VpnStatusEvent.Connected -> ensureConnectionStarted()
            is VpnStatusEvent.Disconnected, is VpnStatusEvent.Error -> {
                connectionClock.disconnected()
                latestTrafficStats = null
            }
            is VpnStatusEvent.TrafficStats -> latestTrafficStats = event
            else -> Unit
        }
        if (event !is VpnStatusEvent.TrafficStats) {
            currentVpnStatus = event
        }
        vpnStatusEvents.tryEmit(event)
    }

    private companion object {
        const val TAG = "VaultApplication"
    }
}
