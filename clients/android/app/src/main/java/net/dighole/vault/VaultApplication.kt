// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.app.Application
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch
import net.dighole.vault.data.recordVaultHostLatency
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
            } catch (e: LinkageError) {
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

    private var latencyWrite: Job? = null

    @Synchronized
    @Suppress("TooGenericExceptionCaught")
    internal fun saveHostLatency(name: String, host: String, port: Int, milliseconds: Long) {
        val previous = latencyWrite
        latencyWrite = applicationScope.launch {
            // Preserve submission order across quick disconnects and service restarts.
            previous?.join()
            try {
                recordVaultHostLatency(name, host, port, milliseconds)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Log.w(TAG, "Could not save host latency", error)
            }
        }
    }

    /**
     * Process-wide event bus for VPN status updates.
     * Replays the latest event to new collectors and buffers brief subscriber delays.
     */
    val vpnStatusEvents: MutableSharedFlow<VpnStatusEvent> =
        MutableSharedFlow(replay = 1, extraBufferCapacity = 64)

    /**
     * Latest non-traffic status within this process; restores UI after rotation
     * or locale changes. Persisted preferences provide the process-restart fallback.
     */
    @Volatile
    var currentVpnStatus: VpnStatusEvent? = null
        private set

    @Volatile var vpnGeneration: Long = 0
        private set
    @Volatile var activeProfileName: String? = null
    @Volatile var requestedProfileName: String? = null

    private val connectionClock = ConnectionClock()
    val connectedAt: Long? get() = connectionClock.startedAt

    @Volatile var latestTrafficStats: VpnStatusEvent.TrafficStats? = null
        private set

    fun ensureConnectionStarted(): Long = connectionClock.connected(android.os.SystemClock.elapsedRealtime())

    /** Cache connection state and traffic separately, then publish the event. */
    @Synchronized
    fun emitVpnStatusEvent(event: VpnStatusEvent) {
        when (event) {
            is VpnStatusEvent.Connected -> ensureConnectionStarted()
            is VpnStatusEvent.Disconnecting, is VpnStatusEvent.Disconnected, is VpnStatusEvent.Error -> {
                connectionClock.disconnected()
                latestTrafficStats = null
            }
            is VpnStatusEvent.TrafficStats -> latestTrafficStats = event
            else -> Unit
        }
        if (event !is VpnStatusEvent.TrafficStats) {
            vpnGeneration++
            currentVpnStatus = event
        }
        vpnStatusEvents.tryEmit(event)
    }

    private companion object {
        const val TAG = "VaultApplication"
    }
}
