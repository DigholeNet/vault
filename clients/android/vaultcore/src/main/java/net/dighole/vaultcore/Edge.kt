// SPDX-License-Identifier: MIT
package net.dighole.vaultcore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.os.Build
import android.util.Log
import net.dighole.vaultcore.uniffi.ConnectionStatus
import net.dighole.vaultcore.uniffi.EdgeCallbacks
import net.dighole.vaultcore.uniffi.RustEdge
import net.dighole.vaultcore.uniffi.TrafficStats
import net.dighole.vaultcore.uniffi.TunnelAssignment
import net.dighole.vaultcore.uniffi.VpnException

/**
 * Configuration for Edge connection.
 *
 * @property password Server password for authentication
 * @property hosts Server IP addresses in preference order; the Rust core
 *   races the handshakes Happy-Eyeballs style
 * @property port Server port number
 */
class EdgeConfig(
    val password: String,
    val hosts: List<String>,
    val port: Int
)

class EdgeException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Kotlin adapter for the Rust VPN session and Android callbacks.
 *
 * This class is a thin Kotlin wrapper around the Rust implementation in
 * `vault-core`. The Rust runtime handles UDP sockets, handshake, heartbeat,
 * encryption, and reconnection. Android-specific concerns (TUN fd, socket
 * protection) remain on the Kotlin side via callbacks.
 */
class Edge(
    val config: EdgeConfig,
    private val id: PeerId,
    private val onPackets: (List<ByteArray>) -> Unit,
    private val onIpAssigned: (TunnelAssignment) -> Unit,
    private val pendingCompletion: (Throwable?) -> Unit,
    private val protectSocket: ((Int) -> Boolean)? = null
) {
    private var rustEdge: RustEdge?

    init {
        val callbacks = object : EdgeCallbacks {
            override fun onDataBatch(packets: List<ByteArray>) {
                this@Edge.onPackets(packets)
            }

            override fun onIpAssigned(assignment: TunnelAssignment) {
                this@Edge.onIpAssigned(assignment)
            }

            override fun onError(error: String) {
                this@Edge.pendingCompletion(EdgeException(error))
            }

            override fun protectSocket(fd: Int): Boolean {
                return this@Edge.protectSocket?.invoke(fd) ?: false
            }
        }

        val deviceName = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
        rustEdge = RustEdge(
            config.password,
            config.hosts,
            config.port,
            id.id,
            deviceName.ifEmpty { "unknown" },
            "android",
            callbacks
        )
    }

    suspend fun connect() = withContext(Dispatchers.IO) {
        synchronized(this@Edge) {
            rustEdge?.connect() ?: throw VpnException.NotConnected("Edge is closed")
        }
    }

    fun close() {
        val current = synchronized(this) {
            val current = rustEdge ?: return
            rustEdge = null
            current
        }
        // Shutdown waits for callbacks, so never hold the Edge monitor here.
        try {
            current.shutdown()
        } finally {
            current.close()
        }
    }

    /** Used on network changes. */
    suspend fun reconnect() = withContext(Dispatchers.IO) {
        synchronized(this@Edge) {
            rustEdge?.reconnect() ?: throw VpnException.NotConnected("Edge is closed")
        }
    }

    companion object {
        private const val TAG = "Edge"
    }

    /**
     * Queues a plaintext IP packet for encryption and transmission by Rust.
     * Returns true if the packet was accepted, false if sending failed
     * (tunnel not connected or an internal error).
     */
    @Synchronized
    fun writeData(data: ByteArray): Boolean {
        return try {
            rustEdge?.writeData(data) ?: return false
            true
        } catch (e: VpnException) {
            // Drops are expected during reconnect; the Rust runtime will retry
            // the connection. Throttled: this fires once per packet while the
            // tunnel is down, flooding logcat and the log file otherwise.
            if (LogThrottle.shouldLog("writeData-drop", 5000)) {
                Log.w(TAG, "Dropping uplink packet: ${e.message}")
            }
            false
        }
    }

    @Synchronized
    fun getConnectionStatus(): ConnectionStatus {
        return rustEdge?.getConnectionStatus()
            ?: ConnectionStatus(connected = false, generation = 0u, publicIp = "")
    }

    @Synchronized
    fun isConnected(): Boolean = getConnectionStatus().connected

    @Synchronized
    fun getTrafficStats(): TrafficStats {
        return rustEdge?.getTrafficStats() ?: TrafficStats(0, 0, 0, 0, 0, 0)
    }
}
