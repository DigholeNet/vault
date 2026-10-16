// SPDX-License-Identifier: MIT
package net.dighole.vaultcore

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import android.os.Build
import android.util.Log
import net.dighole.vaultcore.uniffi.EdgeCallbacks
import net.dighole.vaultcore.uniffi.RustEdge
import net.dighole.vaultcore.uniffi.TrafficStats
import net.dighole.vaultcore.uniffi.VpnException

/**
 * Configuration for Edge connection.
 *
 * @property password Server password for authentication
 * @property host Server hostname or IP address
 * @property port Server port number
 */
class EdgeConfig(
    val password: String,
    val host: String,
    val port: Int
)

class EdgeException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Core VPN networking component managing peer connections and packet routing.
 *
 * This class is a thin Kotlin wrapper around the Rust implementation in
 * `vault-core`. The Rust runtime handles UDP sockets, handshake, heartbeat,
 * encryption, and reconnection. Android-specific concerns (TUN fd, socket
 * protection) remain on the Kotlin side via callbacks.
 */
class Edge(
    val config: EdgeConfig,
    private val id: PeerId,
    private val onData: (ByteArray) -> Unit,
    private val onIpAssigned: (String, String, String, Int) -> Unit,
    private val pendingCompletion: (Throwable?) -> Unit,
    private val protectSocket: ((Int) -> Boolean)? = null,
    parentJob: Job? = null
) {
    private val rustEdge: RustEdge

    init {
        val callbacks = object : EdgeCallbacks {
            override fun onData(data: ByteArray) {
                // Explicitly qualify to avoid calling the callback method itself.
                this@Edge.onData(data)
            }

            override fun onDataBatch(packets: List<ByteArray>) {
                for (packet in packets) {
                    this@Edge.onData(packet)
                }
            }

            override fun onIpAssigned(
                ipv4: String,
                ipv4Mask: String,
                ipv6: String,
                ipv6Prefixlen: Int
            ) {
                this@Edge.onIpAssigned(ipv4, ipv4Mask, ipv6, ipv6Prefixlen)
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
            config.host,
            config.port,
            id.id,
            deviceName.ifEmpty { "unknown" },
            "android",
            callbacks
        )
    }

    suspend fun connect() = withContext(Dispatchers.IO) {
        rustEdge.connect()
    }

    fun close() {
        rustEdge.shutdown()
    }

    /** Used on network changes. */
    suspend fun reconnect() = withContext(Dispatchers.IO) {
        rustEdge.reconnect()
    }

    companion object {
        private const val TAG = "Edge"
    }

    /**
     * Sends an encrypted IP packet to the server.
     * Returns true if the packet was accepted, false if the tunnel is not yet connected.
     */
    fun writeData(data: ByteArray): Boolean {
        return try {
            rustEdge.writeData(data)
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

    /**
     * Refreshes internal traffic statistics. Should be called periodically.
     */
    fun updateTrafficStats() {
        // Statistics are computed on-demand in Rust; no explicit update needed.
    }

    fun getTrafficStats(): TrafficStats {
        return rustEdge.getTrafficStats()
    }
}
