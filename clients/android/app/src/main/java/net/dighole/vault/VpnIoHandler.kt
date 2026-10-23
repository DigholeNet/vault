// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import net.dighole.vaultcore.LogThrottle
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Handles TUN interface packet I/O for the VPN service.
 *
 * Responsibilities:
 * - Reading IP packets from the VPN TUN interface
 * - Writing decrypted packets back to the TUN interface
 * - Managing internal channels for producer/consumer decoupling
 * - Restarting I/O coroutines when they become stuck
 */
// isClosedForSend / isClosedForReceive are used only to decide whether a
// channel must be rebuilt; a lost race just recreates an empty channel.
@OptIn(DelicateCoroutinesApi::class)
class VpnIoHandler(
    private val scope: CoroutineScope,
    private val serviceRunning: AtomicBoolean,
    private val mtu: Int,
    private val logTag: String,
    private val onUplinkPacket: (ByteArray) -> Unit
) {
    /**
     * Channel for downlink packets received from the VPN server.
     * External producers (e.g. Edge.onData) write into this channel.
     * Rebuilt after stop() if ensureRunning() detects it was closed.
     */
    private var _pendingWritePackets = Channel<ByteArray>(capacity = 1024)
    val pendingWritePackets: Channel<ByteArray> get() = _pendingWritePackets

    private var uplinkChannel: Channel<ByteArray>? = null
    @Volatile
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnInputStream: FileInputStream? = null
    private var vpnOutputStream: FileOutputStream? = null
    @Volatile
    private var vpnReadJob: Job? = null
    @Volatile
    private var vpnWriteJob: Job? = null
    @Volatile
    private var vpnIoRestartJob: Job? = null
    private val interfaceGate = SessionGate()
    private var interfaceToken = 0L

    @Synchronized
    fun setVpnInterface(iface: ParcelFileDescriptor) {
        interfaceToken = interfaceGate.begin()
        vpnInterface = iface
        ensureUplinkChannel()
    }

    private fun ensureUplinkChannel() {
        if (uplinkChannel == null || uplinkChannel?.isClosedForSend == true) {
            uplinkChannel = Channel<ByteArray>(capacity = 1024)
            Log.d(logTag, "Uplink channel created/recreated")
        }
    }

    @Synchronized
    fun startReadingAndWriting() {
        startReadingPackets()
        startWritingPackets()
    }

    /**
     * Checks if read/write coroutines are active and restarts them if needed.
     * @return false if the VPN interface was destroyed and cannot be recovered
     */
    @Synchronized
    fun ensureRunning(): Boolean {
        if (!serviceRunning.get()) return true

        val readActive = vpnReadJob?.isActive == true
        val writeActive = vpnWriteJob?.isActive == true
        if (readActive && writeActive) return true

        val result = when {
            vpnIoRestartJob?.isActive == true -> {
                Log.d(logTag, "VPN I/O restart already in progress, skipping")
                true
            }
            vpnInterface == null -> {
                Log.e(logTag, "VPN interface is null, cannot restart I/O")
                false
            }
            else -> {
                if (_pendingWritePackets.isClosedForReceive) {
                    _pendingWritePackets = Channel<ByteArray>(capacity = 1024)
                    Log.d(logTag, "Pending write channel rebuilt after stop()")
                }
                ensureUplinkChannel()
                val token = interfaceToken
                val readJob = vpnReadJob
                val writeJob = vpnWriteJob
                vpnIoRestartJob = scope.launch {
                    Log.w(
                        logTag,
                        "VPN I/O coroutines not active (read=$readActive, write=$writeActive), restarting..."
                    )

                    readJob?.cancel()
                    writeJob?.cancel()

                    var timedOut = false
                    try {
                        withTimeout(3000) {
                            readJob?.join()
                            writeJob?.join()
                        }
                    } catch (_: TimeoutCancellationException) {
                        timedOut = true
                    }

                    synchronized(this@VpnIoHandler) {
                        if (!serviceRunning.get() || !isActive) return@synchronized
                        // Handover may have replaced both the interface and jobs
                        // while join was suspended. Never touch their successors.
                        interfaceGate.update(token) {
                            if (timedOut) {
                                Log.w(logTag, "Old I/O jobs did not exit in time, forcing interface close")
                                vpnInterface?.close()
                                vpnInterface = null
                            }
                            if (vpnInterface == null) {
                                Log.e(logTag, "VPN interface is null, cannot restart I/O")
                            } else {
                                if (vpnReadJob?.isActive != true) startReadingPackets()
                                if (vpnWriteJob?.isActive != true) startWritingPackets()
                                Log.d(logTag, "VPN I/O coroutines restarted")
                            }
                        }
                    }
                }
                true
            }
        }
        return result
    }

    fun isInterfaceAvailable(): Boolean = vpnInterface?.fileDescriptor?.valid() == true

    fun isRunning(): Boolean = isInterfaceAvailable() &&
        vpnReadJob?.isActive == true && vpnWriteJob?.isActive == true &&
        vpnIoRestartJob?.isActive != true

    /**
     * Cancels the I/O coroutines and closes the current TUN interface without
     * touching the packet channels. Used when a reconnect swaps the TUN
     * interface: the caller then installs the new one via [setVpnInterface]
     * and restarts I/O with [startReadingAndWriting]. Cancelling alone would
     * not unblock the read coroutine parked in a blocking read — closing the
     * fd does.
     */
    @Synchronized
    fun releaseInterface() {
        interfaceGate.stop { }
        vpnIoRestartJob?.cancel()
        vpnReadJob?.cancel()
        vpnWriteJob?.cancel()

        try {
            vpnInputStream?.close()
        } catch (_: Exception) {
        }
        vpnInputStream = null

        try {
            vpnOutputStream?.close()
        } catch (_: Exception) {
        }
        vpnOutputStream = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    @Synchronized
    fun stop() {
        interfaceGate.stop { }
        try {
            _pendingWritePackets.close()
            Log.d(logTag, "Pending write channel closed")
        } catch (_: Exception) {
        }
        try {
            uplinkChannel?.close()
            Log.d(logTag, "Uplink channel closed")
        } catch (_: Exception) {
        }
        uplinkChannel = null

        // Close File streams to release native buffers.
        // Closing a FileInputStream/FileOutputStream created from a FileDescriptor
        // does NOT close the underlying fd (Java spec), so this is safe.
        try {
            vpnInputStream?.close()
            Log.d(logTag, "VPN input stream closed")
        } catch (_: Exception) {
        }
        vpnInputStream = null

        try {
            vpnOutputStream?.close()
            Log.d(logTag, "VPN output stream closed")
        } catch (_: Exception) {
        }
        vpnOutputStream = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null

        vpnReadJob?.cancel()
        vpnWriteJob?.cancel()
        vpnIoRestartJob?.cancel()
    }

    /**
     * Forwards queued uplink packets to the Edge for encryption and sending.
     * Runs until the channel is closed or the coroutine is cancelled.
     */
    private fun CoroutineScope.startUplinkForwarding(channel: Channel<ByteArray>): Job = launch {
        while (serviceRunning.get() && isActive) {
            try {
                val packet = channel.receive()
                onUplinkPacket(packet)
            } catch (_: CancellationException) {
                break
            } catch (_: ClosedReceiveChannelException) {
                break
            } catch (_e: Exception) {
                // Throttled: fires per packet while the uplink is broken.
                if (LogThrottle.shouldLog("uplink-processing-error", 5000)) {
                    Log.e(logTag, "Uplink processing error", _e)
                }
            }
        }
        Log.d(logTag, "Uplink processing stopped")
    }

    private fun startReadingPackets() {
        vpnReadJob = scope.launch {
            val iface = vpnInterface ?: run {
                Log.e(logTag, "VPN interface is null, cannot start reading")
                return@launch
            }
            val input = FileInputStream(iface.fileDescriptor)
            vpnInputStream = input
            val buffer = ByteArray(mtu)
            ensureUplinkChannel()
            val channel = uplinkChannel ?: run {
                Log.e(logTag, "Uplink channel is null, cannot start reading")
                return@launch
            }

            val uplinkJob = startUplinkForwarding(channel)

            Log.d(
                logTag,
                "Started reading packets from VPN interface, running=${serviceRunning.get()}"
            )
            var readPackets = 0L
            var readBytes = 0L
            var lastReadLog = System.currentTimeMillis()
            try {
                while (serviceRunning.get() && isActive) {
                    try {
                        val length = input.read(buffer)
                        if (length > 0) {
                            readPackets++
                            readBytes += length
                            val now = System.currentTimeMillis()
                            if (now - lastReadLog >= 1000L) {
                                // Skip idle intervals; a "0 pkts / 0 bytes" line every
                                // second drowns out useful logs during reconnect.
                                if (readPackets > 0) {
                                    Log.i(logTag, "TUN read last 1s: $readPackets pkts / $readBytes bytes")
                                }
                                readPackets = 0
                                readBytes = 0
                                lastReadLog = now
                            }
                            val packet = buffer.copyOf(length)
                            val sendResult = channel.trySend(packet)
                            when {
                                sendResult.isSuccess -> {}
                                sendResult.isClosed -> {
                                    Log.d(logTag, "Uplink channel closed, exiting read loop")
                                    break
                                }
                                else -> {
                                    // Throttled: fires per packet when the consumer stalls.
                                    if (LogThrottle.shouldLog("uplink-channel-full", 5000)) {
                                        Log.w(logTag, "Uplink channel full, dropping packet")
                                    }
                                }
                            }
                        } else if (length == -1) {
                            Log.d(logTag, "VPN interface EOF")
                            break
                        }
                    } catch (e: java.io.IOException) {
                        if (serviceRunning.get()) {
                            Log.e(logTag, "IO Error reading packet: ${e.message}")
                        }
                        break
                    } catch (_e: Exception) {
                        Log.e(logTag, "Error reading packet", _e)
                        if (serviceRunning.get()) {
                            delay(100)
                        }
                    }
                }
            } finally {
                cleanupAfterReadLoop(uplinkJob, input)
            }
            Log.d(logTag, "Packet reading stopped")
        }
    }

    private suspend fun cleanupAfterReadLoop(uplinkJob: Job, input: FileInputStream) {
        uplinkJob.cancel()
        try {
            withTimeout(2000) {
                uplinkJob.join()
            }
        } catch (_: TimeoutCancellationException) {
            Log.w(logTag, "Uplink job did not exit in time")
        }
        // Close the input stream when the read loop exits to prevent
        // native fd leak on normal termination (EOF) or error paths.
        try {
            input.close()
            if (vpnInputStream === input) {
                vpnInputStream = null
            }
            Log.d(logTag, "VPN input stream closed")
        } catch (_: Exception) {
        }
    }

    private fun startWritingPackets() {
        vpnWriteJob = scope.launch {
            val iface = vpnInterface ?: run {
                Log.e(logTag, "VPN interface is null, cannot start writing")
                return@launch
            }
            val output = FileOutputStream(iface.fileDescriptor)
            vpnOutputStream = output

            var writePackets = 0L
            var writeBytes = 0L
            var lastWriteLog = System.currentTimeMillis()
            try {
                while (serviceRunning.get() && isActive) {
                    val packet = try {
                        pendingWritePackets.receive()
                    } catch (_: CancellationException) {
                        break
                    } catch (_: ClosedReceiveChannelException) {
                        break
                    }
                    try {
                        output.write(packet)
                        writePackets++
                        writeBytes += packet.size
                        val now = System.currentTimeMillis()
                        if (now - lastWriteLog >= 1000L) {
                            // Skip idle intervals; see the read loop above.
                            if (writePackets > 0) {
                                Log.i(logTag, "TUN write last 1s: $writePackets pkts / $writeBytes bytes")
                            }
                            writePackets = 0
                            writeBytes = 0
                            lastWriteLog = now
                        }
                        // Explicit flush is not needed here; the kernel flushes the
                        // shared fd on its own schedule. Removing it avoids a syscall
                        // per packet and significantly improves throughput.
                    } catch (e: java.io.IOException) {
                        Log.e(logTag, "IO Error writing packet: ${e.message}")
                        break
                    } catch (_e: Exception) {
                        // Throttled: fires per packet while the TUN fd is broken.
                        if (LogThrottle.shouldLog("write-packet-error", 5000)) {
                            Log.e(logTag, "Error writing packet", _e)
                        }
                    }
                }
            } finally {
                // Do not close the FileOutputStream — it shares the fd with vpnInterface.
                // But clear the reference to avoid leaking the old stream object.
                if (vpnOutputStream === output) {
                    vpnOutputStream = null
                }
            }
            Log.d(logTag, "Packet writing stopped")
        }
    }
}
