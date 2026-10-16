// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import net.dighole.vault.data.readVaultConfig
import net.dighole.vaultcore.Edge
import net.dighole.vaultcore.EdgeConfig
import net.dighole.vaultcore.EdgeException
import net.dighole.vaultcore.LogThrottle
import net.dighole.vaultcore.PeerId
import net.dighole.vaultcore.uniffi.setFdBlocking
import java.io.File
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

@SuppressLint("VpnServicePolicy")
class VaultVpnService : VpnService() {

    companion object {
        const val TAG = "VaultVpnService"
        const val VPN_MTU = 1427

        // Fixed per-packet tunnel overhead: outer IPv6 header (40) + UDP (8)
        // + nonce (8) + AEAD tag (16) + packet type (1).
        const val TUNNEL_OVERHEAD = 73

        // Lower bound for the tunnel MTU (IPv6 minimum MTU).
        const val MIN_VPN_MTU = 1280

        const val ACTION_CONNECT = "net.dighole.vault.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "net.dighole.vault.ACTION_DISCONNECT"

        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_PASSWORD = "password"
        const val EXTRA_ID = "id"
        const val EXTRA_DNS = "dns"
        const val EXTRA_ASSIGNED_IPV4 = "assigned_ipv4"
        const val EXTRA_ASSIGNED_IPV6 = "assigned_ipv6"
        const val EXTRA_BYTES_SENT = "bytes_sent"
        const val EXTRA_BYTES_RECEIVED = "bytes_received"
        const val EXTRA_SEND_SPEED = "send_speed"
        const val EXTRA_RECEIVE_SPEED = "receive_speed"
        const val PREFS_NAME = "vault_prefs"

        /**
         * Reflects whether the service instance is alive and operational.
         * Checks serviceRunning flag and VPN interface validity in addition
         * to the instance reference to handle process-crash stale references.
         */
        @Volatile
        private var serviceInstance: VaultVpnService? = null

        val isRunning: Boolean
            get() {
                val instance = serviceInstance ?: return false
                return instance.serviceRunning.get() &&
                    instance.vpnInterface?.fileDescriptor?.valid() == true
            }
    }

    private lateinit var notificationManager: VpnNotificationManager
    private var vpnIoHandler: VpnIoHandler? = null

    private var edge: Edge? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceRunning = AtomicBoolean(false)
    private var serviceJob = SupervisorJob()
    private var scope = CoroutineScope(Dispatchers.IO + serviceJob)
    private var serverHost: String = ""
    private var dnsList: List<String> = listOf("1.1.1.1", "8.8.8.8")
    private var assignedIpv4: String = ""
    private var tunnelMtu: Int = VPN_MTU
    private var lastUnderlyingTransport: Int? = null

    private var connectJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var networkReconnectJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        serviceInstance = this
        notificationManager = VpnNotificationManager(this)
        notificationManager.createNotificationChannel()
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            Log.d(TAG, "onStartCommand with null intent, stopping")
            stopSelf()
            return START_NOT_STICKY
        }
        when (intent.action) {
            ACTION_CONNECT -> handleConnect(intent)
            ACTION_DISCONNECT -> handleDisconnect()
        }
        return START_REDELIVER_INTENT
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }

    override fun onRevoke() {
        super.onRevoke()
        Log.d(TAG, "onRevoke called by system")
        handleDisconnect()
    }

    private fun handleConnect(intent: Intent) {
        if (serviceRunning.get()) {
            return
        }

        // Re-create scope if it was cancelled by a previous disconnect
        if (!serviceJob.isActive) {
            serviceJob = SupervisorJob()
            scope = CoroutineScope(Dispatchers.IO + serviceJob)
        }

        if (connectJob?.isActive == true) {
            Log.d(TAG, "Connection already in progress, ignoring duplicate request")
            return
        }

        connectJob?.cancel()

        // Clean up previous Edge instance to prevent socket/coroutine leak.
        // Rust shutdown joins worker threads and can block, so the close
        // itself runs on the IO dispatcher at the start of connectJob —
        // handleConnect runs on the main thread and must not block on it.
        val previousEdge = edge
        if (previousEdge != null) {
            Log.w(TAG, "Closing previous Edge before creating new one")
        }
        edge = null

        vpnIoHandler?.stop()

        // Probe the underlying link MTU once per connect, while the active
        // network is still the physical one (the VPN interface is not up yet).
        // Both the TUN interface and the I/O read buffer use this value.
        tunnelMtu = probeTunnelMtu()
        vpnIoHandler = VpnIoHandler(
            scope = scope,
            serviceRunning = serviceRunning,
            mtu = tunnelMtu,
            logTag = TAG,
            onUplinkPacket = { packet -> edge?.writeData(packet) }
        )

        // Start foreground BEFORE validating extras to avoid ANR.
        // If EXTRA_ID is missing we stopSelf immediately after.
        startForeground(
            VpnNotificationManager.NOTIFICATION_ID,
            notificationManager.createNotification(getString(R.string.notification_connecting)),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        )

        val id = intent.getByteArrayExtra(EXTRA_ID)
        if (id == null) {
            Log.e(TAG, "EXTRA_ID missing, stopping service")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        connectJob = scope.launch {
            // Blocking Rust shutdown runs here on the IO dispatcher, not the
            // main thread. Closing before creating the new Edge below also
            // keeps the old UDP socket from racing the new one.
            previousEdge?.let { oldEdge ->
                try {
                    oldEdge.close()
                } catch (_: Exception) {
                }
            }
            try {
                val config = try {
                    this@VaultVpnService.readVaultConfig()
                } catch (_e: Exception) {
                    Log.e(TAG, "Failed to read vault config", _e)
                    emitVpnEvent(VpnStatusEvent.Error("Configuration error"))
                    stopSelf()
                    return@launch
                }
                Log.d(TAG, "Service config loaded")
                if (config.host.isEmpty() || config.password.isEmpty()) {
                    Log.e(TAG, "Vault config incomplete")
                    emitVpnEvent(VpnStatusEvent.Error("Configuration incomplete"))
                    stopSelf()
                    return@launch
                }
                val host = config.host
                val port = config.port
                val password = config.password
                val dnsServers = config.dns.split(",").map { it.trim() }

                serverHost = host
                dnsList = dnsServers

                createAndStartEdge(password, host, port, id)

            } catch (e: EdgeException) {
                Log.e(TAG, "Failed to connect: ${e.message}", e)
                emitVpnEvent(VpnStatusEvent.Error(e.message))
                stopSelf()
            } catch (_e: Exception) {
                Log.e(TAG, "Unexpected error: ${_e.message}", _e)
                emitVpnEvent(VpnStatusEvent.Error(_e.message))
                stopSelf()
            }
        }
    }

    private suspend fun createAndStartEdge(
        password: String,
        host: String,
        port: Int,
        id: ByteArray
    ) {
        // Resolve the server host before the VPN interface is up. Once the TUN
        // interface is active, system DNS queries may be routed through the VPN
        // and black-holed while the tunnel is reconnecting, causing repeated
        // "DNS resolution failed: timeout".
        val addrs = try {
            InetAddress.getAllByName(host)
        } catch (e: java.net.UnknownHostException) {
            Log.w(TAG, "DNS resolution failed for excludeRoute: $host", e)
            emptyArray()
        }

        // Prefer a literal IP for the UDP connection so Rust does not need to
        // perform a DNS lookup that could be intercepted by our own VPN interface.
        // Prefer IPv4 for broader mobile-data compatibility; fall back to IPv6.
        val connectHost = addrs.firstOrNull { it.address.size == 4 }
            ?: addrs.firstOrNull()
        val connectHostStr = connectHost?.let { addr ->
            val ip = addr.hostAddress
            if (addr.address.size == 4) ip else "[$ip]"
        } ?: host

        val edgeConfig = EdgeConfig(password, connectHostStr, port)

        edge = Edge(
            config = edgeConfig,
            id = PeerId(id),
            onData = { data ->
                val handler = vpnIoHandler ?: return@Edge
                val result = handler.pendingWritePackets.trySend(data)
                if (!result.isSuccess) {
                    // Throttled: these fire once per packet while the tunnel
                    // is reconnecting, flooding the logs otherwise.
                    if (result.isClosed) {
                        if (LogThrottle.shouldLog("downlink-channel-closed", 5000)) {
                            Log.d(TAG, "Downlink channel closed, dropping packet")
                        }
                    } else {
                        if (LogThrottle.shouldLog("pending-write-full", 5000)) {
                            Log.w(TAG, "Pending write channel full, dropping packet")
                        }
                    }
                }
            },
            onIpAssigned = { ipv4, ipv4Mask, ipv6, ipv6Prefixlen ->
                scope.launch {
                    try {
                        Log.d(TAG, "IP assigned: ipv4=$ipv4/$ipv4Mask, ipv6=$ipv6/$ipv6Prefixlen")

                        // During a network-switch reconnect the TUN interface can stay up;
                        // re-establishing it closes the old interface and creates a new one,
                        // producing a multi-second black-hole. Skip if we already have a valid
                        // interface with the same assigned IP.
                        if (serviceRunning.get() &&
                            vpnInterface?.fileDescriptor?.valid() == true &&
                            assignedIpv4 == ipv4
                        ) {
                            Log.d(TAG, "Reconnect reused existing TUN interface, skipping re-establish")
                            return@launch
                        }
                        assignedIpv4 = ipv4

                        saveVpnState(true, ipv4, ipv6)
                        startVpnInterface(ipv4, ipv4Mask, ipv6, ipv6Prefixlen, addrs, dnsList)
                        vpnIoHandler?.setVpnInterface(vpnInterface!!)
                        serviceRunning.set(true)
                        connectJob = null
                        vpnIoHandler?.startReadingAndWriting()
                        startTrafficStats()
                        notificationManager.updateNotification(getString(R.string.notification_connected, ipv4))
                        emitVpnEvent(VpnStatusEvent.Connected(ipv4, ipv6))
                    } catch (_e: Exception) {
                        Log.e(TAG, "Failed to start VPN interface: ${_e.message}")
                        serviceRunning.set(false)
                        connectJob = null
                        saveVpnState(false, "", "")
                        emitVpnEvent(VpnStatusEvent.Error(_e.message))
                        stopSelf()
                    }
                }
            },
            pendingCompletion = { error ->
                if (error == null) {
                    // Ignore normal completion.
                } else if (serviceRunning.get()) {
                    // Runtime error (e.g. heartbeat timeout, DNS failure during reconnect).
                    // The Rust run loop already retries with exponential backoff; do NOT kill
                    // the service, otherwise the auto-reconnect logic is interrupted and the
                    // user has to wait for the old service to die before reconnect works.
                    Log.w(TAG, "Runtime error, Rust will retry: ${error.message}")
                    VaultFileLogger.log(Log.WARN, TAG, "Runtime error, Rust will retry: ${error.message}")
                } else {
                    // Initial handshake failed before the VPN interface came up.
                    Log.e(TAG, "Handshake failed: ${error.message}")
                    connectJob = null
                    saveVpnState(false, "", "")
                    emitVpnEvent(VpnStatusEvent.Error(error.message))
                    stopSelf()
                }
            },
            protectSocket = { fd ->
                try {
                    protect(fd)
                } catch (_: Exception) {
                    Log.e(TAG, "Error protecting UDP socket")
                    false
                }
            },
            parentJob = scope.coroutineContext.job
        )

        edge?.connect()
    }

    private fun handleDisconnect() {
        Log.d(TAG, "handleDisconnect called")
        performCleanup()
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            Log.d(TAG, "Service stopped")
        } catch (_: Exception) {
            Log.e(TAG, "Error during disconnect")
        }
    }

    private fun performCleanup() {
        serviceRunning.set(false)
        saveVpnState(false, "", "")

        // Each cleanup step is independent; one failure must not skip the others.
        try {
            unregisterNetworkCallback()
        } catch (_: Exception) {
        }

        // Close Edge first to stop producing data, then close I/O channels.
        // Rust shutdown joins worker threads and can block; this method runs
        // on the main thread (handleDisconnect/onRevoke/onDestroy), so the
        // blocking close is handed to a background thread to avoid an ANR.
        val edgeToClose = edge
        edge = null
        if (edgeToClose != null) {
            thread(name = "edge-close") {
                try {
                    edgeToClose.close()
                } catch (_: Exception) {
                }
            }
        }

        vpnIoHandler?.stop()
        vpnIoHandler = null

        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null

        // Cancel scope after I/O resources are closed so coroutines exit cleanly
        try {
            scope.cancel()
        } catch (_: Exception) {
        }

        assignedIpv4 = ""
        lastUnderlyingTransport = null
        emitVpnEvent(VpnStatusEvent.Disconnected)
    }

    /**
     * Register system network callback to detect WiFi/mobile data switches.
     * When the default network changes, triggers Edge reconnect so the UDP socket
     * binds to the new network interface and gets re-protected.
     */
    private fun registerNetworkCallback() {
        try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    Log.d(TAG, "Network available: $network")
                    if (isVpnNetwork(network)) {
                        Log.d(TAG, "Ignoring our own VPN network")
                        return
                    }
                    if (serviceRunning.get()) {
                        scheduleNetworkReconnect()
                    }
                }

                override fun onLost(network: Network) {
                    Log.d(TAG, "Network lost: $network")
                    if (isVpnNetwork(network)) {
                        Log.d(TAG, "Ignoring our own VPN network loss")
                        return
                    }
                    if (serviceRunning.get()) {
                        // Accelerate reconnect detection when the underlying network drops.
                        // Without this the reconnectJob's 5-second polling may leave the
                        // user with a "connected" UI while traffic is black-holed.
                        scheduleNetworkReconnect()
                    }
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    caps: NetworkCapabilities
                ) {
                    if (isVpnNetwork(network)) {
                        return
                    }
                    val transport = when {
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ->
                            NetworkCapabilities.TRANSPORT_WIFI
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                            NetworkCapabilities.TRANSPORT_CELLULAR
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ->
                            NetworkCapabilities.TRANSPORT_ETHERNET
                        else -> null
                    }
                    if (transport != null) {
                        val previous = lastUnderlyingTransport
                        lastUnderlyingTransport = transport
                        if (previous != null && previous != transport && serviceRunning.get()) {
                            Log.i(
                                TAG,
                                "Underlying transport changed $previous -> $transport, scheduling reconnect"
                            )
                            scheduleNetworkReconnect()
                        }
                    }
                }

                private fun isVpnNetwork(network: Network): Boolean {
                    val caps = cm.getNetworkCapabilities(network) ?: return false
                    return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                }
            }
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
            Log.d(TAG, "Network callback registered")
        } catch (_: Exception) {
            Log.e(TAG, "Failed to register network callback")
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let { callback ->
            try {
                val cm = getSystemService(ConnectivityManager::class.java) ?: return
                cm.unregisterNetworkCallback(callback)
                Log.d(TAG, "Network callback unregistered")
            } catch (_: Exception) {
                Log.e(TAG, "Failed to unregister network callback")
            }
            networkCallback = null
        }
        networkReconnectJob?.cancel()
        networkReconnectJob = null
    }

    /**
     * Debounced network reconnect. Waits 1.5s for the network to stabilize,
     * then triggers Edge reconnect and re-protects the new UDP socket.
     */
    private fun scheduleNetworkReconnect() {
        networkReconnectJob?.cancel()
        networkReconnectJob = scope.launch {
            delay(1500)
            if (!serviceRunning.get() || !isActive) return@launch

            val currentEdge = edge ?: return@launch

            Log.i(TAG, "Network changed, triggering Edge reconnect...")
            VaultFileLogger.log(Log.INFO, TAG, "Network changed, triggering Edge reconnect")
            try {
                currentEdge.reconnect()
            } catch (_e: Exception) {
                Log.e(TAG, "Network-triggered reconnect failed", _e)
            }
        }
    }

    private fun saveVpnState(connected: Boolean, ipv4: String, ipv6: String) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().apply {
            putBoolean("vpn_connected", connected)
            putString("vpn_assigned_ipv4", ipv4)
            putString("vpn_assigned_ipv6", ipv6)
            commit()
        }

        Log.d(TAG, "Saved VPN state: connected=$connected, ipv4=$ipv4, ipv6=$ipv6")
    }

    private fun maskToPrefixLength(mask: String): Int {
        return try {
            mask.split(".").mapNotNull { it.toIntOrNull() }.sumOf {
                Integer.bitCount(it)
            }
        } catch (_: Exception) {
            24 // fallback to default /24
        }
    }

    /**
     * Probes the MTU of the currently active underlying link and derives the
     * tunnel MTU by subtracting the fixed tunnel overhead. The result is
     * clamped to [MIN_VPN_MTU, VPN_MTU]; any failure (no active network,
     * unreadable sysfs entry) falls back to [VPN_MTU].
     */
    private fun probeTunnelMtu(): Int {
        val linkMtu = try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val ifaceName = cm?.activeNetwork
                ?.let { cm.getLinkProperties(it) }
                ?.interfaceName
            ifaceName?.let {
                File("/sys/class/net/$it/mtu").readText().trim().toIntOrNull()
            }
        } catch (_: Exception) {
            null
        }
        if (linkMtu == null) {
            Log.w(TAG, "Could not read underlying link MTU, using default MTU $VPN_MTU")
            return VPN_MTU
        }
        val mtu = (linkMtu - TUNNEL_OVERHEAD).coerceIn(MIN_VPN_MTU, VPN_MTU)
        Log.d(TAG, "Underlying link MTU $linkMtu, tunnel MTU $mtu")
        return mtu
    }

    private fun startVpnInterface(
        assignedIp: String,
        ipv4Mask: String,
        assignedIpv6: String,
        ipv6Prefixlen: Int,
        addrs: Array<out InetAddress>,
        dnsList: List<String>
    ) {
        try {
            val prefixLength = maskToPrefixLength(ipv4Mask)
            val builder = Builder()
                .setMtu(tunnelMtu)
                .addAddress(assignedIp, prefixLength)
                .setSession(getString(R.string.vpn_service_name))
                .setConfigureIntent(
                    PendingIntent.getActivity(
                        this,
                        0,
                        Intent(this, MainActivity::class.java),
                        PendingIntent.FLAG_IMMUTABLE
                    )
                )

            dnsList.forEach { dns ->
                if (dns.isNotEmpty()) {
                    builder.addDnsServer(dns)
                }
            }

            // Add default route (all traffic through VPN)
            builder.addRoute("0.0.0.0", 0)

            // Route IPv6 into the tunnel only when the server actually
            // assigned an IPv6 address. Without one the supernode drops IPv6
            // packets (anti-spoofing source check), which would silently
            // black-hole IPv6 traffic on dual-stack devices.
            if (assignedIpv6.isNotEmpty()) {
                builder.addAddress(assignedIpv6, ipv6Prefixlen)
                try {
                    builder.addRoute("::", 0)
                } catch (_: Exception) {
                    Log.w(TAG, "Failed to add IPv6 default route")
                }
            }

            // Exclude server IP from VPN routing (API 33+ only)
            try {
                for (addr in addrs) {
                    val len = if (addr.address.size == 4) 32 else 128
                    builder.excludeRoute(android.net.IpPrefix(addr, len))
                    Log.d(TAG, "Excluded server IP from VPN: ${addr.hostAddress}")
                }
            } catch (_: Exception) {
                Log.w(TAG, "Failed to exclude server IP")
            }

            vpnInterface = builder.establish()

            checkNotNull(vpnInterface) { "Failed to establish VPN interface" }

            // Some OEM ROMs hand the TUN fd to the app with O_NONBLOCK set.
            // FileInputStream.read() on such an fd returns 0 (EAGAIN) instead
            // of blocking when no packet is queued, which spins the TUN read
            // loop at 100% CPU (plus one expensive JNI exception per empty
            // read). Restore blocking mode once here.
            try {
                setFdBlocking(vpnInterface!!.fd)
            } catch (_e: Exception) {
                Log.w(TAG, "Failed to restore TUN fd blocking mode", _e)
            }

        } catch (_e: Exception) {
            Log.e(TAG, "Failed to start VPN interface: ${_e.message}")
            throw _e
        }
    }

    private fun startTrafficStats() {
        scope.launch {
            while (serviceRunning.get() && isActive) {
                try {
                    edge?.let { e ->
                        e.updateTrafficStats()

                        val stats = e.getTrafficStats()

                        emitVpnEvent(
                            VpnStatusEvent.TrafficStats(
                                stats.bytesSent,
                                stats.bytesReceived,
                                stats.sendSpeed,
                                stats.receiveSpeed
                            )
                        )
                    }
                } catch (_: Exception) {
                    Log.e(TAG, "Error getting traffic stats")
                }

                // Periodically check if VPN I/O is still running.
                // This recovers from I/O coroutines getting stuck due to network changes.
                // It deliberately runs outside the stats try/catch above: a failing
                // stats call (e.g. while the Rust session is mid-reconnect) must not
                // starve the watchdog.
                val ioOk = try {
                    vpnIoHandler?.ensureRunning()
                } catch (_: Exception) {
                    Log.e(TAG, "VPN I/O watchdog check failed")
                    null
                }
                if (ioOk == false) {
                    // The TUN interface is gone and cannot be restarted locally.
                    // Just marking the service disconnected here leaves a zombie:
                    // the Rust session stays connected (heartbeats still pass over
                    // UDP) while all traffic is black-holed and nothing recovers.
                    // Instead, request a Rust reconnect; onIpAssigned then
                    // re-establishes the TUN interface and the I/O loops.
                    Log.w(TAG, "TUN interface unrecoverable, requesting Edge reconnect")
                    VaultFileLogger.log(
                        Log.WARN,
                        TAG,
                        "TUN interface unrecoverable, requesting Edge reconnect"
                    )
                    notificationManager.updateNotification(
                        getString(R.string.notification_connecting)
                    )
                    val currentEdge = edge
                    if (currentEdge == null) {
                        handleDisconnect()
                    } else {
                        scope.launch {
                            try {
                                currentEdge.reconnect()
                            } catch (_e: Exception) {
                                Log.e(TAG, "Watchdog-triggered reconnect failed", _e)
                                handleDisconnect()
                            }
                        }
                    }
                    return@launch
                }
                delay(1000)
            }
            Log.d(TAG, "Traffic stats monitoring stopped")
        }
    }

    private fun emitVpnEvent(event: VpnStatusEvent) {
        // Persist connection state changes and errors to the rolling log file
        // so disconnects can be diagnosed in the field. TrafficStats is
        // excluded: it fires every second and would flood the file.
        if (event !is VpnStatusEvent.TrafficStats) {
            VaultFileLogger.log(Log.INFO, TAG, "VPN status event: $event")
        }
        val app = applicationContext as? VaultApplication ?: return
        app.emitVpnStatusEvent(event)
    }

    override fun onDestroy() {
        Log.d(TAG, "onDestroy called")
        // Always cleanup regardless of serviceRunning state.
        // The service may be destroyed by the system while serviceRunning
        // is already false (e.g. after disconnect) or while still true
        // (e.g. process death). performCleanup() is idempotent.
        performCleanup()
        Log.d(TAG, "Service destroyed, state cleared")
        serviceInstance = null
        super.onDestroy()
    }
}
