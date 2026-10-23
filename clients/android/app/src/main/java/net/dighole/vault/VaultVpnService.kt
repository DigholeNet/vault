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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import net.dighole.vault.data.readVaultConfig
import net.dighole.vaultcore.Edge
import net.dighole.vaultcore.EdgeConfig
import net.dighole.vaultcore.LogThrottle
import net.dighole.vaultcore.PeerId
import net.dighole.vaultcore.uniffi.setFdBlocking
import java.io.File
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

@SuppressLint("VpnServicePolicy")
class VaultVpnService : VpnService() {

    companion object {
        const val TAG = "VaultVpnService"
        const val VPN_MTU = 1427

        // Fixed per-packet tunnel overhead: outer IPv6 header (40) + UDP (8)
        // + counter (8) + AEAD tag (16) + packet type (1).
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
         * An active service has a usable TUN or is recovering it. A temporarily
         * closed TUN during recovery must not look like a killed service to UI.
         */
        @Volatile
        private var serviceInstance: VaultVpnService? = null

        val isRunning: Boolean
            get() {
                val instance = serviceInstance ?: return false
                return instance.serviceRunning.get() &&
                    (instance.vpnInterface?.fileDescriptor?.valid() == true ||
                        instance.recoveryState.isRecovering())
            }
    }

    private lateinit var notificationManager: VpnNotificationManager
    private var vpnIoHandler: VpnIoHandler? = null

    private var edge: Edge? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceRunning = AtomicBoolean(false)
    private val sessionGate = SessionGate()
    private var tunnelConfigurationSequence = 0L // Protected by sessionGate.
    private var serviceJob = SupervisorJob()
    private var scope = CoroutineScope(Dispatchers.IO + serviceJob)
    private var serverHost: String = ""
    private var dnsList: List<String> = listOf("1.1.1.1", "8.8.8.8")
    private data class AssignedAddresses(
        val ipv4: String,
        val ipv4Mask: String,
        val ipv6: String,
        val ipv6PrefixLen: Int
    )

    private var assignedAddresses: AssignedAddresses? = null
    private var tunnelMtu: Int = VPN_MTU
    private var lastUnderlyingTransport: Int? = null

    private val networkEventSequence = AtomicLong()
    private val recoveryState = RecoveryState()
    @Volatile
    private var pendingRecoveryConnection: VpnStatusEvent.Connected? = null
    private var trafficStatsJob: Job? = null
    private var connectJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var networkReconnectJob: Job? = null

    private fun trace(event: String) {
        VaultFileLogger.event(TAG, "service=${System.identityHashCode(this)} " +
            "running=${serviceRunning.get()} recovering=${recoveryState.isRecovering()} " +
            "tunValid=${vpnInterface?.fileDescriptor?.valid()} $event")
    }

    override fun onCreate() {
        super.onCreate()
        trace("SERVICE_CREATE")
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

    // Native/Android setup can throw varied exceptions; cancellation is rethrown.
    @Suppress("TooGenericExceptionCaught")
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
        val sessionToken = sessionGate.begin()

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
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    sessionGate.update(sessionToken) {
                        Log.e(TAG, "Failed to read vault config", error)
                        emitVpnEvent(VpnStatusEvent.Error("Configuration error"))
                        stopSelf()
                    }
                    return@launch
                }
                Log.d(TAG, "Service config loaded")
                if (config.host.isEmpty() || config.password.isEmpty()) {
                    sessionGate.update(sessionToken) {
                        Log.e(TAG, "Vault config incomplete")
                        emitVpnEvent(VpnStatusEvent.Error("Configuration incomplete"))
                        stopSelf()
                    }
                    return@launch
                }
                val host = config.host
                val port = config.port
                val password = config.password
                val dnsServers = config.dns.split(",").map { it.trim() }

                if (!sessionGate.update(sessionToken) {
                    serverHost = host
                    dnsList = dnsServers
                }) return@launch

                createAndStartEdge(password, host, port, id, sessionToken)

            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                sessionGate.update(sessionToken) {
                    Log.e(TAG, "Failed to connect: ${error.message}", error)
                    emitVpnEvent(VpnStatusEvent.Error(error.message))
                    stopSelf()
                }
            }
        }
    }

    private suspend fun createAndStartEdge(
        password: String,
        host: String,
        port: Int,
        id: ByteArray,
        sessionToken: Long
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

        // Prefer literal IPs for the UDP connection so Rust does not need to
        // perform a DNS lookup that could be intercepted by our own VPN interface.
        // The Rust core races all candidates Happy-Eyeballs style (300 ms
        // stagger, first completed handshake wins). IPv6 is listed first
        // (RFC 8305); IPv4 follows as fallback.
        val connectHosts = addrs.sortedBy { if (it.address.size == 4) 1 else 0 }
            .map { addr ->
                val ip = addr.hostAddress
                if (addr.address.size == 4) ip else "[$ip]"
            }
            .distinct()
            .ifEmpty { listOf(host) }

        val edgeConfig = EdgeConfig(password, connectHosts, port)

        val newEdge = Edge(
            config = edgeConfig,
            id = PeerId(id),
            onData = { data ->
                sessionGate.update(sessionToken) {
                    val handler = vpnIoHandler ?: return@update
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
                }
            },
            onIpAssigned = { ipv4, ipv4Mask, ipv6, ipv6Prefixlen ->
                handleEdgeIpAssigned(AssignedAddresses(ipv4, ipv4Mask, ipv6, ipv6Prefixlen), addrs, sessionToken)
            },
            pendingCompletion = { error ->
                sessionGate.update(sessionToken) {
                    if (error == null) {
                        // Ignore normal completion.
                    } else if (serviceRunning.get()) {
                        trace("RUST_RETRY_ERROR reason=${error.message}")
                        // Runtime error (e.g. heartbeat timeout, DNS failure during reconnect).
                        // The Rust run loop already retries with exponential backoff; do NOT kill
                        // the service, otherwise the auto-reconnect logic is interrupted and the
                        // user has to wait for the old service to die before reconnect works.
                        Log.w(TAG, "Runtime error, Rust will retry: ${error.message}")
                        VaultFileLogger.log(Log.WARN, TAG, "Runtime error, Rust will retry: ${error.message}")
                        // Rust already owns this retry; only synchronize Android status.
                        pendingRecoveryConnection = null
                        markRecovering("Rust automatic retry: ${error.message}", restart = true)
                    } else {
                        // Initial handshake failed before the VPN interface came up.
                        Log.e(TAG, "Handshake failed: ${error.message}")
                        connectJob = null
                        saveVpnState(false, "", "")
                        emitVpnEvent(VpnStatusEvent.Error(error.message))
                        stopSelf()
                    }
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

        if (!sessionGate.update(sessionToken) { edge = newEdge }) {
            newEdge.close()
            return
        }
        newEdge.connect()
    }

    // Native/Android setup failures must be reported only to the current session.
    @Suppress("TooGenericExceptionCaught")
    private fun handleEdgeIpAssigned(
        addresses: AssignedAddresses,
        addrs: Array<InetAddress>,
        sessionToken: Long
    ) {
        trace("IP_ASSIGNED_CALLBACK")
        var configurationSequence = 0L
        if (!sessionGate.update(sessionToken) {
            tunnelConfigurationSequence++
            configurationSequence = tunnelConfigurationSequence
        }) return
        scope.launch {
            sessionGate.configure {
                val (ipv4, ipv4Mask, ipv6, ipv6Prefixlen) = addresses
                try {
                    var reused = false
                    var superseded = false
                    val current = sessionGate.update(sessionToken) {
                        trace("IP_ASSIGNED_APPLY")
                        superseded = configurationSequence != tunnelConfigurationSequence
                        if (superseded) return@update
                        if (serviceRunning.get() &&
                            vpnInterface?.fileDescriptor?.valid() == true &&
                            vpnIoHandler?.isInterfaceAvailable() == true &&
                            assignedAddresses == addresses
                        ) {
                            vpnIoHandler?.ensureRunning()
                            onTunnelConfigured(ipv4, ipv6)
                            startTrafficStats(sessionToken)
                            reused = true
                        }
                    }
                    if (!current || reused || superseded) return@configure

                    // Keep blocking establish outside the gate so stop stays responsive.
                    // Retain the old TUN until Android has successfully created the new one.
                    trace("TUN_HANDOVER_BEGIN")
                    val newInterface = createVpnInterface(ipv4, ipv4Mask, ipv6, ipv6Prefixlen, addrs, dnsList)
                    sessionGate.commit(
                        sessionToken,
                        newInterface,
                        condition = { configurationSequence == tunnelConfigurationSequence },
                        // establish() deactivates the old TUN even if we discard
                        // its replacement. An open old fd is no longer reusable.
                        onCreated = { assignedAddresses = null }
                    ) { iface ->
                        trace("TUN_HANDOVER_ESTABLISHED newFd=${iface.fd}")
                        val previousInterface = vpnInterface
                        vpnIoHandler?.releaseInterface()
                        try {
                            previousInterface?.close()
                        } catch (_: Exception) {
                        }
                        vpnInterface = iface
                        assignedAddresses = addresses
                        vpnIoHandler?.setVpnInterface(iface)
                        saveVpnState(true, ipv4, ipv6)
                        serviceRunning.set(true)
                        connectJob = null
                        vpnIoHandler?.startReadingAndWriting()
                        onTunnelConfigured(ipv4, ipv6)
                        startTrafficStats(sessionToken)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    sessionGate.updateIf(sessionToken, { configurationSequence == tunnelConfigurationSequence }) {
                        Log.e(TAG, "Failed to start VPN interface: ${error.message}")
                        serviceRunning.set(false)
                        connectJob = null
                        saveVpnState(false, "", "")
                        emitVpnEvent(VpnStatusEvent.Error(error.message))
                        stopSelf()
                    }
                }
            }
        }
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

    private fun performCleanup() = sessionGate.stop {
        trace("CLEANUP_BEGIN")
        serviceRunning.set(false)
        stopTrafficStats()
        recoveryState.reset()
        pendingRecoveryConnection = null
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

        assignedAddresses = null
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
                    trace("NETWORK_AVAILABLE network=$network")
                    Log.d(TAG, "Network available: $network")
                    if (isVpnNetwork(network)) {
                        Log.d(TAG, "Ignoring our own VPN network")
                        return
                    }
                    if (serviceRunning.get()) {
                        scheduleNetworkReconnect("onAvailable network=$network")
                    }
                }

                override fun onLost(network: Network) {
                    trace("NETWORK_LOST network=$network")
                    Log.d(TAG, "Network lost: $network")
                    if (isVpnNetwork(network)) {
                        Log.d(TAG, "Ignoring our own VPN network loss")
                        return
                    }
                    lastUnderlyingTransport = null
                    if (serviceRunning.get()) {
                        // Enter recovery without waiting for the core heartbeat timeout.
                        scheduleNetworkReconnect("onLost network=$network")
                    }
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    caps: NetworkCapabilities
                ) {
                    trace(
                        "NETWORK_CAPABILITIES network=$network " +
                            "vpn=${caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)} " +
                            "wifi=${caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)} " +
                            "cell=${caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)}"
                    )
                    // VPN capabilities also carry the underlying physical transport.
                    // Keep tracking it so a cellular/Wi-Fi handoff triggers recovery.
                    val transport = when {
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ->
                            NetworkCapabilities.TRANSPORT_WIFI
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                            NetworkCapabilities.TRANSPORT_CELLULAR
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ->
                            NetworkCapabilities.TRANSPORT_ETHERNET
                        else -> null
                    }
                    val previous = lastUnderlyingTransport
                    // Remember loss as well: Wi-Fi -> no network -> the same
                    // Wi-Fi must wake recovery, not look like an unchanged path.
                    lastUnderlyingTransport = transport
                    if (previous != transport && serviceRunning.get() &&
                        (previous != null || recoveryState.isRecovering())
                    ) {
                        Log.i(
                            TAG,
                            "Underlying transport changed $previous -> $transport, scheduling reconnect"
                        )
                        scheduleNetworkReconnect("onCapabilitiesChanged network=$network transport=$previous->$transport")
                    }
                }

                private fun isVpnNetwork(network: Network): Boolean {
                    val caps = cm.getNetworkCapabilities(network)
                    val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                    trace("NETWORK_CLASSIFY network=$network capsPresent=${caps != null} vpn=$vpn")
                    return vpn
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
    private fun scheduleNetworkReconnect(source: String) {
        val request = networkEventSequence.incrementAndGet()
        trace("NETWORK_RECONNECT_SCHEDULE id=$request source=$source cancelPrevious=${networkReconnectJob?.isActive}")
        networkReconnectJob?.cancel()
        networkReconnectJob = scope.launch {
            delay(1500)
            trace("NETWORK_RECONNECT_FIRE id=$request source=$source active=$isActive")
            if (!serviceRunning.get() || !isActive) return@launch

            requestRecovery("Underlying network changed id=$request source=$source", networkChanged = true)
        }
    }

    private fun showConnected(event: VpnStatusEvent.Connected) {
        trace("SHOW_CONNECTED")
        notificationManager.updateNotification(getString(R.string.notification_connected, event.ipv4))
        emitVpnEvent(event)
    }

    private fun onTunnelConfigured(ipv4: String, ipv6: String) {
        val event = VpnStatusEvent.Connected(ipv4, ipv6)
        // Publish the addresses before marking configuration complete: the
        // sampler may observe readiness immediately on another IO thread.
        pendingRecoveryConnection = event
        val deferred = recoveryState.onConfigured()
        trace("TUN_CONFIGURED deferConnected=$deferred")
        if (!deferred) {
            pendingRecoveryConnection = null
            showConnected(event)
        }
    }

    /** Mark recovery without restarting an already retrying Rust session. */
    private fun markRecovering(reason: String, restart: Boolean = false): Boolean {
        if (!serviceRunning.get() || !recoveryState.begin(restart)) {
            trace("RECOVERY_SKIPPED reason=$reason")
            return false
        }
        trace("RECOVERY_BEGIN reason=$reason")
        Log.w(TAG, "Recovering: $reason")
        VaultFileLogger.log(Log.WARN, TAG, "Recovering: $reason")
        notificationManager.updateNotification(getString(R.string.notification_connecting))
        emitVpnEvent(VpnStatusEvent.Reconnecting)
        return true
    }

    /** One recovery spans all Rust retries until handshake and TUN I/O succeed. */
    // Recovery must never crash the service, hence the broad catch below.
    @Suppress("TooGenericExceptionCaught")
    private fun requestRecovery(reason: String, networkChanged: Boolean = false) {
        if (!serviceRunning.get()) return
        val started = markRecovering(reason, restart = networkChanged)
        // A real network change must wake the Rust loop even during an
        // existing recovery. Watchdog ticks stay deduplicated so they cannot
        // repeatedly interrupt a handshake or reset its retry backoff.
        if (!started && !networkChanged) return
        pendingRecoveryConnection = null
        val currentEdge = edge
        if (currentEdge == null) {
            handleDisconnect()
            return
        }
        scope.launch {
            try {
                coroutineContext.ensureActive()
                if (!serviceRunning.get() || edge !== currentEdge) return@launch
                trace("RECONNECT_NATIVE_BEGIN reason=$reason")
                currentEdge.reconnect()
                trace("RECONNECT_NATIVE_RETURN reason=$reason")
                // Returning only means recovery was requested in the existing session.
                // onIpAssigned and the sampler finish recovery after I/O is ready.
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Edge recovery failed", e)
                if (serviceRunning.get() && edge === currentEdge) handleDisconnect()
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

    private fun createVpnInterface(
        assignedIp: String,
        ipv4Mask: String,
        assignedIpv6: String,
        ipv6Prefixlen: Int,
        addrs: Array<out InetAddress>,
        dnsList: List<String>
    ): ParcelFileDescriptor {
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

            val newInterface = checkNotNull(builder.establish()) { "Failed to establish VPN interface" }

            // Some OEM ROMs hand the TUN fd to the app with O_NONBLOCK set.
            // FileInputStream.read() on such an fd returns 0 (EAGAIN) instead
            // of blocking when no packet is queued, which spins the TUN read
            // loop at 100% CPU (plus one expensive JNI exception per empty
            // read). Restore blocking mode once here.
            try {
                setFdBlocking(newInterface.fd)
            } catch (_e: Exception) {
                Log.w(TAG, "Failed to restore TUN fd blocking mode", _e)
            }
            return newInterface
        } catch (_e: Exception) {
            Log.e(TAG, "Failed to start VPN interface: ${_e.message}")
            throw _e
        }
    }

    @Synchronized
    private fun stopTrafficStats() {
        trafficStatsJob?.cancel()
        trafficStatsJob = null
    }

    @Synchronized
    // The watchdog loop must survive transient native-call failures, hence
    // the broad catch below.
    @Suppress("TooGenericExceptionCaught")
    private fun startTrafficStats(sessionToken: Long) {
        if (!serviceRunning.get() || trafficStatsJob?.isActive == true) return
        // Publish the Job before it can run on the IO dispatcher.
        trafficStatsJob = scope.launch(start = CoroutineStart.LAZY) {
            while (serviceRunning.get() && isActive) {
                try {
                    edge?.let { e ->
                        val stats = e.getTrafficStats()
                        // Native calls may finish after disconnect cancelled us.
                        coroutineContext.ensureActive()

                        emitVpnEvent(
                            VpnStatusEvent.TrafficStats(
                                stats.bytesSent,
                                stats.bytesReceived,
                                stats.sendSpeed,
                                stats.receiveSpeed
                            )
                        )
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Log.e(TAG, "Error getting traffic stats", e)
                }

                // Periodically check if VPN I/O is still running.
                // This recovers from I/O coroutines getting stuck due to network changes.
                // It deliberately runs outside the stats try/catch above: a failing
                // stats call (e.g. while the Rust session is mid-reconnect) must not
                // starve the watchdog.
                sessionGate.update(sessionToken) {
                    val ioOk = try {
                        vpnIoHandler?.ensureRunning()
                    } catch (_: Exception) {
                        Log.e(TAG, "VPN I/O watchdog check failed")
                        null
                    }
                    if (recoveryState.completeIfReady(vpnIoHandler?.isRunning() == true)) {
                        trace("RECOVERY_COMPLETE_IO_READY")
                        pendingRecoveryConnection?.let { showConnected(it) }
                        pendingRecoveryConnection = null
                    }
                    if (ioOk == false) {
                        requestRecovery("TUN interface unrecoverable")
                    }
                }
                delay(1000)
            }
            Log.d(TAG, "Traffic stats monitoring stopped")
        }.also { it.start() }
    }

    private fun emitVpnEvent(event: VpnStatusEvent) {
        // Persist connection state changes and errors to the rolling log file
        // so disconnects can be diagnosed in the field. TrafficStats is
        // excluded: it fires every second and would flood the file.
        if (event !is VpnStatusEvent.TrafficStats) {
            trace("EMIT_STATUS event=$event")
            VaultFileLogger.log(Log.INFO, TAG, "VPN status event: $event")
        }
        val app = applicationContext as? VaultApplication ?: return
        app.emitVpnStatusEvent(event)
    }

    override fun onDestroy() {
        trace("SERVICE_DESTROY")
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
