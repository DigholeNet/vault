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
import kotlinx.coroutines.launch
import net.dighole.vault.data.readVaultConfig
import net.dighole.vaultcore.Edge
import net.dighole.vaultcore.EdgeConfig
import net.dighole.vaultcore.LogThrottle
import net.dighole.vaultcore.PeerId
import net.dighole.vaultcore.uniffi.VpnException
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

        /** The service stays active during core reconnects and platform IP updates. */
        @Volatile
        private var serviceInstance: VaultVpnService? = null

        val isRunning: Boolean
            get() {
                val instance = serviceInstance ?: return false
                return instance.serviceRunning.get()
            }
    }

    private lateinit var notificationManager: VpnNotificationManager
    private var vpnIoHandler: VpnIoHandler? = null

    @Volatile
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

    private var tunnelMtu: Int = VPN_MTU
    private var lastUnderlyingTransport: Int? = null

    private var connectedEvent: VpnStatusEvent.Connected? = null
    private var lastCoreConnected: Boolean? = null
    private var trafficStatsJob: Job? = null
    private var connectJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private fun trace(event: String) {
        VaultFileLogger.event(TAG, "service=${System.identityHashCode(this)} " +
            "running=${serviceRunning.get()} " +
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
                val dnsServers = config.dns.ifBlank { "1.1.1.1,8.8.8.8" }.split(",").map { it.trim() }
                if (!sessionGate.update(sessionToken) {
                    config.mtu.toIntOrNull()?.takeIf { it in MIN_VPN_MTU..VPN_MTU }?.let {
                        tunnelMtu = it
                        vpnIoHandler?.stop()
                        vpnIoHandler = VpnIoHandler(scope = scope, serviceRunning = serviceRunning,
                            mtu = tunnelMtu, logTag = TAG,
                            onUplinkPacket = { packet -> edge?.writeData(packet) })
                    }
                }) return@launch

                if (!sessionGate.update(sessionToken) {
                    serverHost = host
                    dnsList = dnsServers
                    (application as VaultApplication).diagnosticDomains = config.probeDomains
                        .split(',').map { it.trim() }.filter { it.isNotEmpty() }
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
        // stagger, first completed handshake wins), including family preference.
        val connectHosts = addrs.asSequence()
            .map { addr ->
                val ip = addr.hostAddress
                if (addr.address.size == 4) ip else "[$ip]"
            }
            .distinct()
            .toList()
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
                    } else {
                        // Transport errors are informational: Rust owns all retries,
                        // including failures before the first IP assignment.
                        Log.w(TAG, "Rust client retry: ${error.message}")
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
            }
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
        var sequence = 0L
        if (!sessionGate.update(sessionToken) {
            tunnelConfigurationSequence++
            sequence = tunnelConfigurationSequence
        }) return
        scope.launch {
            sessionGate.configure {
                if (!sessionGate.updateIf(sessionToken, { sequence == tunnelConfigurationSequence }) {}) {
                    return@configure
                }
                val (ipv4, ipv4Mask, ipv6, ipv6Prefixlen) = addresses
                try {
                    // Rust only notifies initial or changed IP configuration.
                    // Same-IP transport reconnects keep this TUN and its I/O.
                    val newInterface = createVpnInterface(ipv4, ipv4Mask, ipv6, ipv6Prefixlen, addrs, dnsList)
                    sessionGate.commit(
                        sessionToken,
                        newInterface,
                        condition = { sequence == tunnelConfigurationSequence },
                        onCreated = {
                            // establish() supersedes the old Android TUN even
                            // when a newer IP update has already arrived.
                            vpnIoHandler?.stop()
                            vpnIoHandler = null
                            try {
                                vpnInterface?.close()
                            } catch (error: Exception) {
                                Log.w(TAG, "Could not close previous TUN", error)
                            }
                            vpnInterface = null
                        }
                    ) { iface ->
                        vpnInterface = iface
                        vpnIoHandler = VpnIoHandler(scope = scope, serviceRunning = serviceRunning,
                            mtu = tunnelMtu, logTag = TAG,
                            onUplinkPacket = { packet -> edge?.writeData(packet) })
                        vpnIoHandler?.setVpnInterface(iface)
                        saveVpnState(true, ipv4, ipv6)
                        serviceRunning.set(true)
                        connectJob = null
                        vpnIoHandler?.startReadingAndWriting()
                        connectedEvent = VpnStatusEvent.Connected(ipv4, ipv6)
                        lastCoreConnected = null
                        startTrafficStats(sessionToken)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    sessionGate.updateIf(sessionToken, { sequence == tunnelConfigurationSequence }) {
                        Log.e(TAG, "Failed to configure VPN interface", error)
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
        connectedEvent = null
        lastCoreConnected = null
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
                    notifyNetworkChanged("onAvailable network=$network")
                }

                override fun onLost(network: Network) {
                    trace("NETWORK_LOST network=$network")
                    Log.d(TAG, "Network lost: $network")
                    if (isVpnNetwork(network)) {
                        Log.d(TAG, "Ignoring our own VPN network loss")
                        return
                    }
                    lastUnderlyingTransport = null
                    notifyNetworkChanged("onLost network=$network")
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
                    if (previous != null && previous != transport) {
                        Log.i(
                            TAG,
                            "Underlying transport changed $previous -> $transport, scheduling reconnect"
                        )
                        notifyNetworkChanged("onCapabilitiesChanged network=$network transport=$previous->$transport")
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
    }

    /** Report OS path changes even before the first TUN exists; Rust owns retries. */
    private fun notifyNetworkChanged(source: String) {
        trace("NETWORK_CHANGED source=$source")
        val currentEdge = edge ?: return
        scope.launch {
            try {
                if (edge === currentEdge) currentEdge.reconnect()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: VpnException) {
                Log.w(TAG, "Could not notify Rust of network change", error)
            }
        }
    }

    private fun showConnected(event: VpnStatusEvent.Connected) {
        trace("SHOW_CONNECTED")
        notificationManager.updateNotification(getString(R.string.notification_connected, event.ipv4))
        emitVpnEvent(event)
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
                        sessionGate.update(sessionToken) {
                            val connected = e.isConnected()
                            if (lastCoreConnected != connected) {
                                lastCoreConnected = connected
                                if (connected) {
                                    connectedEvent?.let { showConnected(it) }
                                } else {
                                    notificationManager.updateNotification(getString(R.string.notification_connecting))
                                    emitVpnEvent(VpnStatusEvent.Reconnecting)
                                }
                            }
                        }

                        emitVpnEvent(
                            VpnStatusEvent.TrafficStats(
                                stats.bytesSent,
                                stats.bytesReceived,
                                stats.sendSpeed,
                                stats.receiveSpeed,
                                stats.packetsSent,
                                stats.packetsReceived
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
                    if (ioOk == false) {
                        // A broken platform TUN cannot be repaired by reconnecting UDP.
                        emitVpnEvent(VpnStatusEvent.Error("TUN interface unavailable"))
                        handleDisconnect()
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
