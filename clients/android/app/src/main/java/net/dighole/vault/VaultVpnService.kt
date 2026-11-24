// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
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
import net.dighole.vaultcore.PeerId
import net.dighole.vaultcore.uniffi.EdgeSettings
import net.dighole.vaultcore.uniffi.MobileRoutes
import net.dighole.vaultcore.uniffi.MobileTransport
import net.dighole.vaultcore.uniffi.RustTunnelSetup
import net.dighole.vaultcore.uniffi.TunnelAssignment
import net.dighole.vaultcore.uniffi.VpnException
import net.dighole.vaultcore.uniffi.setFdBlocking
import net.dighole.vaultcore.uniffi.validateEdgeSettings
import java.io.File
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

@SuppressLint("VpnServicePolicy")
class VaultVpnService : VpnService() {

    companion object {
        const val TAG = "VaultVpnService"
        val VPN_MTU: Int get() = TunnelPolicy.mtuMax

        const val ACTION_CONNECT = "net.dighole.vault.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "net.dighole.vault.ACTION_DISCONNECT"

        const val EXTRA_ID = "id"
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
    private val serviceRunning = AtomicBoolean(false)
    private val sessionGate = SessionGate()
    private var tunnelConfigurationSequence = 0L // Protected by sessionGate.
    private var serviceJob = SupervisorJob()
    private var scope = CoroutineScope(Dispatchers.IO + serviceJob)
    private var serverHost: String = ""
    private var dnsIpv4List: List<String> = emptyList()
    private var dnsIpv6List: List<String> = emptyList()

    private var tunnelMtu: Int = VPN_MTU
    private var mtuCap: Int? = null
    private val physicalNetworks = PhysicalNetworks(::notifyNetworkChanged)

    private var connectedEvent: VpnStatusEvent.Connected? = null
    private var lastCoreConnected: Boolean? = null
    private var trafficStatsJob: Job? = null
    private var connectJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private fun trace(event: String) {
        VaultFileLogger.event(TAG, "service=${System.identityHashCode(this)} " +
            "running=${serviceRunning.get()} " +
            "tunValid=${vpnIoHandler?.hasValidInterface} $event")
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

    override fun onRevoke() {
        mainExecutor.execute {
            super.onRevoke()
            Log.d(TAG, "onRevoke called by system")
            handleDisconnect()
        }
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

        closeTunnelIo()

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

        emitVpnEvent(VpnStatusEvent.Connecting)
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
                val validated = validateEdgeSettings(EdgeSettings(
                    host = config.host,
                    port = config.port.toString(),
                    password = config.password,
                    dnsIpv4 = config.dnsIpv4,
                    dnsIpv6 = config.dnsIpv6,
                    mtu = config.mtu,
                    probeDomains = config.probeDomains
                ))
                if (!sessionGate.update(sessionToken) {
                    mtuCap = validated.mtuCap?.toInt()
                    serverHost = validated.host
                    dnsIpv4List = validated.dnsIpv4
                    dnsIpv6List = validated.dnsIpv6
                    (application as VaultApplication).diagnosticDomains = validated.probeDomains
                }) return@launch

                createAndStartEdge(validated.password, validated.host, validated.port.toInt(), id, sessionToken)

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
        val edgeConfig = EdgeConfig(password, listOf(host), port)

        val newEdge = Edge(
            config = edgeConfig,
            id = PeerId(id),
            onPackets = { packets ->
                sessionGate.update(sessionToken) {
                    vpnIoHandler?.enqueueDownlink(packets)
                }
            },
            onIpAssigned = { _, setup -> setup.complete("Missing physical network route configuration") },
            resolveTransport = { resolveTransport(host) },
            onTransportAssigned = { assignment, routes, setup ->
                handleEdgeIpAssigned(assignment, setup, routes, sessionToken)
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

    private fun resolveTransport(host: String): MobileTransport? {
        val selected = physicalNetworks.selected ?: return null
        val candidates = try {
            if (InetAddresses.isNumericAddress(host)) {
                listOf(InetAddresses.parseNumericAddress(host))
            } else {
                selected.network.getAllByName(host).toList()
            }
        } catch (error: java.net.UnknownHostException) {
            Log.w(TAG, "Supernode resolution failed on physical network", error)
            return null
        }
        val addresses = candidates.mapNotNull(InetAddress::getHostAddress).distinct()
        if (physicalNetworks.selected != selected || addresses.isEmpty()) return null
        val gateway = if (selected.canMapPorts) {
            selected.link.defaults.firstNotNullOfOrNull { route ->
                (route.gateway as? java.net.Inet4Address)?.takeUnless { it.isAnyLocalAddress }?.hostAddress
            }
        } else null
        val lanAddresses = if (selected.canMapPorts) {
            selected.link.addresses.mapNotNull { link ->
                link.address.hostAddress?.let { "$it/${link.prefixLength}" }
            }
        } else emptyList()
        return MobileTransport(
            addresses, selected.network.networkHandle.toULong(), selected.generation, gateway, lanAddresses
        )
    }

    // Native/Android setup failures must be reported only to the current session.
    @Suppress("TooGenericExceptionCaught")
    private fun handleEdgeIpAssigned(
        assignment: TunnelAssignment,
        setup: RustTunnelSetup,
        routes: MobileRoutes,
        sessionToken: Long
    ) {
        trace("IP_ASSIGNED_CALLBACK")
        val selected = physicalNetworks.selected
        if (selected == null || selected.generation != routes.generation) {
            setup.complete("Physical network changed")
            return
        }
        val appliedMtu = TunnelPolicy.mtu(selected.link.mtu ?: readLinkMtu(selected.link.name), mtuCap)
        var sequence = 0L
        if (!sessionGate.updateIf(sessionToken, setup::isPending) {
            tunnelConfigurationSequence++
            sequence = tunnelConfigurationSequence
        }) {
            setup.complete("VPN session ended")
            return
        }
        val currentSetup = {
            sequence == tunnelConfigurationSequence &&
                physicalNetworks.selected == selected && setup.isPending()
        }
        scope.launch {
            sessionGate.configure {
                if (!sessionGate.updateIf(sessionToken, currentSetup) {}) {
                    return@configure
                }
                try {
                    val newInterface = createVpnInterface(assignment, routes.addresses, selected.network, appliedMtu)
                    sessionGate.commit(
                        sessionToken,
                        newInterface,
                        condition = currentSetup,
                        onCreated = {
                            // establish() supersedes the old Android TUN even
                            // when a newer IP update has already arrived.
                            closeTunnelIo()
                        }
                    ) { iface ->
                        tunnelMtu = appliedMtu
                        edge?.setPeerMtu(appliedMtu)
                        vpnIoHandler = createTunnelIo(iface)
                        if (!setup.complete(null)) {
                            closeTunnelIo()
                            return@commit
                        }
                        val ipv4 = assignment.ipv4?.address.orEmpty()
                        val ipv6 = assignment.ipv6?.address.orEmpty()
                        connectedEvent = VpnStatusEvent.Connected(ipv4, ipv6, "")
                        serviceRunning.set(true)
                        connectJob = null
                        vpnIoHandler?.startReadingAndWriting()
                        lastCoreConnected = null
                        startTrafficStats(sessionToken)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    if (setup.complete(error.message ?: "VPN interface configuration failed")) {
                        Log.w(TAG, "Failed to configure VPN interface; Rust will retry", error)
                    }
                }
            }
        }.invokeOnCompletion {
            setup.complete("VPN interface configuration cancelled")
        }
    }

    /** Once committed, the I/O handler is the sole owner of its TUN descriptor. */
    private fun createTunnelIo(iface: ParcelFileDescriptor): VpnIoHandler = try {
        VpnIoHandler(scope = scope, serviceRunning = serviceRunning, mtu = tunnelMtu, logTag = TAG,
            onUplinkPacket = { packet -> edge?.writeData(packet) }).apply { setVpnInterface(iface) }
    } catch (_error: Exception) {
        // commit has transferred ownership; failed I/O setup must still release the new TUN.
        try { iface.close() } catch (_: Exception) { }
        throw _error
    }

    private fun closeTunnelIo() {
        val previous = vpnIoHandler
        vpnIoHandler = null
        previous?.stop()
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
        saveVpnState(false, "", "", "")

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

        closeTunnelIo()

        // Cancel scope after I/O resources are closed so coroutines exit cleanly
        try {
            scope.cancel()
        } catch (_: Exception) {
        }

        emitVpnEvent(VpnStatusEvent.Disconnected)
    }

    private fun registerNetworkCallback() {
        try {
            val cm = getSystemService(ConnectivityManager::class.java) ?: return
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(network: Network) = physicalNetworks.lost(network)

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                    physicalNetworks.capabilities(network, caps)

                override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) =
                    physicalNetworks.link(network, properties)
            }
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (error: SecurityException) {
            Log.e(TAG, "Failed to register physical network callback", error)
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

    /** Invalidate the active transport before requesting another connection attempt. */
    private fun notifyNetworkChanged() {
        val currentEdge = edge ?: return
        try {
            currentEdge.reconnect()
        } catch (error: VpnException) {
            Log.w(TAG, "Could not notify Rust of network change", error)
        }
        if (serviceRunning.get()) {
            val underlying = physicalNetworks.selected?.let { arrayOf(it.network) }
            setUnderlyingNetworks(underlying ?: emptyArray())
        }
    }

    private fun showConnected(event: VpnStatusEvent.Connected) {
        trace("SHOW_CONNECTED")
        notificationManager.updateNotification(getString(R.string.notification_connected, event.ipv4.ifBlank { event.ipv6 }))
        emitVpnEvent(event)
    }

    private fun saveVpnState(connected: Boolean, ipv4: String, ipv6: String, publicIp: String) {
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().apply {
            putBoolean("vpn_connected", connected)
            putString("vpn_assigned_ipv4", ipv4)
            putString("vpn_assigned_ipv6", ipv6)
            putString("vpn_public_ip", publicIp)
            commit()
        }

        Log.d(TAG, "Saved VPN state: connected=$connected, ipv4=$ipv4, ipv6=$ipv6, publicIp=$publicIp")
    }

    private fun readLinkMtu(name: String?): Int? = try {
        name?.let { File("/sys/class/net/$it/mtu").readText().trim().toIntOrNull() }
    } catch (_: java.io.IOException) {
        null
    }

    private fun createVpnInterface(
        assignment: TunnelAssignment,
        addrs: List<String>,
        network: Network,
        mtu: Int
    ): ParcelFileDescriptor {
        try {
            val addresses = TunnelAddresses.from(assignment)
            val resolvers = addresses.dns(dnsIpv4List, dnsIpv6List)
            val builder = Builder()
                .setMtu(mtu)
                .setUnderlyingNetworks(arrayOf(network))
                .setSession(getString(R.string.vpn_service_name))
                .setConfigureIntent(
                    PendingIntent.getActivity(
                        this,
                        0,
                        Intent(this, MainActivity::class.java),
                        PendingIntent.FLAG_IMMUTABLE
                    )
                )

            addresses.ipv4?.let { builder.addAddress(it, requireNotNull(addresses.ipv4Prefix)) }
            addresses.ipv6?.let { builder.addAddress(it, requireNotNull(addresses.ipv6Prefix)) }
            resolvers.forEach { builder.addDnsServer(it) }
            if (addresses.ipv4 != null) builder.addRoute("0.0.0.0", 0)
            if (addresses.ipv6 != null) builder.addRoute("::", 0)

            // Exclude server IP from VPN routing (API 33+ only)
            try {
                for (candidate in addrs) {
                    val address = InetAddresses.parseNumericAddress(candidate)
                    val len = if (address.address.size == 4) 32 else 128
                    builder.excludeRoute(android.net.IpPrefix(address, len))
                    Log.d(TAG, "Excluded server IP from VPN: ${address.hostAddress}")
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
                            // Read status alongside the addresses committed by this session.
                            val status = e.getConnectionStatus()
                            val connected = status.connected
                            val publicIpChanged = connected && connectedEvent?.publicIp != status.publicIp
                            if (lastCoreConnected != connected || publicIpChanged) {
                                lastCoreConnected = connected
                                if (connected) {
                                    connectedEvent?.let { cached ->
                                        val event = cached.copy(publicIp = status.publicIp)
                                        connectedEvent = event
                                        saveVpnState(true, event.ipv4, event.ipv6, event.publicIp)
                                        showConnected(event)
                                    }
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
