// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.SystemClock
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.dighole.vaultcore.uniffi.DiagnosticConfig
import net.dighole.vaultcore.uniffi.DiagnosticEngine
import net.dighole.vaultcore.uniffi.DiagnosticScope
import net.dighole.vaultcore.uniffi.DiagnosticSnapshot
import net.dighole.vaultcore.uniffi.DiagnosticState
import net.dighole.vaultcore.uniffi.DiagnosticTransport

internal data class DiagnosticsState(
    val running: Boolean = false,
    val startedAt: Long = 0,
    val elapsedMs: Long = 0,
    val header: Int = R.string.checks_intro,
    val snapshot: DiagnosticSnapshot? = null,
    val error: String? = null
)

/** Android supplies live VPN metadata and its Network handle; Rust runs every probe. */
internal class DiagnosticsViewModel : ViewModel() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val mutableState = MutableStateFlow(DiagnosticsState())
    val state = mutableState.asStateFlow()
    private var job: Job? = null
    private val lifetime = Any()
    private var engine: DiagnosticEngine? = null
    private var transport: DiagnosticTransport? = null

    fun cancel() {
        synchronized(lifetime) {
            engine?.cancel()
            transport?.cancel()
        }
        job?.cancel()
    }

    override fun onCleared() { cancel(); scope.cancel() }

    @Suppress("TooGenericExceptionCaught") // Keep platform/FFI failures out of the UI event loop.
    fun run(context: Context) {
        if (job?.isActive == true) return
        val app = context.applicationContext as VaultApplication
        mutableState.value = DiagnosticsState(running = true, startedAt = SystemClock.elapsedRealtime(), header = R.string.checking)
        job = scope.launch(start = CoroutineStart.LAZY) {
            val manager = app.getSystemService(ConnectivityManager::class.java)
            var callback: ConnectivityManager.NetworkCallback? = null
            var monitor: Job? = null
            try {
                val generation = app.vpnGeneration
                val connected = app.currentVpnStatus as? VpnStatusEvent.Connected ?: error("VPN disconnected")
                val network = vpnNetwork(manager, connected.ipv4) ?: error("Live VPN network unavailable")
                val properties = manager.getLinkProperties(network) ?: error("VPN properties unavailable")
                callback = watchNetwork(manager, network, properties)
                monitor = launch {
                    app.vpnStatusEvents.collect { event ->
                        if (event !is VpnStatusEvent.TrafficStats && app.vpnGeneration != generation) this@DiagnosticsViewModel.cancel()
                    }
                }
                runEngine(app, generation, network, properties, connected)
            } catch (cancelled: CancellationException) {
                mutableState.value = mutableState.value.copy(header = R.string.checks_incomplete)
                throw cancelled
            } catch (error: Exception) {
                mutableState.value = mutableState.value.copy(header = R.string.checks_incomplete, error = error.message)
            } finally {
                monitor?.cancel()
                callback?.let { manager.unregisterNetworkCallback(it) }
                mutableState.value = mutableState.value.let {
                    it.copy(running = false, elapsedMs = it.snapshot?.durationMs?.toLong()
                        ?: (SystemClock.elapsedRealtime() - it.startedAt))
                }
            }
        }
        job?.start()
    }

    private suspend fun runEngine(app: VaultApplication, generation: Long, network: Network,
        properties: LinkProperties, connected: VpnStatusEvent.Connected) =
        withContext(Dispatchers.IO) {
            val ipv4 = properties.linkAddresses.firstOrNull { it.address.hostAddress == connected.ipv4 }
                ?: error("Live tunnel IPv4 address unavailable")
            val core = DiagnosticEngine(DiagnosticConfig(
                sessionId = generation.toULong(), domains = app.diagnosticDomains,
                dnsServers = properties.dnsServers.mapNotNull { it.hostAddress },
                tunnelIpv4 = ipv4.address.hostAddress, tunnelIpv4Prefix = ipv4.prefixLength.toUByte(),
                tunnelIpv6 = connected.ipv6.ifBlank { null }, tunnelMtu = properties.mtu.toUShort()
            ))
            synchronized(lifetime) { engine = core }
            try {
                while (true) {
                    ensureActive()
                    check(app.vpnGeneration == generation) { "VPN session changed" }
                    val request = core.nextRequest() ?: break
                    mutableState.value = mutableState.value.copy(snapshot = core.snapshot())
                    val now = core.elapsedMs()
                    if (request.deadlineMs <= now) continue
                    val io = if (request.scope == DiagnosticScope.TUNNEL) {
                        DiagnosticTransport.forNetwork(network.networkHandle.toULong())
                    } else DiagnosticTransport(null)
                    synchronized(lifetime) { transport = io }
                    try {
                        ensureActive()
                        val response = io.execute(request.operation, request.domain, request.deadlineMs - now)
                        ensureActive()
                        check(app.vpnGeneration == generation) { "VPN session changed" }
                        core.complete(request.id, response)
                        core.snapshot().probes.lastOrNull()?.let {
                            VaultFileLogger.event("Diagnostics", "[probe] ${it.request.stage} ${it.request.domain}: ${it.detail}")
                        }
                    } finally {
                        synchronized(lifetime) { transport = null; io.close() }
                    }
                }
                val result = core.snapshot()
                mutableState.value = mutableState.value.copy(snapshot = result, header = when (result.state) {
                    DiagnosticState.PASSED -> R.string.checks_passed
                    DiagnosticState.FAILED -> R.string.checks_failed
                    DiagnosticState.INCOMPLETE -> R.string.checks_incomplete
                })
            } finally {
                synchronized(lifetime) {
                    core.cancel()
                    mutableState.value = mutableState.value.copy(snapshot = core.snapshot())
                    engine = null
                    core.close()
                }
            }
        }

    private fun watchNetwork(manager: ConnectivityManager, network: Network, initial: LinkProperties): ConnectivityManager.NetworkCallback {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(lost: Network) { if (lost == network) cancel() }
            override fun onLinkPropertiesChanged(changed: Network, properties: LinkProperties) {
                if (changed == network && (properties.linkAddresses != initial.linkAddresses ||
                    properties.dnsServers != initial.dnsServers || properties.mtu != initial.mtu)) cancel()
            }
        }
        manager.registerNetworkCallback(NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
        return callback
    }

    @Suppress("DEPRECATION")
    private fun vpnNetwork(manager: ConnectivityManager, ipv4: String): Network? = manager.allNetworks.firstOrNull { network ->
        manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
            manager.getLinkProperties(network)?.linkAddresses?.any { it.address.hostAddress == ipv4 } == true
    }
}
