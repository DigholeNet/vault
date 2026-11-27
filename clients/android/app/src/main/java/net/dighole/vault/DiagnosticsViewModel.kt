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
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.dighole.vault.data.parseConfigList
import net.dighole.vault.data.readProbeDomains
import net.dighole.vaultcore.uniffi.DiagnosticConfig
import net.dighole.vaultcore.uniffi.DiagnosticEngine
import net.dighole.vaultcore.uniffi.DiagnosticScope
import net.dighole.vaultcore.uniffi.DiagnosticSnapshot
import net.dighole.vaultcore.uniffi.DiagnosticState
import net.dighole.vaultcore.uniffi.DiagnosticTransport
import java.net.InetAddress

internal data class DiagnosticsState(
    val running: Boolean = false,
    val cancellationRequested: Boolean = false,
    val startedAt: Long = 0,
    val elapsedMs: Long = 0,
    val header: Int = R.string.checks_intro,
    val snapshot: DiagnosticSnapshot? = null,
    val error: String? = null
) {
    val cancelling: Boolean get() = running && cancellationRequested
    val cancelled: Boolean get() = !running && cancellationRequested
}

/** Android supplies live VPN metadata and its Network handle; Rust runs every probe. */
internal class DiagnosticsViewModel : ViewModel() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val mutableState = MutableStateFlow(DiagnosticsState())
    val state = mutableState.asStateFlow()
    private var job: Job? = null
    private val lifetime = Any()
    private var engine: DiagnosticEngine? = null
    private var transport: DiagnosticTransport? = null

    fun requestCancellation() {
        val state = mutableState.value
        if (!state.running || state.cancellationRequested) return
        mutableState.update { it.copy(cancellationRequested = true) }
        cancel()
    }

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
        if (mutableState.value.running) return
        val app = context.applicationContext as VaultApplication
        mutableState.value = DiagnosticsState(running = true, startedAt = SystemClock.elapsedRealtime(), header = R.string.checking)
        job = scope.launch(start = CoroutineStart.LAZY) {
            val manager = app.getSystemService(ConnectivityManager::class.java)
            var callback: ConnectivityManager.NetworkCallback? = null
            var monitor: Job? = null
            try {
                val generation = app.vpnGeneration
                val connected = app.currentVpnStatus as? VpnStatusEvent.Connected
                monitor = launch {
                    app.vpnStatusEvents.collect { event ->
                        if (event !is VpnStatusEvent.TrafficStats && app.vpnGeneration != generation) this@DiagnosticsViewModel.cancel()
                    }
                }
                if (connected == null) {
                    runEngine(app, generation, DiagnosticConfig(
                        sessionId = generation.toULong(), domains = parseConfigList(app.readProbeDomains()),
                        dnsServers = emptyList(), tunnelIpv4 = null, tunnelIpv4Prefix = null,
                        tunnelIpv6 = null, tunnelMtu = 1427.toUShort()
                    ), null)
                } else {
                    val network = vpnNetwork(manager, connected) ?: error("Live VPN network unavailable")
                    val properties = manager.getLinkProperties(network) ?: error("VPN properties unavailable")
                    callback = watchNetwork(manager, network, properties)
                    runEngine(app, generation, tunnelConfig(app, generation, properties, connected), network)
                }
            } catch (cancelled: CancellationException) {
                mutableState.update { it.copy(header = R.string.checks_incomplete) }
                throw cancelled
            } catch (error: Exception) {
                mutableState.update { it.copy(header = R.string.checks_incomplete, error = error.message) }
            } finally {
                monitor?.cancel()
                callback?.let { manager.unregisterNetworkCallback(it) }
                mutableState.update {
                    it.copy(
                        running = false,
                        header = if (it.cancellationRequested) R.string.checks_cancelled else it.header,
                        elapsedMs = it.snapshot?.durationMs?.toLong() ?: (SystemClock.elapsedRealtime() - it.startedAt),
                        error = if (it.cancellationRequested) null else it.error
                    )
                }
            }
        }
        job?.start()
    }

    private suspend fun tunnelConfig(
        app: VaultApplication, generation: Long, properties: LinkProperties, connected: VpnStatusEvent.Connected
    ): DiagnosticConfig {
        val assigned = assignedAddresses(connected)
        val live = properties.linkAddresses.filter { it.address in assigned }
        check(live.map { it.address }.toSet() == assigned.toSet()) { "Live tunnel addresses unavailable" }
        val ipv4 = live.firstOrNull { it.address is java.net.Inet4Address }
        val ipv6 = live.firstOrNull { it.address is java.net.Inet6Address }
        return DiagnosticConfig(
            sessionId = generation.toULong(), domains = parseConfigList(app.readProbeDomains()),
            dnsServers = properties.dnsServers.mapNotNull { it.hostAddress },
            tunnelIpv4 = ipv4?.address?.hostAddress, tunnelIpv4Prefix = ipv4?.prefixLength?.toUByte(),
            tunnelIpv6 = ipv6?.address?.hostAddress, tunnelMtu = properties.mtu.toUShort()
        )
    }

    private suspend fun runEngine(
        app: VaultApplication, generation: Long, config: DiagnosticConfig, network: Network?
    ) = withContext(Dispatchers.IO) {
        val core = DiagnosticEngine(config)
        synchronized(lifetime) { engine = core }
        try {
            while (true) {
                ensureActive()
                check(app.vpnGeneration == generation) { "VPN session changed" }
                val request = core.nextRequest() ?: break
                val progress = core.snapshot()
                mutableState.update { if (it.cancelling) it else it.copy(snapshot = progress) }
                val now = core.elapsedMs()
                if (request.deadlineMs <= now) continue
                val io = if (request.scope == DiagnosticScope.TUNNEL) {
                    DiagnosticTransport.forNetwork(checkNotNull(network).networkHandle.toULong())
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
            val header = when (result.state) {
                DiagnosticState.PASSED -> R.string.checks_passed
                DiagnosticState.FAILED -> R.string.checks_failed
                DiagnosticState.INCOMPLETE -> R.string.checks_incomplete
            }
            mutableState.update { it.copy(snapshot = result, header = header) }
        } finally {
            synchronized(lifetime) {
                core.cancel()
                val finalSnapshot = core.snapshot()
                mutableState.update { it.copy(snapshot = finalSnapshot) }
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
    private fun vpnNetwork(manager: ConnectivityManager, connected: VpnStatusEvent.Connected): Network? {
        val assigned = assignedAddresses(connected)
        return manager.allNetworks.firstOrNull { network ->
            manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                manager.getLinkProperties(network)?.linkAddresses?.map { it.address }?.containsAll(assigned) == true
        }
    }

    private fun assignedAddresses(connected: VpnStatusEvent.Connected): List<InetAddress> =
        listOf(connected.ipv4, connected.ipv6).filter { it.isNotEmpty() }.map {
            check(SettingsValidation.address(it)) { "Invalid assigned address" }
            InetAddress.getByName(it)
        }.also { check(it.isNotEmpty()) { "No tunnel address assigned" } }
}
