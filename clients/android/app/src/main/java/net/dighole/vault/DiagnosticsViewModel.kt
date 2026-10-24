// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.Context
import android.net.ConnectivityManager
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import net.dighole.vault.data.readVaultConfig

internal data class DiagnosticsState(
    val running: Boolean = false,
    val startedAt: Long = 0,
    val elapsedMs: Long = 0,
    val header: Int = R.string.checks_intro,
    val results: List<ProbeResult> = emptyList()
)

internal class DiagnosticsViewModel : ViewModel() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val mutableState = MutableStateFlow(DiagnosticsState())
    val state = mutableState.asStateFlow()
    private var job: Job? = null

    fun cancel() { job?.cancel() }

    override fun onCleared() { scope.cancel() }

    fun run(context: Context) {
        if (job?.isActive == true) return
        val app = context.applicationContext
        mutableState.value = DiagnosticsState(running = true,
            startedAt = android.os.SystemClock.elapsedRealtime(), header = R.string.checking)
        job = scope.launch {
            try {
                val manager = app.getSystemService(ConnectivityManager::class.java)
                val network = ConnectionDiagnostics.vpnNetwork(manager) ?: error("No VPN network")
                val config = app.readVaultConfig()
                val domains = config.probeDomains.ifBlank { "www.google.com,github.com,t.co" }
                    .split(',').map { it.trim() }.distinct()
                ConnectionDiagnostics.run(manager, network, domains) { result ->
                    mutableState.value = mutableState.value.let { it.copy(results = it.results + result) }
                }
                mutableState.value = mutableState.value.let { state ->
                    state.copy(header = if (state.results.filter { it.stage < 7 }.all { it.passed })
                        R.string.checks_passed else R.string.checks_failed)
                }
            } catch (cancelled: CancellationException) {
                mutableState.value = mutableState.value.copy(header = R.string.checks_incomplete)
                throw cancelled
            } catch (_: Exception) {
                mutableState.value = mutableState.value.copy(header = R.string.checks_incomplete)
            } finally {
                mutableState.value = mutableState.value.let {
                    it.copy(running = false, elapsedMs = android.os.SystemClock.elapsedRealtime() - it.startedAt)
                }
            }
        }
    }
}
