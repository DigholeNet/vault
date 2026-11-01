// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import net.dighole.vaultcore.uniffi.DiagnosticProbe
import net.dighole.vaultcore.uniffi.DiagnosticOperation
import net.dighole.vaultcore.uniffi.DiagnosticStage
import net.dighole.vaultcore.uniffi.DiagnosticState
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.tabs.TabLayout
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.flow.collectLatest

class DiagnosticsFragment : Fragment() {
    private val model by lazy { androidx.lifecycle.ViewModelProvider(this)[DiagnosticsViewModel::class.java] }
    private var tab = 0
    private var logText = ""
    private var logUpdates: Job? = null
    private val logMutex = Mutex()
    private var clearingLogs = false
    private var logsRendered = false
    private val expanded = mutableSetOf<String>()
    private val labels = linkedMapOf(
        DiagnosticStage.DNS to R.string.check_dns, DiagnosticStage.TCP to R.string.check_tcp,
        DiagnosticStage.HTTPS to R.string.check_https, DiagnosticStage.DNS6 to R.string.check_dns6,
        DiagnosticStage.TCP6 to R.string.check_tcp6, DiagnosticStage.HTTPS6 to R.string.check_https6,
        DiagnosticStage.APPLICATION to R.string.check_app, DiagnosticStage.PING to R.string.check_ping,
        DiagnosticStage.PING6 to R.string.check_ping6
    )

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, state: Bundle?): View =
        inflater.inflate(R.layout.fragment_diagnostics, container, false)

    override fun onViewCreated(view: View, state: Bundle?) {
        tab = state?.getInt("tab") ?: tab
        view.findViewById<TabLayout>(R.id.diagnosticTabs).apply {
            addTab(newTab().setText(R.string.checks))
            addTab(newTab().setText(R.string.runtime_logs))
            selectTab(getTabAt(tab))
            addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
                override fun onTabSelected(selected: TabLayout.Tab) {
                    tab = selected.position; render(); updateLogUpdates()
                }
                override fun onTabUnselected(selected: TabLayout.Tab) = Unit
                override fun onTabReselected(selected: TabLayout.Tab) = Unit
            })
        }
        view.findViewById<MaterialButton>(R.id.btnRunChecks).setOnClickListener { runChecks() }
        view.findViewById<MaterialButton>(R.id.btnClearLogs).setOnClickListener { clearLogs() }
        view.findViewById<MaterialButton>(R.id.btnCopyLogs).setOnClickListener {
            requireContext().getSystemService(ClipboardManager::class.java)
                .setPrimaryClip(ClipData.newPlainText(getString(R.string.runtime_logs), logText))
        }
        viewLifecycleOwner.lifecycleScope.launch {
            (requireContext().applicationContext as VaultApplication).vpnStatusEvents.collect {
                if (it !is VpnStatusEvent.TrafficStats) {
                    if (!connected()) model.cancel()
                    render()
                }
            }
        }
        viewLifecycleOwner.lifecycleScope.launch { model.state.collect { render() } }
        viewLifecycleOwner.lifecycleScope.launch {
            model.state.collectLatest { state ->
                if (state.running) {
                    while (true) {
                        if (!isHidden && isResumed) view.findViewById<TextView>(R.id.tvDiagnosticElapsed).text =
                            getString(R.string.elapsed, android.os.SystemClock.elapsedRealtime() - state.startedAt)
                        kotlinx.coroutines.delay(100)
                    }
                }
            }
        }
        render()
        updateLogUpdates()
    }

    private fun connected(): Boolean =
        (requireContext().applicationContext as VaultApplication).currentVpnStatus is VpnStatusEvent.Connected

    private fun render() {
        val root = view ?: return
        val state = model.state.value
        val snapshot = state.snapshot
        root.findViewById<View>(R.id.checksPanel).visibility = if (tab == 0) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.logsPanel).visibility = if (tab == 1) View.VISIBLE else View.GONE
        root.findViewById<TextView>(R.id.tvDiagnosticSummary).setText(
            if (!state.running && snapshot == null && !connected()) R.string.checks_disconnected else state.header)
        root.findViewById<MaterialButton>(R.id.btnRunChecks).apply {
            isEnabled = connected() && !state.running
            setText(if (state.startedAt == 0L) R.string.run_checks else R.string.run_again)
        }
        root.findViewById<View>(R.id.diagnosticProgress).visibility = if (state.running) View.VISIBLE else View.GONE
        root.findViewById<TextView>(R.id.tvDiagnosticElapsed).apply {
            visibility = if (state.startedAt > 0) View.VISIBLE else View.GONE
            text = getString(R.string.elapsed, state.elapsedMs)
        }
        val rows = root.findViewById<LinearLayout>(R.id.diagnosticRows)
        rows.removeAllViews()
        labels.filter { snapshot == null || it.key in snapshot.plannedChecks }.forEach { (stage, label) ->
            val check = snapshot?.checks?.firstOrNull { it.stage == stage }
            val active = state.running && snapshot?.activeStage == stage && check == null
            val summary = when {
                active -> getString(R.string.checking)
                check == null || check.attempted == 0u -> getString(R.string.not_measured)
                else -> symbol(check.state) + " " + getString(R.string.probe_detail,
                    check.passed.toLong(), check.attempted.toLong(),
                    if (check.sampleCount > 0u) "${check.durationMs} ms" else "—")
            }
            val details = snapshot?.probes.orEmpty().filter { it.request.stage == stage }.joinToString("\n\n", transform = ::probeDetail)
            addRow(rows, stage.name, getString(label), summary, details)
        }
        snapshot?.domainStates?.forEach { domain ->
            val details = snapshot.probes.filter { it.request.domain == domain.domain }
                .joinToString("\n\n", transform = ::probeDetail)
            addRow(rows, domain.domain, domain.domain, symbol(domain.state), details)
        }
        root.findViewById<TextView>(R.id.tvDiagnosticDetails).apply {
            val details = (listOfNotNull(state.error) + snapshot?.routeIssues.orEmpty() + snapshot?.routeUnavailable.orEmpty())
                .joinToString("\n")
            text = details
            visibility = if (details.isEmpty()) View.GONE else View.VISIBLE
        }
    }

    private fun symbol(state: DiagnosticState): String = when (state) {
        DiagnosticState.PASSED -> "✓"
        DiagnosticState.FAILED -> "!"
        DiagnosticState.INCOMPLETE -> "—"
    }

    private fun addRow(rows: LinearLayout, key: String, title: String, summary: String, details: String) {
        val row = layoutInflater.inflate(R.layout.diagnostic_row, rows, false)
        row.findViewById<TextView>(R.id.checkTitle).text = title
        row.findViewById<TextView>(R.id.checkSummary).text = summary
        row.findViewById<TextView>(R.id.checkDetails).apply {
            text = details
            visibility = if (key in expanded) View.VISIBLE else View.GONE
        }
        row.setOnClickListener {
            if (key in expanded) expanded.remove(key) else expanded.add(key)
            row.findViewById<TextView>(R.id.checkDetails).visibility = if (key in expanded) View.VISIBLE else View.GONE
        }
        rows.addView(row)
    }

    private fun probeDetail(probe: DiagnosticProbe): String {
        val target = when (val operation = probe.request.operation) {
            is DiagnosticOperation.Dns -> "${operation.server}: "
            is DiagnosticOperation.Tcp -> "${operation.address}:${operation.port} · "
            is DiagnosticOperation.Https -> operation.address?.let { "$it:443 · " }.orEmpty()
            is DiagnosticOperation.Ping -> "${operation.address} seq=${operation.sequence} size=${operation.packetSize} · "
            DiagnosticOperation.Route -> ""
        }
        val tls = probe.tlsDurationMs?.let { "\nTLS $it ms" }.orEmpty()
        return "${probe.request.domain} · ${probe.durationMs} ms\n$target${probe.detail}$tls"
    }

    private fun runChecks() {
        if (connected()) model.run(requireContext())
    }

    /** Poll only while the log tab is visible; unchanged content never resets selection or scroll. */
    private fun updateLogUpdates() {
        val visible = view != null && isResumed && !isHidden && tab == 1 && !clearingLogs
        if (!visible) { logUpdates?.cancel(); logUpdates = null; return }
        if (logUpdates?.isActive == true) return
        logUpdates = viewLifecycleOwner.lifecycleScope.launch {
            while (isActive) {
                refreshLogs(false)
                delay(1000)
            }
        }
    }

    private suspend fun refreshLogs(clear: Boolean) = logMutex.withLock {
        try {
            val content = if (clear) VaultFileLogger.clearAndRead() else VaultFileLogger.readLogs()
            val root = view ?: return@withLock
            val text = root.findViewById<TextView>(R.id.tvLogs)
            if (!clear && text.selectionStart >= 0 && text.selectionEnd > text.selectionStart) return@withLock
            val scroll = root.findViewById<android.widget.ScrollView>(R.id.logScroll)
            val followTail = clear || !logsRendered || !scroll.canScrollVertically(1)
            val previousY = scroll.scrollY
            if (content != logText || !logsRendered) {
                logText = content
                text.text = content.ifEmpty { getString(R.string.no_logs) }
                logsRendered = true
                scroll.post {
                    if (followTail) scroll.fullScroll(View.FOCUS_DOWN) else scroll.scrollTo(0, previousY)
                }
            }
            root.findViewById<MaterialButton>(R.id.btnCopyLogs).isEnabled = content.isNotEmpty() && !clearingLogs
            root.findViewById<MaterialButton>(R.id.btnClearLogs).isEnabled = content.isNotEmpty() && !clearingLogs
        } catch (cancelled: CancellationException) { throw cancelled
        } catch (_: Exception) {
            logsRendered = false
            view?.findViewById<TextView>(R.id.tvLogs)?.setText(R.string.logs_failed)
            view?.findViewById<MaterialButton>(R.id.btnCopyLogs)?.isEnabled = false
        }
    }

    private fun clearLogs() {
        if (clearingLogs) return
        clearingLogs = true
        updateLogUpdates()
        view?.findViewById<MaterialButton>(R.id.btnCopyLogs)?.isEnabled = false
        view?.findViewById<MaterialButton>(R.id.btnClearLogs)?.isEnabled = false
        viewLifecycleOwner.lifecycleScope.launch {
            try { refreshLogs(true) } finally {
                clearingLogs = false
                view?.findViewById<MaterialButton>(R.id.btnClearLogs)?.isEnabled = logText.isNotEmpty() && logsRendered
                view?.findViewById<MaterialButton>(R.id.btnCopyLogs)?.isEnabled = logText.isNotEmpty() && logsRendered
                updateLogUpdates()
            }
        }
    }

    override fun onResume() { super.onResume(); updateLogUpdates() }
    override fun onPause() { logUpdates?.cancel(); logUpdates = null; super.onPause() }
    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        if (!hidden) render()
        updateLogUpdates()
    }
    override fun onDestroyView() {
        logUpdates?.cancel()
        logUpdates = null
        logsRendered = false
        super.onDestroyView()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt("tab", tab)
    }
}
