// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import kotlin.math.roundToInt
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.core.view.doOnPreDraw
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.progressindicator.LinearProgressIndicator
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.dighole.vault.data.readProbeDomains
import net.dighole.vault.data.writeProbeDomains
import net.dighole.vaultcore.uniffi.DiagnosticProbe
import net.dighole.vaultcore.uniffi.DiagnosticOperation
import net.dighole.vaultcore.uniffi.DiagnosticStage
import net.dighole.vaultcore.uniffi.DiagnosticState

class DiagnosticsFragment : Fragment() {
    private val model by lazy { androidx.lifecycle.ViewModelProvider(this)[DiagnosticsViewModel::class.java] }
    private var tab = 0
    private var logText = ""
    private var logUpdates: Job? = null
    private var logCopyFeedback: Job? = null
    private val logMutex = Mutex()
    private var clearingLogs = false
    private var logsRendered = false
    private var storedProbeDomains: String? = null
    private var savingProbeDomains = false
    private var loadingProbeDomains = false
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
        val tabViews = listOf(
            view.findViewById<TextView>(R.id.tabChecks),
            view.findViewById<TextView>(R.id.tabRuntimeLogs)
        )
        fun selectDiagnosticTab(index: Int) {
            if (index != tab) (activity as? MainActivity)?.dismissInputKeyboard()
            tab = index
            tabViews.forEachIndexed { position, textView ->
                val selected = position == tab
                textView.isSelected = selected
                textView.setTextColor(textView.context.getColor(
                    if (selected) R.color.vault_blue else R.color.vault_text_secondary
                ))
                textView.setTypeface(Typeface.create("sans-serif", if (selected) Typeface.BOLD else Typeface.NORMAL))
            }
            render()
            updateLogUpdates()
        }
        tabViews.forEachIndexed { index, textView ->
            textView.setOnClickListener { selectDiagnosticTab(index) }
        }
        selectDiagnosticTab(tab.coerceIn(0, tabViews.lastIndex))
        bindProbeDomains(view, state)
        view.findViewById<MaterialButton>(R.id.btnRunChecks).setOnClickListener {
            if (model.state.value.running) model.requestCancellation() else runChecks()
        }
        view.findViewById<MaterialButton>(R.id.btnClearLogs).setOnClickListener { confirmClearLogs() }
        view.findViewById<MaterialButton>(R.id.btnCopyLogs).setOnClickListener { copyLogs() }
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
                if (state.running && !state.cancelling) {
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

    private fun bindProbeDomains(view: View, state: Bundle?) {
        val field = view.findViewById<EditText>(R.id.edtDiagnosticDomains)
        (activity as? MainActivity)?.dismissKeyboardOnDone(field)
        view.findViewById<View>(R.id.probeDomainsField).setOnClickListener {
            if (field.isEnabled && field.requestFocus()) {
                field.context.getSystemService(InputMethodManager::class.java)
                    .showSoftInput(field, InputMethodManager.SHOW_IMPLICIT)
            }
        }
        field.doAfterTextChanged {
            if (!loadingProbeDomains) {
                view.findViewById<TextView>(R.id.tvProbeStatus).visibility = View.GONE
                updateProbeValidation()
            }
        }
        view.findViewById<MaterialButton>(R.id.btnSaveProbeDomains).setOnClickListener { saveProbeDomains() }
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val stored = requireContext().readProbeDomains()
                storedProbeDomains = stored
                setProbeDraft(state?.getString("probeDraft") ?: stored)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                showProbeStatus(R.string.config_load_failed)
            } finally {
                updateProbeValidation()
            }
        }
    }

    private fun setProbeDraft(value: String) {
        loadingProbeDomains = true
        view?.findViewById<EditText>(R.id.edtDiagnosticDomains)?.setText(value)
        loadingProbeDomains = false
    }

    private fun updateProbeValidation() {
        val root = view ?: return
        val value = root.findViewById<EditText>(R.id.edtDiagnosticDomains).text.toString()
        val valid = SettingsValidation.domains(value.trim())
        val stored = storedProbeDomains
        root.findViewById<EditText>(R.id.edtDiagnosticDomains).isEnabled = stored != null && !savingProbeDomains
        root.findViewById<TextView>(R.id.tvProbeHelp).apply {
            setText(if (valid) R.string.probe_help else R.string.error_probe)
            setTextColor(context.getColor(if (valid) R.color.vault_text_secondary else R.color.vault_danger))
        }
        val outline = if (valid) R.color.vault_diagnostic_field_outline else R.color.vault_danger
        val field = root.findViewById<View>(R.id.probeDomainsField)
        (field.background.mutate() as GradientDrawable).setStroke(
            resources.displayMetrics.density.roundToInt().coerceAtLeast(1), root.context.getColor(outline)
        )
        root.findViewById<MaterialButton>(R.id.btnSaveProbeDomains).isEnabled =
            stored != null && !savingProbeDomains && valid && value.trim() != stored
    }

    private fun saveProbeDomains() {
        val root = view ?: return
        val value = root.findViewById<EditText>(R.id.edtDiagnosticDomains).text.toString().trim()
        if (!SettingsValidation.domains(value) || savingProbeDomains) return
        (activity as? MainActivity)?.dismissInputKeyboard()
        savingProbeDomains = true
        updateProbeValidation()
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                requireContext().writeProbeDomains(value)
                storedProbeDomains = value
                setProbeDraft(value)
                showProbeStatus(R.string.probe_saved)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                showProbeStatus(R.string.config_save_failed)
            } finally {
                savingProbeDomains = false
                updateProbeValidation()
            }
        }
    }

    private fun showProbeStatus(message: Int) {
        view?.findViewById<TextView>(R.id.tvProbeStatus)?.apply {
            setText(message)
            visibility = View.VISIBLE
        }
    }

    private fun connected(): Boolean =
        (requireContext().applicationContext as VaultApplication).currentVpnStatus is VpnStatusEvent.Connected

    private fun render() {
        val root = view ?: return
        val state = model.state.value
        val snapshot = state.snapshot
        root.findViewById<View>(R.id.checksPanel).visibility = if (tab == 0) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.logsPanel).visibility = if (tab == 1) View.VISIBLE else View.GONE
        renderSummary(root, state, connected())
        renderRows(root, state)
        root.findViewById<View>(R.id.tvDiagnosticPingNote).visibility =
            if (snapshot == null) View.GONE else View.VISIBLE
        root.findViewById<TextView>(R.id.tvDiagnosticDetails).apply {
            val details = (listOfNotNull(state.error) + snapshot?.routeIssues.orEmpty() + snapshot?.routeUnavailable.orEmpty())
                .joinToString("\n")
            text = details
            visibility = if (details.isEmpty()) View.GONE else View.VISIBLE
        }
    }

    private fun renderSummary(root: View, state: DiagnosticsState, connected: Boolean) {
        val idle = state.startedAt == 0L
        val passed = !state.cancellationRequested && state.header == R.string.checks_passed
        val hasIssue = !idle && !state.running && !state.cancelled && !passed
        val failed = hasIssue && state.header == R.string.checks_failed
        val tint = when {
            idle || state.cancellationRequested -> R.color.vault_text_secondary
            failed -> R.color.vault_danger
            hasIssue -> R.color.vault_diagnostic_warning
            else -> R.color.vault_blue_dark
        }
        val surface = when {
            idle -> R.color.vault_surface_subtle
            failed -> R.color.vault_failure_surface
            hasIssue -> R.color.vault_diagnostic_warning_surface
            else -> R.color.vault_surface
        }
        root.findViewById<MaterialCardView>(R.id.diagnosticSummaryCard).apply {
            visibility = if (idle && connected) View.GONE else View.VISIBLE
            setCardBackgroundColor(context.getColor(surface))
        }
        root.findViewById<TextView>(R.id.tvDiagnosticSummary).apply {
            setText(when {
                idle -> R.string.diagnostic_offline_title
                state.cancelling -> R.string.checks_cancelling
                state.cancelled -> R.string.checks_cancelled
                else -> state.header
            })
            setTextColor(context.getColor(if (passed) R.color.vault_text else tint))
        }
        root.findViewById<View>(R.id.diagnosticSummarySpinner).visibility =
            if (state.running) View.VISIBLE else View.GONE
        root.findViewById<ImageView>(R.id.diagnosticSummaryIcon).apply {
            visibility = if (state.running) View.INVISIBLE else View.VISIBLE
            setImageResource(when {
                passed -> R.drawable.ic_check
                hasIssue -> R.drawable.ic_error
                else -> R.drawable.ic_info
            })
            val iconTint = when {
                idle || state.cancelled -> R.color.vault_text_secondary
                passed -> R.color.vault_blue
                else -> tint
            }
            imageTintList = ColorStateList.valueOf(context.getColor(iconTint))
        }
        bindSummaryProgress(root, state, idle, tint.takeIf { hasIssue })
        renderRunButton(root, state, idle, connected)
    }

    private fun renderRunButton(root: View, state: DiagnosticsState, idle: Boolean, connected: Boolean) {
        root.findViewById<MaterialButton>(R.id.btnRunChecks).apply {
            isEnabled = !state.cancelling
            val surfaceColor = when {
                state.cancelling -> R.color.vault_surface_muted
                state.running -> R.color.vault_indigo_soft
                else -> R.color.vault_blue
            }
            val contentColor = when {
                state.cancelling -> R.color.vault_text_secondary
                state.running -> R.color.vault_blue_dark
                else -> R.color.vault_on_primary
            }
            backgroundTintList = ColorStateList.valueOf(context.getColor(surfaceColor))
            setIconResource(if (state.running) 0 else R.drawable.ic_diagnostics)
            iconTint = ColorStateList.valueOf(context.getColor(contentColor))
            setTextColor(context.getColor(contentColor))
            setText(when {
                state.cancelling -> R.string.checks_cancelling
                state.running -> R.string.cancel_checks
                !idle -> R.string.run_again
                connected -> R.string.run_checks
                else -> R.string.diagnostic_start_direct
            })
        }
    }

    private fun bindSummaryProgress(root: View, state: DiagnosticsState, idle: Boolean, issueTint: Int?) {
        val snapshot = state.snapshot
        val count = snapshot?.plannedChecks?.size ?: 0
        val textColor = issueTint ?: when {
            state.running -> R.color.vault_blue
            else -> R.color.vault_text_secondary
        }
        root.findViewById<TextView>(R.id.tvDiagnosticElapsed).apply {
            text = when {
                idle -> getString(R.string.diagnostic_offline_detail)
                state.cancelling -> ""
                state.cancelled -> getString(R.string.checks_cancelled_detail)
                state.running -> getString(R.string.elapsed, android.os.SystemClock.elapsedRealtime() - state.startedAt)
                snapshot == null -> ""
                issueTint != null -> getString(R.string.diagnostic_summary_partial,
                    snapshot.checks.count { it.state == DiagnosticState.PASSED }, count,
                    snapshot.checks.count { it.state == DiagnosticState.FAILED })
                else -> getString(R.string.diagnostic_summary_success, count, state.elapsedMs / 1000.0)
            }
            visibility = if (text.isEmpty()) View.GONE else View.VISIBLE
            setTextColor(context.getColor(textColor))
        }
        root.findViewById<LinearProgressIndicator>(R.id.diagnosticProgress).apply {
            visibility = if (state.running && !state.cancelling && count > 0) View.VISIBLE else View.GONE
            max = count.coerceAtLeast(1)
            progress = snapshot?.checks?.size ?: 0
        }
    }

    private data class ResultRow(
        val key: String,
        val title: String,
        val summary: String,
        val state: DiagnosticState?,
        val probes: List<DiagnosticProbe>
    )

    private fun renderRows(root: View, state: DiagnosticsState) {
        val rows = root.findViewById<LinearLayout>(R.id.diagnosticRows)
        rows.removeAllViews()
        val snapshot = state.snapshot ?: return
        val probesByStage = snapshot.probes.groupBy { it.request.stage }
        labels.filter { it.key in snapshot.plannedChecks }.forEach { (stage, label) ->
            val check = snapshot.checks.firstOrNull { it.stage == stage }
            val summary = when {
                state.running && !state.cancelling && snapshot.activeStage == stage && check == null -> getString(R.string.checking)
                check == null || check.attempted == 0u -> getString(R.string.not_measured)
                else -> getString(R.string.probe_detail, check.passed.toLong(), check.attempted.toLong(),
                    if (check.sampleCount > 0u) "${check.durationMs} ms" else "—")
            }
            addRow(rows, ResultRow(stage.name, getString(label), summary, check?.state, probesByStage[stage].orEmpty()))
        }
        if (!state.running) {
            val probesByDomain = snapshot.probes.groupBy { it.request.domain }
            snapshot.domainStates.forEach { domain ->
                val label = when (domain.state) {
                    DiagnosticState.PASSED -> R.string.diagnostic_row_passed
                    DiagnosticState.FAILED -> R.string.diagnostic_row_failed
                    DiagnosticState.INCOMPLETE -> R.string.not_measured
                }
                addRow(rows, ResultRow(domain.domain, domain.domain, getString(label), domain.state,
                    probesByDomain[domain.domain].orEmpty()))
            }
        }
    }

    private fun addRow(rows: LinearLayout, result: ResultRow) {
        val row = layoutInflater.inflate(R.layout.diagnostic_row, rows, false) as MaterialCardView
        row.findViewById<TextView>(R.id.checkTitle).text = result.title
        row.findViewById<TextView>(R.id.checkSummary).apply {
            text = result.summary
            setTextColor(context.getColor(rowTint(result.state)))
        }
        val canExpand = result.probes.isNotEmpty()
        row.findViewById<View>(R.id.checkChevron).visibility = if (canExpand) View.VISIBLE else View.GONE
        if (canExpand) {
            row.findViewById<View>(R.id.checkHeader).apply {
                isFocusable = true
                setOnClickListener {
                    if (!expanded.add(result.key)) expanded.remove(result.key)
                    bindRowExpansion(row, result)
                }
            }
        }
        bindRowExpansion(row, result)
        rows.addView(row)
    }

    private fun rowTint(state: DiagnosticState?): Int = when (state) {
        DiagnosticState.PASSED -> R.color.vault_blue
        DiagnosticState.FAILED -> R.color.vault_danger
        else -> R.color.vault_text_secondary
    }

    private fun bindRowExpansion(row: MaterialCardView, result: ResultRow) {
        val isExpanded = result.probes.isNotEmpty() && result.key in expanded
        row.strokeColor = row.context.getColor(if (isExpanded) R.color.vault_diagnostic_expanded_outline else R.color.vault_outline)
        row.findViewById<View>(R.id.checkHeader).stateDescription = if (result.probes.isEmpty()) null else
            getString(if (isExpanded) R.string.diagnostic_expanded else R.string.diagnostic_collapsed)
        row.findViewById<View>(R.id.checkChevron).rotation = if (isExpanded) 90f else 0f
        row.findViewById<ImageView>(R.id.checkIcon).apply {
            setImageResource(when (result.state) {
                DiagnosticState.PASSED -> R.drawable.ic_check
                DiagnosticState.FAILED -> R.drawable.ic_error
                else -> R.drawable.ic_diagnostic_skipped
            })
            imageTintList = ColorStateList.valueOf(context.getColor(rowTint(result.state)))
        }
        row.findViewById<View>(R.id.checkDetails).visibility = if (isExpanded) View.VISIBLE else View.GONE
        val details = row.findViewById<LinearLayout>(R.id.checkProbeLines)
        if (isExpanded && details.childCount == 0) {
            result.probes.forEach { probe ->
                addProbeLine(details, probeDetail(probe), probe.durationMs)
                probe.tlsDurationMs?.let { addProbeLine(details, getString(R.string.diagnostic_tls_handshake), it) }
            }
        }
    }

    private fun addProbeLine(details: LinearLayout, label: String, duration: ULong) {
        val line = layoutInflater.inflate(R.layout.diagnostic_probe_line, details, false)
        line.findViewById<TextView>(R.id.probeLineLabel).text = label
        line.findViewById<TextView>(R.id.probeLineTime).text = "$duration ms"
        details.addView(line)
    }

    private fun probeDetail(probe: DiagnosticProbe): String {
        val target = when (val operation = probe.request.operation) {
            is DiagnosticOperation.Dns -> "${operation.server}: "
            is DiagnosticOperation.Tcp -> "${operation.address}:${operation.port} · "
            is DiagnosticOperation.Https -> operation.address?.let { "$it:443 · " }.orEmpty()
            is DiagnosticOperation.Ping -> "${operation.address} seq=${operation.sequence} size=${operation.packetSize} · "
            DiagnosticOperation.Route -> ""
        }
        return "${probe.request.domain} · $target${probe.detail}"
    }

    private fun runChecks() {
        (activity as? MainActivity)?.dismissInputKeyboard()
        expanded.clear()
        model.run(requireContext())
    }

    private fun copyLogs() {
        val root = view ?: return
        requireContext().getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(getString(R.string.runtime_logs), logText))
        val hint = root.findViewById<TextView>(R.id.tvLogHint)
        hint.setText(R.string.diagnostic_logs_copied)
        val tint = root.context.getColor(R.color.vault_blue)
        hint.setTextColor(tint)
        val copiedIcon = root.context.getDrawable(R.drawable.ic_check)?.mutate()?.apply {
            val size = (16 * resources.displayMetrics.density).roundToInt()
            setBounds(0, 0, size, size)
            setTint(tint)
        }
        hint.setCompoundDrawablesRelative(copiedIcon, null, null, null)
        logCopyFeedback?.cancel()
        logCopyFeedback = viewLifecycleOwner.lifecycleScope.launch {
            delay(2000)
            hint.setText(R.string.log_selection_hint)
            hint.setTextColor(root.context.getColor(R.color.vault_text_secondary))
            hint.setCompoundDrawablesRelative(null, null, null, null)
        }
    }

    private fun showLogState(root: View, message: Int?, loading: Boolean = false) {
        root.findViewById<View>(R.id.logState).visibility = if (message == null) View.GONE else View.VISIBLE
        root.findViewById<View>(R.id.logScroll).visibility = if (message == null) View.VISIBLE else View.INVISIBLE
        root.findViewById<View>(R.id.logProgress).visibility = if (loading) View.VISIBLE else View.GONE
        if (message != null) root.findViewById<TextView>(R.id.tvLogState).setText(message)
    }

    /** Poll only while the log tab is visible; unchanged content never resets selection or scroll. */
    private fun updateLogUpdates() {
        val visible = view != null && isResumed && !isHidden && tab == 1 && !clearingLogs
        if (!visible) { logUpdates?.cancel(); logUpdates = null; return }
        if (logUpdates?.isActive == true) return
        logsRendered = false
        if (logText.isEmpty()) view?.let { showLogState(it, R.string.diagnostic_logs_loading, loading = true) }
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
            showLogState(root, if (content.isEmpty()) R.string.no_logs else null)
            val followTail = clear || !logsRendered || !scroll.canScrollVertically(1)
            val previousY = scroll.scrollY
            if (content != logText || !logsRendered) {
                logText = content
                text.text = content
                logsRendered = true
                // Apply the final offset after layout and focus restoration. fullScroll
                // also changes focus, which can reveal the selectable text's start again.
                scroll.doOnPreDraw {
                    if (view !== root || tab != 1) return@doOnPreDraw
                    val targetY = if (followTail) text.bottom + scroll.paddingBottom - scroll.height else previousY
                    scroll.scrollTo(0, targetY.coerceAtLeast(0))
                }
            }
            root.findViewById<MaterialButton>(R.id.btnCopyLogs).isEnabled = content.isNotEmpty() && !clearingLogs
            root.findViewById<MaterialButton>(R.id.btnClearLogs).isEnabled = content.isNotEmpty() && !clearingLogs
        } catch (cancelled: CancellationException) { throw cancelled
        } catch (_: Exception) {
            logsRendered = false
            view?.let {
                showLogState(it, R.string.logs_failed)
                it.findViewById<MaterialButton>(R.id.btnCopyLogs).isEnabled = false
                it.findViewById<MaterialButton>(R.id.btnClearLogs).isEnabled = false
            }
        }
    }

    private fun confirmClearLogs() {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.clear_runtime_logs_title)
            .setMessage(R.string.clear_runtime_logs_message)
            .setNegativeButton(R.string.cancel_description, null)
            .setPositiveButton(R.string.clear) { _, _ -> clearLogs() }
            .show()
    }

    private fun clearLogs() {
        if (clearingLogs) return
        clearingLogs = true
        updateLogUpdates()
        view?.let { showLogState(it, R.string.diagnostic_logs_clearing, loading = true) }
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
        logCopyFeedback?.cancel()
        logCopyFeedback = null
        logsRendered = false
        storedProbeDomains = null
        savingProbeDomains = false
        loadingProbeDomains = false
        super.onDestroyView()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt("tab", tab)
        if (storedProbeDomains != null) {
            outState.putString("probeDraft", view?.findViewById<EditText>(R.id.edtDiagnosticDomains)?.text.toString())
        }
    }
}
