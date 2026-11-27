// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.animation.ValueAnimator
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.TransitionDrawable
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.view.updateLayoutParams
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import net.dighole.vault.VaultVpnService.Companion.PREFS_NAME
import net.dighole.vault.data.deviceId
import net.dighole.vault.data.readVaultConfig
import net.dighole.vault.data.readVaultProfiles
import net.dighole.vault.data.selectVaultProfile
import kotlin.math.roundToInt

class StatusFragment : Fragment() {

    private lateinit var btnToggleVpn: ImageButton
    private var connectionIconRes: Int? = null
    private lateinit var tvStatus: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var tvIpv4Address: TextView
    private lateinit var tvIpv6Address: TextView
    private lateinit var networkCard: View
    private lateinit var publicIpSection: View
    private lateinit var tvPublicIpAddress: TextView
    private lateinit var duration: TextView
    private var durationUpdates: Job? = null
    private lateinit var sentPackets: TextView
    private lateinit var receivedPackets: TextView
    private lateinit var sentBytes: TextView
    private lateinit var receivedBytes: TextView
    private lateinit var sentSpeed: TextView
    private lateinit var receivedSpeed: TextView

    private var vpnState = VpnUiState()
    private var connectJob: Job? = null
    private var awaitingPermission = false
    private var permissionRequired = false
    private var hasProfiles: Boolean? = null
    private var selectedProfileName: String? = null
    private var pendingConnectProfileName: String? = null

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        awaitingPermission = false
        permissionRequired = result.resultCode != android.app.Activity.RESULT_OK
        if (!permissionRequired) {
            startVpnService()
        } else {
            Log.d("StatusFragment", "VPN permission denied or dialog cancelled")
            vpnState = vpnState.copy(isConnecting = false)
            updateUI()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        awaitingPermission = savedInstanceState?.getBoolean("awaitingPermission") ?: false
        permissionRequired = savedInstanceState?.getBoolean("permissionRequired") ?: false
        pendingConnectProfileName = savedInstanceState?.getString("pendingProfileName")
        Log.d("StatusFragment", "onCreate")
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean("awaitingPermission", awaitingPermission)
        outState.putBoolean("permissionRequired", permissionRequired)
        outState.putString("pendingProfileName", pendingConnectProfileName)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_status, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        btnToggleVpn = view.findViewById(R.id.btnToggleVpn)
        connectionIconRes = null
        tvStatus = view.findViewById(R.id.tvStatus)
        tvStatusDetail = view.findViewById(R.id.tvStatusDetail)
        tvIpv4Address = view.findViewById(R.id.tvIpv4Address)
        tvIpv6Address = view.findViewById(R.id.tvIpv6Address)
        networkCard = view.findViewById(R.id.networkCard)
        publicIpSection = view.findViewById(R.id.publicIpSection)
        tvPublicIpAddress = view.findViewById(R.id.tvPublicIpAddress)
        duration = view.findViewById(R.id.connectionDuration)
        duration.typeface = Typeface.create(Typeface.MONOSPACE, 300, false)
        sentPackets = view.findViewById(R.id.tvSentPackets)
        receivedPackets = view.findViewById(R.id.tvReceivedPackets)
        sentBytes = view.findViewById(R.id.tvSentBytes)
        receivedBytes = view.findViewById(R.id.tvReceivedBytes)
        sentSpeed = view.findViewById(R.id.tvSentSpeed)
        receivedSpeed = view.findViewById(R.id.tvReceivedSpeed)

        btnToggleVpn.setOnClickListener {
            when {
                vpnState.isConnected || vpnState.isConnecting -> disconnectVpn()
                hasProfiles == false && !permissionRequired &&
                    (requireContext().applicationContext as VaultApplication).currentVpnStatus !is VpnStatusEvent.Error ->
                    (activity as? MainActivity)?.openNewProfile()
                else -> connectVpn()
            }
        }
        view.findViewById<View>(R.id.btnProfile).setOnClickListener { showProfileDialog() }

        restoreStateFromPrefs()
        refreshProfiles()
        renderTrafficStats((requireContext().applicationContext as VaultApplication).latestTrafficStats)

        viewLifecycleOwner.lifecycleScope.launch {
            val app = requireContext().applicationContext as? VaultApplication ?: return@launch
            app.vpnStatusEvents.collect { event ->
                applyVpnEvent(event)
            }
        }

        // updateUI() is called from onResume -> restoreStateFromPrefs(),
        // so we skip it here to avoid a redundant layout pass.
    }

    override fun onResume() {
        super.onResume()
        restoreStateFromPrefs()
        refreshProfiles()
    }

    private fun restoreStateFromPrefs() {
        val prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        val app = requireContext().applicationContext as VaultApplication
        val event = app.currentVpnStatus
        vpnState = if (event != null) {
            vpnState.applying(event)
        } else {
            val connected = isVpnServiceRunning() && prefs.getBoolean("vpn_connected", false)
            if (connected) app.activeProfileName = prefs.getString("vpn_profile_name", null)
            VpnUiState(
                isConnected = connected,
                ipv4 = if (connected) prefs.getString("vpn_assigned_ipv4", "").orEmpty() else "",
                ipv6 = if (connected) prefs.getString("vpn_assigned_ipv6", "").orEmpty() else "",
                publicIp = if (connected) prefs.getString("vpn_public_ip", "").orEmpty() else ""
            )
        }

        Log.d(
            "StatusFragment",
            "Restored state: $vpnState"
        )
        updateUI()
    }

    private fun isVpnServiceRunning(): Boolean {
        return VaultVpnService.isRunning
    }

    override fun onPause() {
        stopDurationUpdates()
        super.onPause()
    }

    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        if (view != null) {
            if (hidden) {
                stopDurationUpdates()
            } else {
                restoreStateFromPrefs()
                refreshProfiles()
            }
        }
    }

    private fun connectVpn() {
        if (connectJob?.isActive == true || awaitingPermission) return
        connectJob = viewLifecycleOwner.lifecycleScope.launch {
            try {
                val config = requireContext().readVaultConfig()
                Log.d("StatusFragment", "Config loaded for connect")

                if (config.name.isEmpty() || config.host.isEmpty() || config.password.isEmpty()) {
                    com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
                        .setMessage(R.string.status_configure_first)
                        .setPositiveButton(R.string.nav_configure) { _, _ ->
                            (activity as? MainActivity)?.navigateTo(R.id.nav_configure)
                        }.setNegativeButton(R.string.cancel_description, null).show()
                    return@launch
                }

                pendingConnectProfileName = config.name
                val intent = VpnService.prepare(requireContext())
                if (intent != null) {
                    permissionRequired = true
                    awaitingPermission = true
                    vpnLauncher.launch(intent)
                } else {
                    startVpnService()
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_e: Exception) {
                Log.e("StatusFragment", "Failed to connect VPN", _e)
                awaitingPermission = false
                permissionRequired = false
                vpnState = VpnUiState()
                (requireContext().applicationContext as VaultApplication)
                    .emitVpnStatusEvent(VpnStatusEvent.Error(_e.message))
            } finally {
                connectJob = null
                updateUI()
            }
        }
        updateUI()
    }

    private fun disconnectVpn() {
        try {
            val serviceIntent = Intent(requireContext(), VaultVpnService::class.java).apply {
                action = VaultVpnService.ACTION_DISCONNECT
            }
            requireContext().startService(serviceIntent)
            val app = requireContext().applicationContext as VaultApplication
            app.emitVpnStatusEvent(VpnStatusEvent.Disconnecting)
            vpnState = vpnState.applying(VpnStatusEvent.Disconnecting)
            updateUI()
        } catch (_: Exception) {
            Log.e("StatusFragment", "Failed to disconnect VPN")
        }
    }

    private fun refreshProfiles() {
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val store = requireContext().readVaultProfiles()
                hasProfiles = store.profiles.isNotEmpty()
                selectedProfileName = store.selectedProfileName
                view?.findViewById<TextView>(R.id.btnProfileText)?.text =
                    store.selectedProfileName ?: getString(R.string.add_profile)
                updateUI()
            } catch (_: Exception) {
                view?.findViewById<TextView>(R.id.btnProfileText)?.setText(R.string.config_load_failed)
            }
        }
    }

    private fun showProfileDialog() {
        viewLifecycleOwner.lifecycleScope.launch {
            val store = try {
                requireContext().readVaultProfiles()
            } catch (_: Exception) {
                return@launch
            }
            if (store.profiles.isEmpty()) {
                (activity as? MainActivity)?.navigateTo(R.id.nav_configure)
                return@launch
            }
            val names = store.profiles.map { it.name }.toTypedArray()
            val selected = names.indexOf(store.selectedProfileName)
            com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.select_profile)
                .setSingleChoiceItems(names, selected) { dialog, which ->
                    dialog.dismiss()
                    chooseProfile(names[which])
                }
                .setNegativeButton(R.string.cancel_description, null)
                .show()
        }
    }

    private fun chooseProfile(name: String) {
        val app = requireContext().applicationContext as VaultApplication
        val running = app.activeProfileName ?: app.requestedProfileName
        if ((vpnState.isConnected || vpnState.isConnecting || running != null) && running != name) {
            com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.switch_profile)
                .setMessage(getString(R.string.switch_profile_confirmation, name))
                .setPositiveButton(R.string.disconnect_and_connect) { _, _ -> selectProfile(name, true) }
                .setNegativeButton(R.string.cancel_description, null)
                .show()
        } else {
            selectProfile(name, false)
        }
    }

    private fun selectProfile(name: String, connect: Boolean) {
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                requireContext().selectVaultProfile(name)
                pendingConnectProfileName = name
                refreshProfiles()
                if (connect) startVpnService(name)
            } catch (_: Exception) {
                (requireContext().applicationContext as VaultApplication)
                    .emitVpnStatusEvent(VpnStatusEvent.Error(getString(R.string.config_save_failed)))
            }
        }
    }

    private fun startVpnService(profileName: String? = null) {
        permissionRequired = false
        try {
            val target = profileName ?: pendingConnectProfileName ?: return
            val idBytes = requireContext().deviceId().bytes
            val serviceIntent = Intent(requireContext(), VaultVpnService::class.java).apply {
                action = VaultVpnService.ACTION_CONNECT
                putExtra(VaultVpnService.EXTRA_ID, idBytes)
                putExtra(VaultVpnService.EXTRA_PROFILE_NAME, target)
            }

            ContextCompat.startForegroundService(requireContext(), serviceIntent)
            (requireContext().applicationContext as VaultApplication).emitVpnStatusEvent(VpnStatusEvent.Connecting)
            vpnState = vpnState.applying(VpnStatusEvent.Connecting)
        } catch (_e: Exception) {
            Log.e("StatusFragment", "Failed to start VPN service", _e)
            vpnState = VpnUiState()
            (requireContext().applicationContext as VaultApplication)
                .emitVpnStatusEvent(VpnStatusEvent.Error(_e.message))
        }
        updateUI()
    }

    private enum class CardState(val title: Int, val action: Int, val usesIndigo: Boolean = false) {
        NoProfile(R.string.status_no_profile, R.string.add_profile),
        Disconnected(R.string.status_off, R.string.status_tap_to_connect),
        Connecting(R.string.status_connecting, R.string.status_wait, true),
        Connected(R.string.status_on, R.string.status_tap_to_disconnect, true),
        Reconnecting(R.string.status_reconnecting, R.string.status_tap_to_disconnect, true),
        Disconnecting(R.string.status_disconnecting, R.string.status_wait),
        Failure(R.string.status_failed, R.string.status_tap_to_retry),
        Permission(R.string.status_permission_required, R.string.status_authorize);

        val busy: Boolean get() = this == Connecting || this == Reconnecting || this == Disconnecting
    }

    private fun cardState(app: VaultApplication): CardState = when {
        vpnState.isDisconnecting -> CardState.Disconnecting
        vpnState.isConnecting && vpnState.isConnected -> CardState.Reconnecting
        vpnState.isConnected -> CardState.Connected
        vpnState.isConnecting || (!awaitingPermission && connectJob?.isActive == true) -> CardState.Connecting
        permissionRequired -> CardState.Permission
        app.currentVpnStatus is VpnStatusEvent.Error -> CardState.Failure
        hasProfiles == false -> CardState.NoProfile
        else -> CardState.Disconnected
    }

    private fun statusDetailText(app: VaultApplication, state: CardState): String? = when (state) {
        CardState.NoProfile -> getString(R.string.status_no_profile_detail)
        CardState.Disconnected -> selectedProfileName?.let { getString(R.string.status_using_profile, it) }
        CardState.Connecting -> getString(R.string.status_connecting_detail)
        CardState.Reconnecting -> getString(R.string.status_reconnecting_detail)
        CardState.Disconnecting -> getString(R.string.status_disconnecting_detail)
        CardState.Permission -> getString(R.string.status_permission_detail)
        CardState.Connected -> (app.activeProfileName ?: app.requestedProfileName)?.let {
            getString(R.string.profile_disconnect_format, it)
        } ?: getString(R.string.status_tap_to_disconnect)
        CardState.Failure -> (app.currentVpnStatus as? VpnStatusEvent.Error)?.let { error ->
            error.messageResId?.let(::getString)
                ?: error.message?.lineSequence()?.firstOrNull()?.takeIf { it.isNotBlank() }
        } ?: getString(R.string.error_connection_timeout)
    }

    private fun updateUI() {
        val root = view ?: return
        val app = requireContext().applicationContext as VaultApplication
        val state = cardState(app)
        val connected = state == CardState.Connected
        renderStatus(root, state)
        renderHero(root, state)
        renderConnectionControls(root, state)
        renderStatusDetails(root, app, state)
        root.findViewById<View>(R.id.readyCard).visibility =
            if (state == CardState.Disconnected && hasProfiles == true) View.VISIBLE else View.GONE
        renderConnectionDuration(app, connected)
        renderConnectionInfo(root, connected)
        renderTrafficStats(app.latestTrafficStats)
    }

    private fun renderStatus(root: View, state: CardState) {
        root.findViewById<View>(R.id.btnProfile).visibility = when (state) {
            CardState.Disconnected, CardState.Failure, CardState.Permission -> View.VISIBLE
            else -> View.GONE
        }
        tvStatus.setText(state.title)
        val showsBadge = state != CardState.Failure && state != CardState.Permission
        root.findViewById<View>(R.id.headerStatusBadge).visibility = if (showsBadge) View.VISIBLE else View.GONE
        if (showsBadge) renderStatusBadge(root, state.usesIndigo)
    }

    private fun renderStatusBadge(root: View, emphasized: Boolean) {
        root.findViewById<View>(R.id.headerStatusBadge).backgroundTintList =
            ColorStateList.valueOf(root.context.getColor(when {
                emphasized -> R.color.vault_indigo_soft
                else -> R.color.vault_surface_subtle
            }))
        root.findViewById<TextView>(R.id.tvHeaderStatus).apply {
            text = if (vpnState.isConnected && !vpnState.isConnecting) getString(R.string.status_running) else tvStatus.text
            setTextColor(ContextCompat.getColor(
                requireContext(), when {
                    emphasized -> R.color.vault_blue_dark
                    else -> R.color.vault_text_secondary
                }
            ))
        }
        root.findViewById<View>(R.id.headerStatusDot).backgroundTintList =
            ColorStateList.valueOf(ContextCompat.getColor(
                requireContext(), when {
                    emphasized -> R.color.connection_connected
                    else -> R.color.connection_disconnected
                }
            ))
    }

    private fun renderHero(root: View, state: CardState) {
        root.findViewById<View>(R.id.statusHero).setBackgroundResource(when {
            state == CardState.Connected -> R.drawable.vault_bg_hero_connected
            state.usesIndigo -> R.drawable.vault_bg_hero_progress
            else -> R.drawable.vault_bg_hero_neutral
        })
        tvStatus.setTextColor(ContextCompat.getColor(
            requireContext(), if (state.usesIndigo) R.color.vault_hero_text else R.color.vault_text_secondary
        ))
        btnToggleVpn.setBackgroundResource(
            if (state.usesIndigo) R.drawable.vault_bg_connection_button_connected else R.drawable.vault_bg_connection_button_neutral
        )
        btnToggleVpn.setPadding(dp(23), dp(23), dp(23), dp(23))
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).roundToInt()

    private fun setTopMargin(view: View, value: Int) {
        val margin = dp(value)
        if ((view.layoutParams as LinearLayout.LayoutParams).topMargin != margin) {
            view.updateLayoutParams<LinearLayout.LayoutParams> { topMargin = margin }
        }
    }

    private fun renderConnectionControls(root: View, state: CardState) {
        renderConnectionIcon(root, state)
        val preparing = connectJob?.isActive == true
        btnToggleVpn.isEnabled = !preparing && !awaitingPermission && state != CardState.Disconnecting
        btnToggleVpn.contentDescription = getString(when (state) {
            CardState.Connecting -> R.string.status_cancel_connection
            CardState.Failure -> R.string.retry
            else -> state.action
        })
        root.findViewById<TextView>(R.id.tvConnectionAction).apply {
            visibility = if (state == CardState.Connected) View.GONE else View.VISIBLE
            setText(state.action)
            setTextColor(ContextCompat.getColor(
                requireContext(), if (state.usesIndigo) R.color.vault_hero_text else R.color.vault_blue
            ))
        }
    }

    private fun renderConnectionIcon(root: View, state: CardState) {
        val allowMotion = ValueAnimator.areAnimatorsEnabled()
        val progress = root.findViewById<com.google.android.material.progressindicator.CircularProgressIndicator>(
            R.id.connectionProgress
        )
        progress.setIndicatorColor(requireContext().getColor(
            if (state == CardState.Disconnecting) R.color.vault_text_disabled else R.color.status_progress
        ))
        val nextIcon = when {
            state.busy && allowMotion -> 0
            state == CardState.Disconnecting -> R.drawable.ic_connection_stopping
            state.busy -> R.drawable.ic_status_progress
            state == CardState.Connected -> R.drawable.ic_connected
            state == CardState.NoProfile -> R.drawable.ic_connection_add
            state == CardState.Failure -> R.drawable.ic_connection_failed
            state == CardState.Permission -> R.drawable.ic_connection_permission
            else -> R.drawable.ic_disconnected
        }
        val previousIcon = connectionIconRes
        if (nextIcon == previousIcon) return
        connectionIconRes = nextIcon

        val fadeDuration = 180L
        progress.animate().cancel()
        if (previousIcon != null && allowMotion && btnToggleVpn.isShown) {
            val context = root.context
            val icons = Array(2) { index ->
                val icon = if (index == 0) previousIcon else nextIcon
                if (icon == 0) ColorDrawable() else requireNotNull(ContextCompat.getDrawable(context, icon))
            }
            val transition = TransitionDrawable(icons).apply { isCrossFadeEnabled = true }
            btnToggleVpn.setImageDrawable(transition)
            transition.startTransition(fadeDuration.toInt())
            when {
                nextIcon == 0 -> {
                    if (progress.visibility != View.VISIBLE) progress.alpha = 0f
                    progress.visibility = View.VISIBLE
                    progress.animate().alpha(1f).setDuration(fadeDuration).start()
                }
                progress.visibility == View.VISIBLE -> {
                    progress.animate().alpha(0f).setDuration(fadeDuration)
                        .withEndAction { progress.visibility = View.GONE }.start()
                }
            }
        } else {
            btnToggleVpn.setImageResource(nextIcon)
            progress.alpha = 1f
            progress.visibility = if (nextIcon == 0) View.VISIBLE else View.GONE
        }
    }

    private fun renderStatusDetails(root: View, app: VaultApplication, state: CardState) {
        val detail = statusDetailText(app, state)
        tvStatusDetail.text = detail.orEmpty()
        tvStatusDetail.visibility = if (detail == null) View.GONE else View.VISIBLE
        setTopMargin(tvStatusDetail, if (state == CardState.Connected) 17 else 16)
        tvStatusDetail.setTextColor(ContextCompat.getColor(
            requireContext(), if (state.usesIndigo) R.color.vault_hero_secondary else R.color.vault_text_secondary
        ))
        root.findViewById<TextView>(R.id.tvTunnelFeature).apply {
            visibility = if (state == CardState.Connected || state == CardState.Disconnected) View.VISIBLE else View.GONE
            setBackgroundResource(
                if (state == CardState.Connected) R.drawable.vault_bg_feature_connected else R.drawable.vault_bg_feature
            )
            setTopMargin(this, if (state == CardState.Connected) 24 else 22)
            setTextColor(ContextCompat.getColor(
                requireContext(), if (state.usesIndigo) R.color.vault_hero_secondary else R.color.vault_text_secondary
            ))
        }
        root.findViewById<TextView>(R.id.connectionRecovery).apply {
            visibility = if (state == CardState.Reconnecting) View.VISIBLE else View.GONE
            if (state == CardState.Reconnecting) {
                val addresses = listOfNotNull(
                    vpnState.ipv4.takeIf { it.isNotEmpty() }?.let { "IPv4  $it" },
                    vpnState.ipv6.takeIf { it.isNotEmpty() }?.let { "IPv6  $it" }
                )
                val stats = app.latestTrafficStats
                val rates = getString(R.string.status_recovery_rates,
                    StatusPresentation.bytes(stats?.sendSpeed ?: 0), StatusPresentation.bytes(stats?.receiveSpeed ?: 0))
                text = (addresses + rates).joinToString("\n")
            }
        }
    }

    private fun renderConnectionDuration(app: VaultApplication, connected: Boolean) {
        duration.visibility = if (connected) View.VISIBLE else View.GONE
        if (connected) {
            renderDuration(app.ensureConnectionStarted())
            if (!isHidden && isResumed) startDurationUpdates(app.ensureConnectionStarted())
        } else stopDurationUpdates()
    }

    private fun renderConnectionInfo(root: View, connected: Boolean) {
        val showPublicIp = connected && vpnState.publicIp.isNotEmpty()
        val hasTunnelIps = vpnState.ipv4.isNotEmpty() || vpnState.ipv6.isNotEmpty()
        val showNetworkCard = connected && (showPublicIp || hasTunnelIps)
        val connectionInfo = root.findViewById<View>(R.id.connectionInfo)
        connectionInfo.visibility = if (connected) View.VISIBLE else View.GONE
        networkCard.visibility = if (showNetworkCard) View.VISIBLE else View.GONE
        publicIpSection.visibility = if (showPublicIp) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.networkDivider).visibility =
            if (showPublicIp && hasTunnelIps) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.rowIpv4).visibility = if (vpnState.ipv4.isNotEmpty()) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.rowIpv6).visibility = if (vpnState.ipv6.isNotEmpty()) View.VISIBLE else View.GONE
        tvIpv4Address.text = vpnState.ipv4
        tvIpv6Address.text = vpnState.ipv6
        tvPublicIpAddress.text = vpnState.publicIp
    }

    private fun renderTrafficStats(stats: VpnStatusEvent.TrafficStats?) {
        if (isHidden || !isResumed) return
        sentPackets.setIfChanged(getString(R.string.packets, (stats?.packetsSent ?: 0).coerceAtLeast(0)))
        receivedPackets.setIfChanged(getString(R.string.packets, (stats?.packetsReceived ?: 0).coerceAtLeast(0)))
        sentBytes.setIfChanged(StatusPresentation.bytes(stats?.bytesSent ?: 0))
        receivedBytes.setIfChanged(StatusPresentation.bytes(stats?.bytesReceived ?: 0))
        sentSpeed.setIfChanged(StatusPresentation.bytes(stats?.sendSpeed ?: 0) + "/s")
        receivedSpeed.setIfChanged(StatusPresentation.bytes(stats?.receiveSpeed ?: 0) + "/s")
    }

    private fun TextView.setIfChanged(value: String) {
        if (text.toString() != value) text = value
    }

    private fun renderDuration(base: Long) {
        val elapsed = StatusPresentation.duration(android.os.SystemClock.elapsedRealtime() - base)
        duration.setIfChanged(elapsed)
        duration.contentDescription = getString(R.string.connected_duration, elapsed)
    }

    private fun startDurationUpdates(base: Long) {
        if (durationUpdates?.isActive == true) return
        durationUpdates = viewLifecycleOwner.lifecycleScope.launch {
            while (isActive) {
                renderDuration(base)
                val elapsed = (android.os.SystemClock.elapsedRealtime() - base).coerceAtLeast(0)
                delay(1000 - elapsed % 1000)
            }
        }
    }

    private fun stopDurationUpdates() {
        durationUpdates?.cancel()
        durationUpdates = null
    }

    private fun applyVpnEvent(event: VpnStatusEvent) {
        if (event is VpnStatusEvent.TrafficStats) {
            renderTrafficStats(event)
            return
        }
        VaultFileLogger.event("StatusFragment", "APPLY_EVENT event=$event before=$vpnState")
        vpnState = vpnState.applying(event)
        updateUI()
    }

    companion object {
        fun newInstance() = StatusFragment()
    }
}
