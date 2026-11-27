// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageButton
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
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

class StatusFragment : Fragment() {

    private lateinit var btnToggleVpn: ImageButton
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
    private var pendingConnectProfileName: String? = null

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        awaitingPermission = false
        if (result.resultCode == android.app.Activity.RESULT_OK) {
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
        pendingConnectProfileName = savedInstanceState?.getString("pendingProfileName")
        Log.d("StatusFragment", "onCreate")
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean("awaitingPermission", awaitingPermission)
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
        tvStatus = view.findViewById(R.id.tvStatus)
        tvStatusDetail = view.findViewById(R.id.tvStatusDetail)
        tvIpv4Address = view.findViewById(R.id.tvIpv4Address)
        tvIpv6Address = view.findViewById(R.id.tvIpv6Address)
        networkCard = view.findViewById(R.id.networkCard)
        publicIpSection = view.findViewById(R.id.publicIpSection)
        tvPublicIpAddress = view.findViewById(R.id.tvPublicIpAddress)
        duration = view.findViewById(R.id.connectionDuration)
        sentPackets = view.findViewById(R.id.tvSentPackets)
        receivedPackets = view.findViewById(R.id.tvReceivedPackets)
        sentBytes = view.findViewById(R.id.tvSentBytes)
        receivedBytes = view.findViewById(R.id.tvReceivedBytes)
        sentSpeed = view.findViewById(R.id.tvSentSpeed)
        receivedSpeed = view.findViewById(R.id.tvReceivedSpeed)

        btnToggleVpn.setOnClickListener {
            if (vpnState.isConnected || vpnState.isConnecting) {
                disconnectVpn()
            } else {
                connectVpn()
            }
        }
        view.findViewById<View>(R.id.btnProfile).setOnClickListener { showProfileDialog() }
        view.findViewById<View>(R.id.failureDiagnosticsCard).setOnClickListener {
            requireActivity().findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(
                R.id.bottomNav
            ).selectedItemId = R.id.nav_diagnostics
        }

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
        } catch (_: Exception) {
            Log.e("StatusFragment", "Failed to disconnect VPN")
        }
    }

    private fun refreshProfiles() {
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val store = requireContext().readVaultProfiles()
                view?.findViewById<TextView>(R.id.btnProfileText)?.text =
                    store.selectedProfileName ?: getString(R.string.add_profile)
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

    private fun statusDetailText(app: VaultApplication, active: Boolean): String? {
        val error = app.currentVpnStatus as? VpnStatusEvent.Error
        val runningProfile = if (active) app.activeProfileName ?: app.requestedProfileName else null
        return when {
            error != null -> getString(
                R.string.status_error_prefix,
                error.messageResId?.let(::getString) ?: error.message.orEmpty()
            )
            runningProfile != null -> getString(R.string.profile_disconnect_format, runningProfile)
            else -> null
        }
    }

    private fun updateUI() {
        val root = view ?: return
        val app = requireContext().applicationContext as VaultApplication
        val preparing = awaitingPermission || connectJob?.isActive == true
        val active = vpnState.isConnected || vpnState.isConnecting
        val emphasized = active || preparing
        val failed = app.currentVpnStatus is VpnStatusEvent.Error && !emphasized
        val connected = vpnState.isConnected && !vpnState.isConnecting
        renderStatus(root, preparing, emphasized, failed)
        renderHero(root, emphasized, failed)
        renderConnectionControls(root, active, preparing, emphasized, failed)
        renderStatusDetails(root, app, active, emphasized, failed)
        root.findViewById<View>(R.id.readyCard).visibility = if (emphasized || failed) View.GONE else View.VISIBLE
        root.findViewById<View>(R.id.failureDiagnosticsCard).visibility = if (failed) View.VISIBLE else View.GONE
        renderConnectionDuration(app, connected)
        renderConnectionInfo(root, vpnState.isConnected)
        renderTrafficStats(app.latestTrafficStats)
    }

    private fun renderStatus(root: View, preparing: Boolean, emphasized: Boolean, failed: Boolean) {
        root.findViewById<View>(R.id.btnProfile).visibility = if (emphasized) View.GONE else View.VISIBLE
        tvStatus.setText(when {
            failed -> R.string.status_failed
            vpnState.isConnecting && vpnState.isConnected -> R.string.status_reconnecting
            vpnState.isConnecting || preparing -> R.string.status_connecting
            vpnState.isConnected -> R.string.status_on
            else -> R.string.status_off
        })
        root.findViewById<TextView>(R.id.tvHeaderStatus).apply {
            text = tvStatus.text
            setTextColor(ContextCompat.getColor(
                requireContext(), when {
                    failed -> R.color.vault_danger
                    emphasized -> R.color.vault_blue_dark
                    else -> R.color.vault_text_secondary
                }
            ))
        }
        root.findViewById<View>(R.id.headerStatusDot).backgroundTintList =
            android.content.res.ColorStateList.valueOf(ContextCompat.getColor(
                requireContext(), when {
                    failed -> R.color.vault_danger
                    emphasized -> R.color.connection_connected
                    else -> R.color.connection_disconnected
                }
            ))
    }

    private fun renderHero(root: View, emphasized: Boolean, failed: Boolean) {
        val hero = root.findViewById<View>(R.id.statusHero)
        hero.setBackgroundResource(when {
            failed -> R.drawable.vault_bg_hero_error
            emphasized -> R.drawable.vault_bg_hero_active
            else -> R.drawable.vault_bg_hero_muted
        })
        hero.layoutParams = hero.layoutParams.apply {
            height = ((if (emphasized) 258 else 286) * resources.displayMetrics.density).toInt()
        }
        val heroVerticalPadding = ((if (emphasized) 8 else 24) * resources.displayMetrics.density).toInt()
        hero.setPadding(hero.paddingLeft, heroVerticalPadding, hero.paddingRight, heroVerticalPadding)
        tvStatus.setTextColor(ContextCompat.getColor(
            requireContext(), when {
                failed -> R.color.vault_danger
                emphasized -> R.color.vault_hero_text
                else -> R.color.vault_text_secondary
            }
        ))
    }

    private fun renderConnectionControls(
        root: View,
        active: Boolean,
        preparing: Boolean,
        emphasized: Boolean,
        failed: Boolean
    ) {
        btnToggleVpn.setImageResource(when {
            failed -> R.drawable.ic_error
            active -> R.drawable.ic_connected
            else -> R.drawable.ic_disconnected
        })
        btnToggleVpn.isEnabled = !preparing
        btnToggleVpn.alpha = if (btnToggleVpn.isEnabled) 1f else 0.5f
        btnToggleVpn.contentDescription = getString(when {
            failed -> R.string.retry
            active -> R.string.status_tap_to_disconnect
            else -> R.string.status_tap_to_connect
        })
        root.findViewById<TextView>(R.id.tvConnectionAction).apply {
            visibility = if (emphasized) View.GONE else View.VISIBLE
            setText(if (failed) R.string.retry else R.string.status_tap_to_connect)
            setTextColor(ContextCompat.getColor(requireContext(), R.color.vault_blue))
        }
    }

    private fun renderStatusDetails(
        root: View,
        app: VaultApplication,
        active: Boolean,
        emphasized: Boolean,
        failed: Boolean
    ) {
        val detail = statusDetailText(app, active)
        tvStatusDetail.text = detail.orEmpty()
        tvStatusDetail.visibility = if (detail == null) View.GONE else View.VISIBLE
        tvStatusDetail.setTextColor(ContextCompat.getColor(
            requireContext(), when {
                failed -> R.color.vault_danger
                emphasized -> R.color.vault_hero_secondary
                else -> R.color.vault_text_secondary
            }
        ))
        root.findViewById<TextView>(R.id.tvTunnelFeature).apply {
            setText(if (failed) R.string.failure_retry_hint else R.string.tunnel_features)
            setBackgroundResource(
                if (emphasized) R.drawable.vault_bg_feature_active else R.drawable.vault_bg_feature
            )
            setTextColor(ContextCompat.getColor(
                requireContext(), if (emphasized) R.color.vault_hero_secondary else R.color.vault_text_secondary
            ))
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
