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
import kotlinx.coroutines.launch
import net.dighole.vault.VaultVpnService.Companion.PREFS_NAME
import net.dighole.vault.data.readVaultConfig

class StatusFragment : Fragment() {

    private lateinit var btnToggleVpn: ImageButton
    private lateinit var tvStatus: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var tvIpv4Address: TextView
    private lateinit var tvIpv6Address: TextView
    private lateinit var duration: android.widget.Chronometer
    private lateinit var sentPackets: TextView
    private lateinit var receivedPackets: TextView
    private lateinit var sentBytes: TextView
    private lateinit var receivedBytes: TextView
    private lateinit var sentSpeed: TextView
    private lateinit var receivedSpeed: TextView

    private var isConnected = false
    private var isConnecting = false
    private var currentIp: String = ""
    private var currentIpv6: String = ""

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            startVpnService()
        } else {
            Log.d("StatusFragment", "VPN permission denied or dialog cancelled")
            isConnecting = false
            updateUI()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d("StatusFragment", "onCreate")
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
        duration = view.findViewById(R.id.connectionDuration)
        duration.setOnChronometerTickListener { timer ->
            val elapsed = StatusPresentation.duration(android.os.SystemClock.elapsedRealtime() - timer.base)
            timer.text = elapsed
            timer.contentDescription = getString(R.string.connected_duration, elapsed)
        }
        sentPackets = view.findViewById(R.id.tvSentPackets)
        receivedPackets = view.findViewById(R.id.tvReceivedPackets)
        sentBytes = view.findViewById(R.id.tvSentBytes)
        receivedBytes = view.findViewById(R.id.tvReceivedBytes)
        sentSpeed = view.findViewById(R.id.tvSentSpeed)
        receivedSpeed = view.findViewById(R.id.tvReceivedSpeed)

        btnToggleVpn.setOnClickListener {
            if (isConnected) {
                disconnectVpn()
            } else {
                connectVpn()
            }
        }

        restoreStateFromPrefs()
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
    }

    private fun restoreStateFromPrefs() {
        val prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        val app = requireContext().applicationContext as VaultApplication
        when (val event = app.currentVpnStatus) {
            is VpnStatusEvent.Connected -> {
                isConnected = true
                isConnecting = false
                currentIp = event.ipv4
                currentIpv6 = event.ipv6
            }
            is VpnStatusEvent.Reconnecting -> { isConnected = true; isConnecting = true }
            is VpnStatusEvent.Error, is VpnStatusEvent.Disconnected -> {
                isConnected = false; isConnecting = false; currentIp = ""; currentIpv6 = ""
            }
            else -> {
                isConnected = isVpnServiceRunning() && prefs.getBoolean("vpn_connected", false)
                isConnecting = false
                currentIp = if (isConnected) prefs.getString("vpn_assigned_ipv4", "").orEmpty() else ""
                currentIpv6 = if (isConnected) prefs.getString("vpn_assigned_ipv6", "").orEmpty() else ""
            }
        }

        Log.d(
            "StatusFragment",
            "Restored state: connected=$isConnected, connecting=$isConnecting, ip=$currentIp"
        )
        updateUI()
    }

    private fun isVpnServiceRunning(): Boolean {
        return VaultVpnService.isRunning
    }

    override fun onPause() {
        duration.stop()
        super.onPause()
    }

    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        if (view != null) {
            if (hidden) duration.stop() else restoreStateFromPrefs()
        }
    }

    private fun connectVpn() {
        lifecycleScope.launch {
            try {
                val config = requireContext().readVaultConfig()
                Log.d("StatusFragment", "Config loaded for connect")

                if (config.host.isEmpty() || config.password.isEmpty()) {
                    com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
                        .setMessage(R.string.status_configure_first)
                        .setPositiveButton(R.string.nav_configure) { _, _ ->
                            (activity as? MainActivity)?.navigateTo(R.id.nav_configure)
                        }.setNegativeButton(R.string.cancel_description, null).show()
                    return@launch
                }

                isConnecting = true
                updateUI()

                val intent = VpnService.prepare(requireContext())
                if (intent != null) {
                    vpnLauncher.launch(intent)
                } else {
                    startVpnService()
                }
            } catch (_e: Exception) {
                Log.e("StatusFragment", "Failed to connect VPN", _e)
                isConnecting = false
                isConnected = false
                updateUI()
                tvStatusDetail.text = getString(R.string.status_error_prefix, _e.message)
                tvStatusDetail.visibility = View.VISIBLE
            }
        }
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

    private fun startVpnService() {
        lifecycleScope.launch {
            try {
                val prefs = requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                val deviceId = prefs.getString("device_id", null) ?: generateDeviceId()

                val idBytes = try {
                    hexToBytes(deviceId)
                } catch (_e: Exception) {
                    Log.e("StatusFragment", "Invalid device ID, generating new one", _e)
                    val newId = generateDeviceId()
                    hexToBytes(newId)
                }
                check(idBytes.isNotEmpty()) { "Invalid device ID" }

                val serviceIntent = Intent(requireContext(), VaultVpnService::class.java).apply {
                    action = VaultVpnService.ACTION_CONNECT
                    putExtra(VaultVpnService.EXTRA_ID, idBytes)
                }

                ContextCompat.startForegroundService(requireContext(), serviceIntent)
            } catch (_e: Exception) {
                Log.e("StatusFragment", "Failed to start VPN service", _e)
                isConnecting = false
                isConnected = false
                updateUI()
                tvStatusDetail.text = getString(R.string.status_error_starting, _e.message)
                tvStatusDetail.visibility = View.VISIBLE
            }
        }
    }

    private fun updateUI() {
        val root = view ?: return
        val app = requireContext().applicationContext as VaultApplication
        val connected = isConnected && !isConnecting
        tvStatus.setText(when {
            isConnecting && isConnected -> R.string.status_reconnecting
            isConnecting -> R.string.status_connecting
            isConnected -> R.string.status_on
            else -> R.string.status_off
        })
        btnToggleVpn.setImageResource(if (isConnected) R.drawable.ic_connected else R.drawable.ic_disconnected)
        btnToggleVpn.isEnabled = !isConnecting || isConnected
        btnToggleVpn.alpha = if (btnToggleVpn.isEnabled) 1f else 0.5f
        btnToggleVpn.contentDescription = getString(
            if (isConnected) R.string.status_tap_to_disconnect else R.string.status_tap_to_connect)
        val error = app.currentVpnStatus as? VpnStatusEvent.Error
        tvStatusDetail.text = error?.let { getString(R.string.status_error_prefix, it.message.orEmpty()) }.orEmpty()
        tvStatusDetail.visibility = if (error == null) View.GONE else View.VISIBLE
        duration.visibility = if (connected) View.VISIBLE else View.GONE
        if (connected) {
            duration.base = app.ensureConnectionStarted()
            duration.text = StatusPresentation.duration(android.os.SystemClock.elapsedRealtime() - duration.base)
            if (!isHidden && isResumed) duration.start()
        } else duration.stop()
        root.findViewById<View>(R.id.connectionInfo).visibility = if (connected) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.rowIpv4).visibility = if (currentIp.isNotEmpty()) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.rowIpv6).visibility = if (currentIpv6.isNotEmpty()) View.VISIBLE else View.GONE
        root.findViewById<View>(R.id.ipDivider).visibility =
            if (currentIp.isNotEmpty() || currentIpv6.isNotEmpty()) View.VISIBLE else View.GONE
        tvIpv4Address.text = currentIp
        tvIpv6Address.text = currentIpv6
        renderTrafficStats(app.latestTrafficStats)
    }

    private fun renderTrafficStats(stats: VpnStatusEvent.TrafficStats?) {
        sentPackets.text = (stats?.packetsSent ?: 0).coerceAtLeast(0).toString()
        receivedPackets.text = (stats?.packetsReceived ?: 0).coerceAtLeast(0).toString()
        sentBytes.text = StatusPresentation.bytes(stats?.bytesSent ?: 0)
        receivedBytes.text = StatusPresentation.bytes(stats?.bytesReceived ?: 0)
        sentSpeed.text = "+ " + StatusPresentation.bytes(stats?.sendSpeed ?: 0) + "/s"
        receivedSpeed.text = "+ " + StatusPresentation.bytes(stats?.receiveSpeed ?: 0) + "/s"
    }

    private fun generateDeviceId(): String {
        val id = java.util.UUID.randomUUID().toString().replace("-", "")
        requireContext().getSharedPreferences("vault_prefs", Context.MODE_PRIVATE)
            .edit()
            .putString("device_id", id)
            .commit()

        return id
    }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.isNotEmpty()) { "device_id cannot be empty" }
        require(hex.length % 2 == 0) { "device_id hex string must have even length" }

        val len = hex.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] =
                ((hex[i].digitToInt(16) shl 4) + hex[i + 1].digitToInt(16)).toByte()
        }
        return data
    }

    /**
     * Apply a [VpnStatusEvent] to local state.
     */
    private fun applyVpnEvent(
        event: VpnStatusEvent,
        update: Boolean = true
    ) {
        if (event !is VpnStatusEvent.TrafficStats) {
            VaultFileLogger.event("StatusFragment", "APPLY_EVENT event=$event beforeConnected=$isConnected beforeConnecting=$isConnecting")
        }
        when (event) {
            is VpnStatusEvent.Connected -> {
                isConnected = true
                isConnecting = false
                currentIp = event.ipv4
                currentIpv6 = event.ipv6
                if (update) updateUI()
            }

            is VpnStatusEvent.Reconnecting -> {
                // isConnected also means a service is available to disconnect.
                isConnected = true
                isConnecting = true
                if (update) updateUI()
            }

            is VpnStatusEvent.Disconnected -> {
                isConnected = false
                isConnecting = false
                currentIp = ""
                currentIpv6 = ""
                if (update) updateUI()
            }

            is VpnStatusEvent.Error -> {
                isConnected = false
                isConnecting = false
                currentIp = ""
                currentIpv6 = ""
                if (update) {
                    updateUI()
                    tvStatusDetail.text = getString(R.string.status_error_prefix, event.message.orEmpty())
                }
            }

            is VpnStatusEvent.TrafficStats -> renderTrafficStats(event)
        }
    }

    companion object {
        fun newInstance() = StatusFragment()
    }
}
