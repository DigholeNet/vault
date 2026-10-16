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
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import net.dighole.vault.VaultVpnService.Companion.PREFS_NAME
import java.util.Locale
import net.dighole.vault.data.readVaultConfig

class StatusFragment : Fragment() {

    private lateinit var btnToggleVpn: ImageButton
    private lateinit var tvStatus: TextView
    private lateinit var tvStatusDetail: TextView
    private lateinit var tvIpv4Address: TextView
    private lateinit var tvIpv6Address: TextView
    private lateinit var tvSentStats: TextView
    private lateinit var tvReceivedStats: TextView
    private lateinit var progressBar: ProgressBar

    private var isConnected = false
    private var isConnecting = false
    private var currentIp: String = ""
    private var currentIpv6: String = ""

    // Track last displayed text to avoid unnecessary updates (prevents flickering)
    private var lastSentText: String = ""
    private var lastReceivedText: String = ""

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

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_IS_CONNECTED, isConnected)
        outState.putBoolean(KEY_IS_CONNECTING, isConnecting)
        outState.putString(KEY_CURRENT_IP, currentIp)
        outState.putString(KEY_CURRENT_IPV6, currentIpv6)
        outState.putString(KEY_LAST_SENT_TEXT, lastSentText)
        outState.putString(KEY_LAST_RECEIVED_TEXT, lastReceivedText)
        Log.d("StatusFragment", "onSaveInstanceState: connected=$isConnected")
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
        tvSentStats = view.findViewById(R.id.tvSentStats)
        tvReceivedStats = view.findViewById(R.id.tvReceivedStats)
        progressBar = view.findViewById(R.id.progressBar)

        btnToggleVpn.setOnClickListener {
            if (isConnected) {
                disconnectVpn()
            } else {
                connectVpn()
            }
        }

        // Restore state from savedInstanceState (rotation / process death)
        // or from the application-wide cache (fresh start while service is running).
        restoreUiState(savedInstanceState)

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

        val wasConnected = prefs.getBoolean("vpn_connected", false)

        if (wasConnected) {
            val isServiceRunning = isVpnServiceRunning()
            if (!isServiceRunning) {
                // Service was killed (e.g., device reboot), clear stale state
                Log.d("StatusFragment", "Service was killed, clearing stale state")
                prefs.edit().apply {
                    putBoolean("vpn_connected", false)
                    putBoolean("vpn_connecting", false)
                    putString("vpn_assigned_ipv4", "")
                    putString("vpn_assigned_ipv6", "")
                    commit()
                }
                isConnected = false
                isConnecting = false
                currentIp = ""
                currentIpv6 = ""
            } else {
                isConnected = true
                isConnecting = false
                currentIp = prefs.getString("vpn_assigned_ipv4", "") ?: ""
                currentIpv6 = prefs.getString("vpn_assigned_ipv6", "") ?: ""
            }
        } else {
            isConnected = false
            isConnecting = false
            currentIp = ""
            currentIpv6 = ""
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

    private fun saveStateToPrefs() {
        requireContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().apply {
                putBoolean("vpn_connected", isConnected)
                putBoolean("vpn_connecting", isConnecting)
                putString("vpn_assigned_ipv4", currentIp)
                putString("vpn_assigned_ipv6", currentIpv6)
                commit()
            }

        Log.d(
            "StatusFragment",
            "State saved: connected=$isConnected, connecting=$isConnecting, ipv4=$currentIp, ipv6=$currentIpv6"
        )
    }

    override fun onPause() {
        super.onPause()
        saveStateToPrefs()
    }

    private fun connectVpn() {
        lifecycleScope.launch {
            try {
                val config = requireContext().readVaultConfig()
                Log.d("StatusFragment", "Config loaded for connect")

                if (config.host.isEmpty() || config.password.isEmpty()) {
                    tvStatusDetail.text = getString(R.string.status_configure_first)
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
            }
        }
    }

    private fun updateUI() {
        Log.d(
            "StatusFragment",
            "updateUI: isConnected=$isConnected, isConnecting=$isConnecting, ip=$currentIp"
        )
        when {
            isConnecting -> {
                btnToggleVpn.setImageResource(R.drawable.ic_disconnected)
                btnToggleVpn.isEnabled = false
                tvStatus.text = getString(R.string.status_connecting)
                tvStatus.setTextColor(
                    ContextCompat.getColor(
                        requireContext(),
                        android.R.color.holo_orange_dark
                    )
                )
                tvStatusDetail.text = getString(R.string.status_please_wait)
                tvIpv4Address.visibility = View.GONE
                tvIpv6Address.visibility = View.GONE
                progressBar.visibility = View.VISIBLE
            }

            isConnected -> {
                btnToggleVpn.setImageResource(R.drawable.ic_connected)
                btnToggleVpn.isEnabled = true
                tvStatus.text = getString(R.string.status_on)
                tvStatus.setTextColor(
                    ContextCompat.getColor(
                        requireContext(),
                        android.R.color.holo_green_dark
                    )
                )
                tvStatusDetail.text = getString(R.string.status_tap_to_disconnect)

                if (currentIp.isNotEmpty()) {
                    tvIpv4Address.text = getString(R.string.ip_format, currentIp)
                    tvIpv4Address.visibility = View.VISIBLE
                } else {
                    tvIpv4Address.visibility = View.GONE
                }

                if (currentIpv6.isNotEmpty()) {
                    tvIpv6Address.text = getString(R.string.ipv6_format, currentIpv6)
                    tvIpv6Address.visibility = View.VISIBLE
                } else {
                    tvIpv6Address.visibility = View.GONE
                }

                tvSentStats.visibility = View.VISIBLE
                tvReceivedStats.visibility = View.VISIBLE
                progressBar.visibility = View.GONE
            }

            else -> {
                btnToggleVpn.setImageResource(R.drawable.ic_disconnected)
                btnToggleVpn.isEnabled = true
                tvStatus.text = getString(R.string.status_off)
                tvStatus.setTextColor(
                    ContextCompat.getColor(
                        requireContext(),
                        android.R.color.holo_red_dark
                    )
                )
                tvStatusDetail.text = getString(R.string.status_tap_to_connect)
                tvIpv4Address.visibility = View.GONE
                tvIpv6Address.visibility = View.GONE
                tvSentStats.visibility = View.GONE
                tvReceivedStats.visibility = View.GONE
                progressBar.visibility = View.GONE
            }
        }
    }

    private fun updateTrafficStats(
        bytesSent: Long,
        bytesReceived: Long,
        sendSpeed: Long,
        receiveSpeed: Long
    ) {
        val sentStr = formatBytes(bytesSent)
        val receivedStr = formatBytes(bytesReceived)
        val sendSpeedStr = formatBytes(sendSpeed)
        val receiveSpeedStr = formatBytes(receiveSpeed)

        val newSentText = getString(R.string.traffic_sent, sentStr, sendSpeedStr)
        val newReceivedText = getString(R.string.traffic_received, receivedStr, receiveSpeedStr)

        // Only update if text actually changed (prevents flickering)
        if (newSentText != lastSentText) {
            tvSentStats.text = newSentText
            lastSentText = newSentText
        }
        if (newReceivedText != lastReceivedText) {
            tvReceivedStats.text = newReceivedText
            lastReceivedText = newReceivedText
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1_073_741_824 -> "%.2f GB".format(Locale.ROOT, bytes / 1_073_741_824.0)
            bytes >= 1_048_576 -> "%.2f MB".format(Locale.ROOT, bytes / 1_048_576.0)
            bytes >= 1_024 -> "%.2f KB".format(Locale.ROOT, bytes / 1_024.0)
            else -> "$bytes B"
        }
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
     * Restore UI state from [savedInstanceState] or the application-level cache.
     */
    private fun restoreUiState(savedInstanceState: Bundle?) {
        if (savedInstanceState != null) {
            isConnected = savedInstanceState.getBoolean(KEY_IS_CONNECTED, false)
            isConnecting = savedInstanceState.getBoolean(KEY_IS_CONNECTING, false)
            currentIp = savedInstanceState.getString(KEY_CURRENT_IP, "")
            currentIpv6 = savedInstanceState.getString(KEY_CURRENT_IPV6, "")
            lastSentText = savedInstanceState.getString(KEY_LAST_SENT_TEXT, "")
            lastReceivedText = savedInstanceState.getString(KEY_LAST_RECEIVED_TEXT, "")
            Log.d("StatusFragment", "State restored from savedInstanceState")
            updateUI()
            return
        }

        val app = requireContext().applicationContext as? VaultApplication
        app?.currentVpnStatus?.let { event ->
            if (event !is VpnStatusEvent.TrafficStats) {
                applyVpnEvent(event, saveToPrefs = false, update = false)
                Log.d("StatusFragment", "State restored from VaultApplication cache")
            }
        }
        updateUI()
    }

    /**
     * Apply a [VpnStatusEvent] to local state.
     */
    private fun applyVpnEvent(
        event: VpnStatusEvent,
        saveToPrefs: Boolean = true,
        update: Boolean = true
    ) {
        when (event) {
            is VpnStatusEvent.Connected -> {
                isConnected = true
                isConnecting = false
                currentIp = event.ipv4
                currentIpv6 = event.ipv6
                if (saveToPrefs) saveStateToPrefs()
                if (update) updateUI()
            }

            is VpnStatusEvent.Disconnected -> {
                isConnected = false
                isConnecting = false
                currentIp = ""
                currentIpv6 = ""
                if (saveToPrefs) saveStateToPrefs()
                if (update) updateUI()
            }

            is VpnStatusEvent.Error -> {
                isConnected = false
                isConnecting = false
                currentIp = ""
                currentIpv6 = ""
                if (saveToPrefs) saveStateToPrefs()
                if (update) updateUI()
            }

            is VpnStatusEvent.TrafficStats -> {
                updateTrafficStats(
                    event.bytesSent,
                    event.bytesReceived,
                    event.sendSpeed,
                    event.receiveSpeed
                )
            }
        }
    }

    companion object {
        private const val KEY_IS_CONNECTED = "is_connected"
        private const val KEY_IS_CONNECTING = "is_connecting"
        private const val KEY_CURRENT_IP = "current_ip"
        private const val KEY_CURRENT_IPV6 = "current_ipv6"
        private const val KEY_LAST_SENT_TEXT = "last_sent_text"
        private const val KEY_LAST_RECEIVED_TEXT = "last_received_text"

        fun newInstance() = StatusFragment()
    }
}
