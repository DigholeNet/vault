// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageButton
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import net.dighole.vault.data.VaultConfig
import net.dighole.vault.data.readVaultConfig
import net.dighole.vault.data.writeVaultConfig

class ConfigureFragment : Fragment() {

    private lateinit var edtHost: EditText
    private lateinit var edtPort: EditText
    private lateinit var edtPassword: EditText
    private lateinit var edtDns: EditText
    private lateinit var btnSave: ImageButton
    private lateinit var btnCancel: ImageButton

    // Store original values for cancel
    private var originalHost: String = ""
    private var originalPort: String = ""
    private var originalPassword: String = ""
    private var originalDns: String = ""

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_configure, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        edtHost = view.findViewById(R.id.edtHost)
        edtPort = view.findViewById(R.id.edtPort)
        edtPassword = view.findViewById(R.id.edtPassword)
        edtDns = view.findViewById(R.id.edtDns)
        btnSave = view.findViewById(R.id.btnSave)
        btnCancel = view.findViewById(R.id.btnCancel)

        if (savedInstanceState != null) {
            restoreStateFromBundle(savedInstanceState)
        } else {
            loadConfiguration()
        }

        btnSave.setOnClickListener {
            saveConfiguration()
        }

        btnCancel.setOnClickListener {
            cancelConfiguration()
        }
    }

    private fun loadConfiguration() {
        lifecycleScope.launch {
            try {
                val config = requireContext().readVaultConfig()
                originalHost = config.host
                originalPort = config.port.toString()
                originalPassword = config.password
                originalDns = config.dns

                edtHost.setText(originalHost)
                edtPort.setText(originalPort)
                edtPassword.setText(originalPassword)
                edtDns.setText(originalDns)

                Log.d("ConfigureFragment", "Config loaded")
            } catch (_e: Exception) {
                Log.e("ConfigureFragment", "Failed to load configuration", _e)
            }
        }
    }

    private fun saveConfiguration() {
        val host = edtHost.text.toString().trim()
        val portStr = edtPort.text.toString().trim()
        val password = edtPassword.text.toString()
        val dns = edtDns.text.toString().trim()

        if (host.isEmpty()) {
            edtHost.error = getString(R.string.error_host_required)
            return
        }

        // An empty port falls back to the default instead of an error.
        val port: Int
        if (portStr.isEmpty()) {
            port = VaultConfig().port
        } else {
            val parsed = portStr.toIntOrNull()
            if (parsed == null || parsed <= 0 || parsed > 65535) {
                edtPort.error = getString(R.string.error_port_invalid)
                return
            }
            port = parsed
        }

        if (password.isEmpty()) {
            edtPassword.error = getString(R.string.error_password_required)
            return
        }

        // Prevent double-click while saving
        btnSave.isEnabled = false

        lifecycleScope.launch {
            try {
                val newConfig = VaultConfig(
                    host = host,
                    port = port,
                    password = password,
                    dns = dns.ifEmpty { "1.1.1.1,8.8.8.8" }
                )

                Log.d("ConfigureFragment", "Saving config")
                requireContext().writeVaultConfig(newConfig)

                val savedConfig = requireContext().readVaultConfig()
                Log.d("ConfigureFragment", "Config saved and verified")

                if (savedConfig.host != host || savedConfig.port != port) {
                    throw IllegalStateException(
                        "Verification failed: expected host=$host port=$port, " +
                                "got host=${savedConfig.host} port=${savedConfig.port}"
                    )
                }

                // Update original values so cancel works correctly
                originalHost = host
                originalPort = portStr
                originalPassword = password
                originalDns = dns

                Toast.makeText(requireContext(), R.string.config_saved, Toast.LENGTH_SHORT).show()

                (activity as? MainActivity)?.navigateTo(R.id.nav_status)
            } catch (_e: Exception) {
                Log.e("ConfigureFragment", "Failed to save configuration", _e)
                val msg = "Save failed: ${_e.javaClass.simpleName} - ${_e.message}"
                Toast.makeText(requireContext(), msg, Toast.LENGTH_LONG).show()
            } finally {
                btnSave.isEnabled = true
            }
        }
    }

    private fun cancelConfiguration() {
        edtHost.setText(originalHost)
        edtPort.setText(originalPort)
        edtPassword.setText(originalPassword)
        edtDns.setText(originalDns)

        edtHost.error = null
        edtPort.error = null
        edtPassword.error = null

        Toast.makeText(requireContext(), R.string.changes_cancelled, Toast.LENGTH_SHORT).show()

        (activity as? MainActivity)?.navigateTo(R.id.nav_status)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_ORIGINAL_HOST, originalHost)
        outState.putString(KEY_ORIGINAL_PORT, originalPort)
        outState.putString(KEY_ORIGINAL_PASSWORD, originalPassword)
        outState.putString(KEY_ORIGINAL_DNS, originalDns)
        // Also save current input values so they survive rotation
        outState.putString(KEY_INPUT_HOST, edtHost.text.toString())
        outState.putString(KEY_INPUT_PORT, edtPort.text.toString())
        outState.putString(KEY_INPUT_PASSWORD, edtPassword.text.toString())
        outState.putString(KEY_INPUT_DNS, edtDns.text.toString())
    }

    private fun restoreStateFromBundle(bundle: Bundle) {
        originalHost = bundle.getString(KEY_ORIGINAL_HOST, "")
        originalPort = bundle.getString(KEY_ORIGINAL_PORT, "")
        originalPassword = bundle.getString(KEY_ORIGINAL_PASSWORD, "")
        originalDns = bundle.getString(KEY_ORIGINAL_DNS, "")

        edtHost.setText(bundle.getString(KEY_INPUT_HOST, originalHost))
        edtPort.setText(bundle.getString(KEY_INPUT_PORT, originalPort))
        edtPassword.setText(bundle.getString(KEY_INPUT_PASSWORD, originalPassword))
        edtDns.setText(bundle.getString(KEY_INPUT_DNS, originalDns))
        Log.d("ConfigureFragment", "State restored from savedInstanceState")
    }

    companion object {
        private const val KEY_ORIGINAL_HOST = "original_host"
        private const val KEY_ORIGINAL_PORT = "original_port"
        private const val KEY_ORIGINAL_PASSWORD = "original_password"
        private const val KEY_ORIGINAL_DNS = "original_dns"
        private const val KEY_INPUT_HOST = "input_host"
        private const val KEY_INPUT_PORT = "input_port"
        private const val KEY_INPUT_PASSWORD = "input_password"
        private const val KEY_INPUT_DNS = "input_dns"

        fun newInstance() = ConfigureFragment()
    }
}
