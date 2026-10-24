// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.core.content.edit
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import net.dighole.vault.data.VaultConfig
import net.dighole.vault.data.readVaultConfig
import net.dighole.vault.data.writeVaultConfig

class ConfigureFragment : Fragment() {
    private var fields = emptyList<EditText>()
    private var saving = false
    private var loaded = false
    private var loading = false
    private var saved = false

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, state: Bundle?): View =
        inflater.inflate(R.layout.fragment_configure, container, false)

    override fun onViewCreated(view: View, state: Bundle?) {
        fields = listOf(R.id.edtHost, R.id.edtPort, R.id.edtPassword, R.id.edtMtu,
            R.id.edtDns, R.id.edtProbeDomains).map { view.findViewById(it) }
        val prefs = requireContext().getSharedPreferences(VaultVpnService.PREFS_NAME, 0)
        val id = prefs.getString("device_id", null) ?: java.util.UUID.randomUUID().toString()
            .replace("-", "").also { value -> prefs.edit(commit = true) { putString("device_id", value) } }
        view.findViewById<EditText>(R.id.edtId).setText(id)
        LanguageSelector(this, view.findViewById(R.id.languageSpinner)).bind()
        fields.forEach { it.doAfterTextChanged { saved = false; updateValidation() } }
        view.findViewById<com.google.android.material.button.MaterialButton>(R.id.action_save).setOnClickListener { save() }
        loadConfiguration(state)
    }

    private fun loadConfiguration(state: Bundle?) {
        if (loading) return
        loading = true
        fields.forEach { it.isEnabled = false }
        view?.findViewById<View>(R.id.action_save)?.isEnabled = false
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val config = requireContext().readVaultConfig()
                val values = state?.getStringArrayList("draft") ?: arrayListOf(config.host,
                    config.port.toString(), config.password, config.mtu, config.dns, config.probeDomains)
                fields.zip(values).forEach { (field, value) -> field.setText(value) }
                loaded = true
                updateValidation()
            } catch (cancelled: CancellationException) { throw cancelled
            } catch (_: Exception) {
                view?.findViewById<TextView>(R.id.tvSaveStatus)?.setText(R.string.config_load_failed)
            } finally { loading = false }
        }
    }

    private fun updateValidation(): Boolean {
        if (fields.isEmpty()) return false
        fields.forEach { it.isEnabled = !saving && loaded }
        val v = fields.map { it.text.toString() }
        val errors = listOf(
            if (SettingsValidation.server(v[0].trim())) null else R.string.error_host_invalid,
            if (v[1].toIntOrNull() in 1..65535) null else R.string.error_port_invalid,
            if (v[2].isNotEmpty()) null else R.string.error_password_required,
            if (v[3].isBlank() || v[3].trim().toIntOrNull() in 1280..1427) null else R.string.error_mtu,
            if (SettingsValidation.dns(v[4])) null else R.string.error_dns,
            if (SettingsValidation.domains(v[5])) null else R.string.error_probe
        )
        fields.zip(errors).forEach { (field, error) ->
            (field.parent.parent as? com.google.android.material.textfield.TextInputLayout)?.error =
                if (loaded && error != null) getString(error) else null
        }
        view?.findViewById<View>(R.id.action_save)?.isEnabled = loaded && !saving && errors.all { it == null }
        view?.findViewById<TextView>(R.id.tvSaveStatus)?.setText(
            if (saved) R.string.config_saved_next else R.string.save_hint)
        return loaded && errors.all { it == null }
    }

    fun save() {
        if (saving || !updateValidation()) return
        val v = fields.map { it.text.toString() }
        val config = VaultConfig(host = v[0].trim(), port = v[1].toInt(), password = v[2],
            mtu = v[3].trim(), dns = v[4].trim(), probeDomains = v[5].trim())
        saving = true
        updateValidation()
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                requireContext().writeVaultConfig(config)
                saved = true
            } catch (cancelled: CancellationException) { throw cancelled
            } catch (_: Exception) {
                com.google.android.material.snackbar.Snackbar.make(requireView(),
                    R.string.config_save_failed, com.google.android.material.snackbar.Snackbar.LENGTH_LONG).show()
            } finally { saving = false; updateValidation() }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (loaded) outState.putStringArrayList("draft", ArrayList(fields.map { it.text.toString() }))
    }

    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        if (!hidden && fields.isNotEmpty()) {
            if (!loaded) loadConfiguration(null) else updateValidation()
        }
    }

    override fun onDestroyView() {
        fields = emptyList()
        loaded = false
        super.onDestroyView()
    }

    companion object { fun newInstance() = ConfigureFragment() }
}
