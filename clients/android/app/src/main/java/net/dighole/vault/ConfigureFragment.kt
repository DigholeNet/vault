// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.content.Intent
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.LineBreakConfigSpan
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import net.dighole.vault.data.VaultConfig
import net.dighole.vault.data.VaultProfiles
import net.dighole.vault.data.deleteVaultProfile
import net.dighole.vault.data.deviceId
import net.dighole.vault.data.observeVaultHostLatencies
import net.dighole.vault.data.readVaultProfiles
import net.dighole.vault.data.selectVaultProfile
import net.dighole.vault.data.writeVaultConfig
import java.text.NumberFormat

class ConfigureFragment : Fragment() {
    private var fields = emptyList<EditText>()
    private var profiles = VaultProfiles()
    private var originalName: String? = null
    private var saving = false
    private var loaded = false
    private var loading = false
    private var editing = false
    private var opensNewProfile = false

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, state: Bundle?): View =
        inflater.inflate(R.layout.fragment_configure, container, false)

    override fun onViewCreated(view: View, state: Bundle?) {
        fields = listOf(
            R.id.edtProfileName, R.id.edtHost, R.id.edtPort, R.id.edtPassword,
            R.id.edtMtu, R.id.edtDnsIpv4, R.id.edtDnsIpv6
        ).map { view.findViewById(it) }
        view.findViewById<EditText>(R.id.edtId).apply {
            try {
                setText(requireContext().deviceId().hex)
            } catch (_: IllegalStateException) {
                setText(R.string.config_load_failed)
            }
        }
        LanguageSelector(this, view.findViewById(R.id.languageSpinner)).bind()
        fields.forEach { field ->
            field.doAfterTextChanged { if (loaded && !loading) updateValidation() }
            (activity as? MainActivity)?.dismissKeyboardOnDone(field)
        }
        view.findViewById<View>(R.id.action_save).setOnClickListener { save() }
        view.findViewById<View>(R.id.action_back).setOnClickListener { setEditing(false) }
        view.findViewById<View>(R.id.action_add_profile).setOnClickListener { editNewProfile() }
        view.findViewById<View>(R.id.action_delete_profile).setOnClickListener { confirmDelete() }
        parentFragmentManager.setFragmentResultListener(NEW_PROFILE_REQUEST, viewLifecycleOwner) { _, _ ->
            if (loaded) editNewProfile() else opensNewProfile = true
        }
        loadConfiguration(state)
    }

    private fun loadConfiguration(state: Bundle?) {
        if (loading) return
        loading = true
        fields.forEach { it.isEnabled = false }
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                profiles = requireContext().readVaultProfiles()
                originalName = if (state?.getBoolean("editingNew") == true) {
                    null
                } else {
                    state?.getString("originalName") ?: profiles.selectedProfileName
                }
                val draft = state?.getStringArrayList("draft")?.takeIf { it.size == fields.size }
                if (draft != null) fields.zip(draft).forEach { (field, value) -> field.setText(value) }
                else showProfile(originalName)
                loaded = true
                observeHostLatencies()
                if (opensNewProfile) {
                    opensNewProfile = false
                    editNewProfile()
                } else {
                    setEditing(state?.getBoolean("editing") == true)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                view?.findViewById<TextView>(R.id.profileEmpty)?.setText(R.string.config_load_failed)
                view?.findViewById<TextView>(R.id.tvSaveStatus)?.setText(R.string.config_load_failed)
            } finally {
                loading = false
                updateValidation()
            }
        }
    }

    private fun renderProfiles() {
        val container = view?.findViewById<ViewGroup>(R.id.profileRows) ?: return
        val numberFormat = NumberFormat.getIntegerInstance(resources.configuration.locales[0])
        container.removeAllViews()
        profiles.profiles.forEach { profile ->
            val row = layoutInflater.inflate(R.layout.item_profile, container, false)
            row.findViewById<TextView>(R.id.profileName).text = profile.name
            row.findViewById<TextView>(R.id.profileServer).also { label ->
                val address = "${profile.host}:${profile.port}"
                val latency = profile.hostLatencyMs
                label.text = if (latency == null) {
                    "$address · --"
                } else {
                    SpannableStringBuilder("$address · ").apply {
                        append(
                            "${numberFormat.format(latency)} ms",
                            ForegroundColorSpan(container.context.getColor(R.color.vault_blue)),
                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                        )
                        setSpan(
                            LineBreakConfigSpan.createNoBreakSpan(),
                            address.length + 1, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                        )
                    }
                }
            }
            val selected = profile.name == profiles.selectedProfileName
            row.findViewById<View>(R.id.profileSelectedGroup).visibility = if (selected) View.VISIBLE else View.GONE
            (row as com.google.android.material.card.MaterialCardView).strokeColor =
                androidx.core.content.ContextCompat.getColor(
                    requireContext(),
                    if (selected) R.color.vault_profile_selected_outline else R.color.vault_outline
                )
            row.findViewById<View>(R.id.profileUse).visibility = if (selected) View.GONE else View.VISIBLE
            row.findViewById<View>(R.id.profileEdit).setOnClickListener { openProfile(profile.name) }
            row.findViewById<View>(R.id.profileUse).setOnClickListener { useProfile(profile.name) }
            container.addView(row)
        }
        view?.findViewById<TextView>(R.id.profileEmpty)?.visibility =
            if (profiles.profiles.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun openProfile(name: String) {
        if (!loaded) return
        showProfile(name)
        setEditing(true)
    }

    private fun useProfile(name: String) {
        val app = requireContext().applicationContext as VaultApplication
        val running = app.activeProfileName ?: app.requestedProfileName
        if (running != null && running != name) {
            com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.switch_profile)
                .setMessage(getString(R.string.switch_profile_confirmation, name))
                .setPositiveButton(R.string.disconnect_and_connect) { _, _ -> selectProfileForConnection(name, true) }
                .setNegativeButton(R.string.cancel_description, null)
                .show()
        } else {
            selectProfileForConnection(name, false)
        }
    }

    private fun selectProfileForConnection(name: String, connect: Boolean) {
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                requireContext().selectVaultProfile(name)
                profiles = requireContext().readVaultProfiles()
                renderProfiles()
                if (connect) {
                    val intent = Intent(requireContext(), VaultVpnService::class.java).apply {
                        action = VaultVpnService.ACTION_CONNECT
                        putExtra(VaultVpnService.EXTRA_ID, requireContext().deviceId().bytes)
                        putExtra(VaultVpnService.EXTRA_PROFILE_NAME, name)
                    }
                    androidx.core.content.ContextCompat.startForegroundService(requireContext(), intent)
                    (activity as? MainActivity)?.navigateTo(R.id.nav_status)
                }
            } catch (_: Exception) {
                showMessage(getString(R.string.config_save_failed))
            }
        }
    }

    private fun showProfile(name: String?) {
        val config = profiles.profiles.firstOrNull { it.name == name }
        originalName = config?.name
        setFields(config ?: VaultConfig())
    }

    private fun editNewProfile() {
        if (!loaded) return
        originalName = null
        setFields(VaultConfig())
        setEditing(true)
        fields.firstOrNull()?.requestFocus()
    }

    private fun setEditing(value: Boolean) {
        if (editing && !value) (activity as? MainActivity)?.dismissInputKeyboard()
        editing = value
        (activity as? MainActivity)?.setProfileEditorVisible(value && !isHidden)
        view?.findViewById<View>(R.id.profileList)?.visibility = if (value) View.GONE else View.VISIBLE
        view?.findViewById<View>(R.id.profileEditor)?.visibility = if (value) View.VISIBLE else View.GONE
        if (value) {
            updateValidation()
        } else {
            renderProfiles()
        }
    }

    fun navigateBack(): Boolean {
        if (!editing) return false
        setEditing(false)
        return true
    }

    private fun setFields(config: VaultConfig) {
        loading = true
        val values = listOf(
            config.name, config.host, config.port.toString(), config.password, config.mtu,
            config.dnsIpv4, config.dnsIpv6
        )
        fields.zip(values).forEach { (field, value) -> field.setText(value) }
        loading = false
    }

    private fun isActiveProfile(name: String? = originalName): Boolean {
        val app = requireContext().applicationContext as VaultApplication
        val runningName = app.activeProfileName ?: app.requestedProfileName
        return name != null && name == runningName
    }

    private fun updateValidation(): Boolean {
        if (fields.isEmpty()) return false
        val active = isActiveProfile()
        fields.forEach { it.isEnabled = !saving && loaded && editing }
        fields[0].isEnabled = !saving && loaded && editing && !active
        val errors = validationErrors(fields.map { it.text.toString() })
        fields.zip(errors).forEach { (field, error) ->
            (field.parent.parent as? com.google.android.material.textfield.TextInputLayout)?.error =
                if (loaded && editing && error != null) getString(error) else null
        }
        view?.findViewById<View>(R.id.action_save)?.isEnabled =
            loaded && editing && !saving && errors.all { it == null }
        view?.findViewById<View>(R.id.action_delete_profile)?.isEnabled = originalName != null && !active && !saving
        return loaded && errors.all { it == null }
    }

    private fun validationErrors(v: List<String>) = listOf(
        if (v[0].isNotBlank()) null else R.string.error_profile_name_required,
        if (SettingsValidation.server(v[1].trim())) null else R.string.error_host_invalid,
        if (v[2].toIntOrNull() in 1..65535) null else R.string.error_port_invalid,
        if (v[3].isNotEmpty()) null else R.string.error_password_required,
        if (SettingsValidation.mtu(v[4])) null else R.string.error_mtu,
        if (SettingsValidation.dns(v[5], ipv6 = false)) null else R.string.error_dns_ipv4,
        if (SettingsValidation.dns(v[6], ipv6 = true)) null else R.string.error_dns_ipv6
    )

    fun save() {
        if (saving || !updateValidation()) return
        (activity as? MainActivity)?.dismissInputKeyboard()
        val v = fields.map { it.text.toString() }
        val config = VaultConfig(
            name = v[0].trim(), host = v[1].trim(), port = v[2].toInt(), password = v[3],
            mtu = v[4].trim(), dnsIpv4 = v[5].trim(), dnsIpv6 = v[6].trim()
        )
        if (!canRenameProfile(originalName, config.name, isActiveProfile())) {
            showActiveProfileError()
            return
        }
        saving = true
        updateValidation()
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                if (!canRenameProfile(originalName, config.name, isActiveProfile())) {
                    showActiveProfileError()
                    return@launch
                }
                requireContext().writeVaultConfig(config, originalName)
                originalName = config.name
                profiles = requireContext().readVaultProfiles()
                setEditing(false)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: IllegalArgumentException) {
                showMessage(error.message ?: getString(R.string.config_save_failed))
            } catch (_: Exception) {
                showMessage(getString(R.string.config_save_failed))
            } finally {
                saving = false
                updateValidation()
            }
        }
    }

    private fun confirmDelete() {
        val name = originalName ?: return
        (activity as? MainActivity)?.dismissInputKeyboard()
        if (isActiveProfile(name)) {
            showActiveProfileError()
            return
        }
        com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
            .setMessage(getString(R.string.delete_profile_confirmation, name))
            .setPositiveButton(R.string.delete_profile) { _, _ -> deleteProfile(name) }
            .setNegativeButton(R.string.cancel_description, null).show()
    }

    private fun deleteProfile(name: String) {
        if (isActiveProfile(name)) {
            showActiveProfileError()
            return
        }
        viewLifecycleOwner.lifecycleScope.launch {
            if (isActiveProfile(name)) {
                showActiveProfileError()
                return@launch
            }
            try {
                requireContext().deleteVaultProfile(name)
                profiles = requireContext().readVaultProfiles()
                originalName = profiles.selectedProfileName
                setEditing(false)
            } catch (_: Exception) {
                showMessage(getString(R.string.config_save_failed))
            }
        }
    }

    private fun showActiveProfileError() {
        updateValidation()
        showMessage(getString(R.string.error_profile_in_use))
    }

    override fun onResume() {
        super.onResume()
        if (fields.isNotEmpty()) updateValidation()
    }

    override fun onHiddenChanged(hidden: Boolean) {
        super.onHiddenChanged(hidden)
        (activity as? MainActivity)?.setProfileEditorVisible(editing && !hidden)
        if (!hidden && fields.isNotEmpty()) updateValidation()
    }

    private fun observeHostLatencies() {
        val context = requireContext()
        viewLifecycleOwner.lifecycleScope.launch {
            context.observeVaultHostLatencies()
                .map { context.readVaultProfiles() }
                .catch { android.util.Log.w("ConfigureFragment", "Could not refresh host latency", it) }
                .collect { updated ->
                    if (updated != profiles) {
                        profiles = updated
                        if (!editing) renderProfiles()
                    }
                }
        }
    }

    private fun showMessage(message: String) {
        com.google.android.material.snackbar.Snackbar.make(
            requireView(), message, com.google.android.material.snackbar.Snackbar.LENGTH_LONG
        ).show()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (loaded) {
            outState.putBoolean("editing", editing)
            outState.putString("originalName", originalName)
            outState.putBoolean("editingNew", editing && originalName == null)
            if (editing) outState.putStringArrayList("draft", ArrayList(fields.map { it.text.toString() }))
        }
    }

    override fun onDestroyView() {
        fields = emptyList()
        loaded = false
        editing = false
        super.onDestroyView()
    }

    companion object {
        const val NEW_PROFILE_REQUEST = "newProfile"
        fun newInstance() = ConfigureFragment()
    }
}
