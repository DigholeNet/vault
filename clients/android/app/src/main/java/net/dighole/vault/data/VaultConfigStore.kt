// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

internal object ConfigKeys {
    val SELECTED_PROFILE = stringPreferencesKey("selected_profile")
    val PROFILE_NAMES = stringSetPreferencesKey("profile_names")

    val MTU = stringPreferencesKey("mtu")
    val PROBE_DOMAINS = stringPreferencesKey("probe_domains")
    val HOST = stringPreferencesKey("host")
    val PORT = intPreferencesKey("port")
    val DNS = stringPreferencesKey("dns")
    val DNS_IPV4 = stringPreferencesKey("dns_ipv4")
    val DNS_IPV6 = stringPreferencesKey("dns_ipv6")
    val ENCRYPTED_PASSWORD = stringPreferencesKey("password_encrypted")
    val PASSWORD = stringPreferencesKey("password")
    val PASSWORD_FALLBACK = booleanPreferencesKey("password_fallback")

    val LEGACY = listOf(
        MTU, HOST, PORT, DNS, DNS_IPV4, DNS_IPV6,
        ENCRYPTED_PASSWORD, PASSWORD, PASSWORD_FALLBACK
    )
}

data class VaultProfiles(
    val profiles: List<VaultConfig> = emptyList(),
    val selectedProfileName: String? = null
) {
    val selected: VaultConfig? get() = profiles.firstOrNull { it.name == selectedProfileName }
}

internal class VaultConfigStore(
    private val dataStore: DataStore<Preferences>,
    private val encrypt: (String) -> String,
    private val decrypt: (String) -> String,
    private val clearLegacyPassword: () -> Unit
) {
    suspend fun read(): VaultProfiles {
        var result = VaultProfiles()
        dataStore.edit { prefs ->
            ConfigKeys.LEGACY.forEach { key -> prefs.remove(key) }
            val names = prefs[ConfigKeys.PROFILE_NAMES].orEmpty().sortedBy(String::lowercase)
            val profiles = names.map { name -> readProfile(prefs, name) }
            val selected = prefs[ConfigKeys.SELECTED_PROFILE].takeIf(names::contains) ?: names.firstOrNull()
            if (selected != prefs[ConfigKeys.SELECTED_PROFILE]) {
                if (selected == null) prefs.remove(ConfigKeys.SELECTED_PROFILE)
                else prefs[ConfigKeys.SELECTED_PROFILE] = selected
            }
            result = VaultProfiles(profiles, selected)
        }
        clearLegacyPassword()
        return result
    }

    suspend fun write(config: VaultConfig, originalName: String? = null) {
        dataStore.edit { prefs ->
            val names = prefs[ConfigKeys.PROFILE_NAMES].orEmpty()
            require(config.name.isNotBlank()) { "Profile name is required" }
            require(names.none { it.equals(config.name, ignoreCase = true) && it != originalName }) {
                "A profile with this name already exists"
            }
            val hostLatency = if (originalName != null && matchesEndpoint(prefs, originalName, config.host, config.port)) {
                prefs[latencyKey(originalName)]
            } else null
            if (originalName != null) {
                require(originalName in names) { "Profile does not exist" }
                removeProfile(prefs, originalName)
            }
            writeProfile(prefs, config)
            hostLatency?.let { prefs[latencyKey(config.name)] = it }
            prefs[ConfigKeys.PROFILE_NAMES] = names.filter { it != originalName }.toSet() + config.name
            val selected = prefs[ConfigKeys.SELECTED_PROFILE]
            if (selected == null || selected == originalName) {
                prefs[ConfigKeys.SELECTED_PROFILE] = config.name
            }
            ConfigKeys.LEGACY.forEach { key -> prefs.remove(key) }
        }
        clearLegacyPassword()
    }

    fun observeHostLatencies() = dataStore.data.map { prefs ->
        prefs[ConfigKeys.PROFILE_NAMES].orEmpty().mapNotNull { name ->
            prefs[latencyKey(name)]?.let { name to it }
        }.toMap()
    }.distinctUntilChanged()

    suspend fun recordHostLatency(name: String, host: String, port: Int, milliseconds: Long) {
        dataStore.edit { prefs ->
            if (name in prefs[ConfigKeys.PROFILE_NAMES].orEmpty() && matchesEndpoint(prefs, name, host, port)) {
                prefs[latencyKey(name)] = milliseconds
            }
        }
    }

    private fun matchesEndpoint(prefs: Preferences, name: String, host: String, port: Int): Boolean =
        prefs[stringPreferencesKey(key(name, "host"))] == host &&
            (prefs[intPreferencesKey(key(name, "port"))] ?: VaultConfig().port) == port

    private fun latencyKey(name: String) = longPreferencesKey(key(name, "network_latency_ms"))

    suspend fun select(name: String) {
        dataStore.edit { prefs ->
            require(name in prefs[ConfigKeys.PROFILE_NAMES].orEmpty()) { "Profile does not exist" }
            prefs[ConfigKeys.SELECTED_PROFILE] = name
        }
    }

    suspend fun delete(name: String) {
        dataStore.edit { prefs ->
            val remaining = prefs[ConfigKeys.PROFILE_NAMES].orEmpty() - name
            removeProfile(prefs, name)
            prefs[ConfigKeys.PROFILE_NAMES] = remaining
            if (prefs[ConfigKeys.SELECTED_PROFILE] == name) {
                val next = remaining.minByOrNull(String::lowercase)
                if (next == null) prefs.remove(ConfigKeys.SELECTED_PROFILE)
                else prefs[ConfigKeys.SELECTED_PROFILE] = next
            }
        }
    }

    suspend fun readProbeDomains(): String = dataStore.data.first()[ConfigKeys.PROBE_DOMAINS].orEmpty()

    suspend fun writeProbeDomains(domains: String) {
        dataStore.edit { prefs -> prefs[ConfigKeys.PROBE_DOMAINS] = domains }
    }

    private fun readProfile(prefs: MutablePreferences, name: String): VaultConfig {
        val encrypted = prefs[stringPreferencesKey(key(name, "password_encrypted"))]
        val plaintext = prefs[stringPreferencesKey(key(name, "password"))]
        val fallback = prefs[booleanPreferencesKey(key(name, "password_fallback"))] == true
        val password = when {
            encrypted != null -> decrypt(encrypted)
            plaintext != null && fallback -> plaintext
            else -> ""
        }
        if (encrypted == null && plaintext != null && fallback) storePassword(prefs, name, password)
        return VaultConfig(
            name = name,
            host = prefs[stringPreferencesKey(key(name, "host"))].orEmpty(),
            port = prefs[intPreferencesKey(key(name, "port"))] ?: VaultConfig().port,
            dnsIpv4 = prefs[stringPreferencesKey(key(name, "dns_ipv4"))].orEmpty(),
            dnsIpv6 = prefs[stringPreferencesKey(key(name, "dns_ipv6"))].orEmpty(),
            mtu = prefs[stringPreferencesKey(key(name, "mtu"))].orEmpty(),
            password = password,
            hostLatencyMs = prefs[latencyKey(name)]
        )
    }

    private fun writeProfile(prefs: MutablePreferences, config: VaultConfig) {
        storePassword(prefs, config.name, config.password)
        prefs[stringPreferencesKey(key(config.name, "host"))] = config.host
        prefs[intPreferencesKey(key(config.name, "port"))] = config.port
        prefs[stringPreferencesKey(key(config.name, "dns_ipv4"))] = config.dnsIpv4
        prefs[stringPreferencesKey(key(config.name, "dns_ipv6"))] = config.dnsIpv6
        prefs[stringPreferencesKey(key(config.name, "mtu"))] = config.mtu
    }

    private fun removeProfile(prefs: MutablePreferences, name: String) {
        prefs.remove(latencyKey(name))
        for (field in listOf(
            "host", "port", "dns_ipv4", "dns_ipv6", "mtu", "probe_domains",
            "password_encrypted", "password", "password_fallback"
        )) {
            prefs.remove(stringPreferencesKey(key(name, field)))
            prefs.remove(intPreferencesKey(key(name, field)))
            prefs.remove(booleanPreferencesKey(key(name, field)))
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun storePassword(prefs: MutablePreferences, name: String, password: String) {
        val ciphertext = try {
            encrypt(password)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        }
        val encryptedKey = stringPreferencesKey(key(name, "password_encrypted"))
        val plaintextKey = stringPreferencesKey(key(name, "password"))
        val fallbackKey = booleanPreferencesKey(key(name, "password_fallback"))
        if (ciphertext != null) {
            prefs[encryptedKey] = ciphertext
            prefs.remove(plaintextKey)
            prefs.remove(fallbackKey)
        } else {
            prefs.remove(encryptedKey)
            prefs[plaintextKey] = password
            prefs[fallbackKey] = true
        }
    }

    private fun key(name: String, field: String) = "profile.$name.$field"
}
