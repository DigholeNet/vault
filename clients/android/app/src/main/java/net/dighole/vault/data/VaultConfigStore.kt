// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.CancellationException

internal object ConfigKeys {
    val HOST = stringPreferencesKey("host")
    val PORT = intPreferencesKey("port")
    val DNS = stringPreferencesKey("dns")
    val ENCRYPTED_PASSWORD = stringPreferencesKey("password_encrypted")
    val PASSWORD = stringPreferencesKey("password")
    val PASSWORD_FALLBACK = booleanPreferencesKey("password_fallback")
}

/** One DataStore transaction owns the complete config, including encrypted credentials. */
internal class VaultConfigStore(
    private val dataStore: DataStore<Preferences>,
    private val encrypt: (String) -> String,
    private val decrypt: (String) -> String,
    private val readLegacyPassword: () -> String?,
    private val clearLegacyPassword: () -> Unit
) {
    suspend fun read(): VaultConfig {
        var config = VaultConfig()
        var hasCredential = false
        dataStore.edit { prefs ->
            val encrypted = prefs[ConfigKeys.ENCRYPTED_PASSWORD]
            val plaintext = prefs[ConfigKeys.PASSWORD]
            val password = when {
                encrypted != null -> decrypt(encrypted)
                plaintext != null && prefs[ConfigKeys.PASSWORD_FALLBACK] == true -> plaintext
                else -> legacyOrPlaintext(plaintext)
            }
            hasCredential = password != null
            // Migration and fallback recovery run under the same transaction
            // as reads/writes. A failed disk commit leaves the old record intact.
            if (encrypted == null && password != null) storePassword(prefs, password)
            config = VaultConfig(
                host = prefs[ConfigKeys.HOST] ?: "",
                port = prefs[ConfigKeys.PORT] ?: VaultConfig().port,
                dns = prefs[ConfigKeys.DNS] ?: VaultConfig().dns,
                password = password.orEmpty()
            )
        }
        if (hasCredential) clearLegacyPassword()
        return config
    }

    suspend fun write(config: VaultConfig) {
        dataStore.edit { prefs ->
            storePassword(prefs, config.password)
            prefs[ConfigKeys.HOST] = config.host
            prefs[ConfigKeys.PORT] = config.port
            prefs[ConfigKeys.DNS] = config.dns
        }
        clearLegacyPassword()
    }

    @Suppress("TooGenericExceptionCaught")
    private fun legacyOrPlaintext(plaintext: String?): String? = try {
        readLegacyPassword() ?: plaintext
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (error: Exception) {
        // Do not turn an unreadable credential into an empty password or
        // delete it. Old plaintext remains a recovery copy when available.
        plaintext ?: throw error
    }

    @Suppress("TooGenericExceptionCaught")
    private fun storePassword(prefs: MutablePreferences, password: String) {
        // Encryption has no credential-file side effect. Only the DataStore
        // commit publishes a new password together with its host/port/DNS.
        val ciphertext = try {
            encrypt(password)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        }
        if (ciphertext != null) {
            prefs[ConfigKeys.ENCRYPTED_PASSWORD] = ciphertext
            prefs.remove(ConfigKeys.PASSWORD)
            prefs.remove(ConfigKeys.PASSWORD_FALLBACK)
        } else {
            prefs.remove(ConfigKeys.ENCRYPTED_PASSWORD)
            prefs[ConfigKeys.PASSWORD] = password
            prefs[ConfigKeys.PASSWORD_FALLBACK] = true
        }
    }
}
