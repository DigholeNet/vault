// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import android.content.Context
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private const val PREFS_NAME = "vault_config"
private const val TAG = "VaultConfigPrefs"

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = PREFS_NAME)

private object Keys {
    val HOST = stringPreferencesKey("host")
    val PORT = intPreferencesKey("port")
    val PASSWORD = stringPreferencesKey("password")
    val DNS = stringPreferencesKey("dns")
}

/**
 * Reads the current [VaultConfig] from preferences.
 *
 * The password is read from [SecureStorage] (Android Keystore-backed
 * encrypted preferences). If that fails or returns null, falls back to
 * the legacy plaintext DataStore entry so existing users are not locked
 * out after migration.
 *
 * Returns defaults if no configuration has been saved yet.
 */
@Suppress("TooGenericExceptionCaught")
suspend fun Context.readVaultConfig(): VaultConfig {
    val securePassword = try {
        SecureStorage(this).getPassword()
    } catch (e: Exception) {
        // SecureStorage may throw various Keystore-related exceptions.
        // We catch broadly so the app can fall back to plaintext and remain usable.
        Log.w(TAG, "SecureStorage read failed, falling back to plaintext", e)
        null
    }
    return dataStore.data.map { prefs ->
        VaultConfig(
            host = prefs[Keys.HOST] ?: "",
            port = prefs[Keys.PORT] ?: VaultConfig().port,
            password = securePassword ?: prefs[Keys.PASSWORD] ?: "",
            dns = prefs[Keys.DNS] ?: ""
        )
    }.first()
}

/**
 * Persists [config] to preferences atomically.
 *
 * The password is stored in [SecureStorage] (encrypted). If Keystore is
 * unavailable, falls back to plaintext DataStore so the app remains
 * functional and the user can reconnect.
 */
@Suppress("TooGenericExceptionCaught")
suspend fun Context.writeVaultConfig(config: VaultConfig) {
    val secureOk = try {
        SecureStorage(this).savePassword(config.password)
        true
    } catch (e: Exception) {
        // SecureStorage may throw various Keystore-related exceptions.
        // We catch broadly so the app can fall back to plaintext and remain usable.
        Log.w(TAG, "SecureStorage write failed, falling back to plaintext", e)
        false
    }
    dataStore.edit { prefs ->
        prefs[Keys.HOST] = config.host
        prefs[Keys.PORT] = config.port
        prefs[Keys.DNS] = config.dns
        if (!secureOk) {
            prefs[Keys.PASSWORD] = config.password
        }
    }
}
