// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import android.content.Context
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val TAG = "VaultConfigPrefs"
private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "vault_config")

@Suppress("TooGenericExceptionCaught")
private fun Context.configStore(): VaultConfigStore {
    val secure = SecureStorage(this)
    return VaultConfigStore(
        dataStore = dataStore,
        encrypt = { password ->
            try {
                secure.encryptPassword(password)
            } catch (error: Exception) {
                Log.w(TAG, "Password encryption failed, using app-private plaintext fallback", error)
                throw error
            }
        },
        decrypt = secure::decryptPassword,
        readLegacyPassword = {
            try {
                secure.getPassword()
            } catch (error: Exception) {
                Log.w(TAG, "Legacy password read failed", error)
                throw error
            }
        },
        clearLegacyPassword = {
            try {
                secure.clearLegacyPassword()
            } catch (error: Exception) {
                // The committed DataStore record is authoritative. Cleanup can
                // retry on the next access without undoing a successful save.
                Log.w(TAG, "Legacy password cleanup failed", error)
            }
        }
    )
}

suspend fun Context.readVaultConfig(): VaultConfig = withContext(Dispatchers.IO) {
    configStore().read()
}

suspend fun Context.writeVaultConfig(config: VaultConfig): Unit = withContext(Dispatchers.IO) {
    configStore().write(config)
}
