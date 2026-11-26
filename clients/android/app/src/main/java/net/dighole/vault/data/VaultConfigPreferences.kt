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
        clearLegacyPassword = {
            try {
                secure.clearLegacyPassword()
            } catch (error: Exception) {
                Log.w(TAG, "Legacy password cleanup failed", error)
            }
        }
    )
}

suspend fun Context.readVaultProfiles(): VaultProfiles = withContext(Dispatchers.IO) {
    configStore().read()
}

suspend fun Context.readVaultConfig(profileName: String? = null): VaultConfig = withContext(Dispatchers.IO) {
    val store = configStore().read()
    if (profileName == null) store.selected else store.profiles.firstOrNull { it.name == profileName }
} ?: VaultConfig()

suspend fun Context.writeVaultConfig(config: VaultConfig, originalName: String? = null): Unit =
    withContext(Dispatchers.IO) {
        configStore().write(config, originalName)
    }

suspend fun Context.selectVaultProfile(name: String): Unit = withContext(Dispatchers.IO) {
    configStore().select(name)
}

suspend fun Context.deleteVaultProfile(name: String): Unit = withContext(Dispatchers.IO) {
    configStore().delete(name)
}

suspend fun Context.readProbeDomains(): String = withContext(Dispatchers.IO) {
    configStore().readProbeDomains()
}

suspend fun Context.writeProbeDomains(domains: String): Unit = withContext(Dispatchers.IO) {
    configStore().writeProbeDomains(domains)
}
