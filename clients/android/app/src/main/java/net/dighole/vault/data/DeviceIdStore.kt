// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import android.content.Context
import net.dighole.vault.VaultVpnService
import net.dighole.vaultcore.uniffi.generatePeerIdHex
import net.dighole.vaultcore.uniffi.peerIdFromHex

internal class DeviceId(val hex: String, val bytes: ByteArray)

/** Preserve a valid installation ID; repair missing or malformed legacy values once. */
internal object DeviceIdStore {
    @Synchronized
    fun getOrCreate(read: () -> String?, write: (String) -> Unit): DeviceId {
        val saved = read()
        if (saved != null) decode(saved)?.let { return DeviceId(saved, it) }
        val generated = generatePeerIdHex()
        write(generated)
        return DeviceId(generated, requireNotNull(decode(generated)))
    }

    private fun decode(value: String): ByteArray? = runCatching { peerIdFromHex(value) }.getOrNull()
}

internal fun Context.deviceId(): DeviceId {
    val prefs = getSharedPreferences(VaultVpnService.PREFS_NAME, Context.MODE_PRIVATE)
    return DeviceIdStore.getOrCreate(
        read = { try { prefs.getString("device_id", null) } catch (_: ClassCastException) { null } },
        write = { check(prefs.edit().putString("device_id", it).commit()) { "Failed to save device ID" } }
    )
}
