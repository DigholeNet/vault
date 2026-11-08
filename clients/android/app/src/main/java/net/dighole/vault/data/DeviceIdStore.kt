// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import android.content.Context
import net.dighole.vault.VaultVpnService
import java.util.UUID

internal class DeviceId(val hex: String, val bytes: ByteArray)

/** Preserve a valid installation ID; repair missing or malformed legacy values once. */
internal object DeviceIdStore {
    @Synchronized
    fun getOrCreate(read: () -> String?, write: (String) -> Unit): DeviceId {
        val saved = read()
        if (saved != null) decode(saved)?.let { return DeviceId(saved, it) }
        val generated = UUID.randomUUID().toString().replace("-", "")
        write(generated)
        return DeviceId(generated, requireNotNull(decode(generated)))
    }

    private fun decode(value: String): ByteArray? {
        if (value.length != 32 || value.any { it.digitToIntOrNull(16) == null }) return null
        return ByteArray(16) { index ->
            ((value[index * 2].digitToInt(16) shl 4) + value[index * 2 + 1].digitToInt(16)).toByte()
        }
    }
}

internal fun Context.deviceId(): DeviceId {
    val prefs = getSharedPreferences(VaultVpnService.PREFS_NAME, Context.MODE_PRIVATE)
    return DeviceIdStore.getOrCreate(
        read = { try { prefs.getString("device_id", null) } catch (_: ClassCastException) { null } },
        write = { check(prefs.edit().putString("device_id", it).commit()) { "Failed to save device ID" } }
    )
}
