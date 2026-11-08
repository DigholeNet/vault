// SPDX-License-Identifier: MIT
package net.dighole.vault.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DeviceIdTest {
    @Test fun validId() {
        val saved = "00112233445566778899AABBCCDDEEFF"
        val id = DeviceIdStore.getOrCreate({ saved }, { error("Valid ID must not be rewritten") })
        assertEquals(saved, id.hex)
        assertArrayEquals(ByteArray(16) { (it * 17).toByte() }, id.bytes)
    }

    @Test fun repairId() {
        for (invalid in listOf(null, "", "00", "g".repeat(32), "0".repeat(34))) {
            var saved = invalid
            var writes = 0
            val first = DeviceIdStore.getOrCreate({ saved }) { saved = it; writes++ }
            val next = DeviceIdStore.getOrCreate({ saved }) { error("Repaired ID must remain stable") }
            assertEquals(1, writes)
            assertEquals(32, first.hex.length)
            assertEquals(16, first.bytes.size)
            assertNotEquals(invalid, first.hex)
            assertEquals(first.hex, next.hex)
            assertArrayEquals(first.bytes, next.bytes)
        }
    }

    @Test fun saveFailure() {
        assertThrows(IllegalStateException::class.java) {
            DeviceIdStore.getOrCreate({ null }) { error("Disk failure") }
        }
    }
}
