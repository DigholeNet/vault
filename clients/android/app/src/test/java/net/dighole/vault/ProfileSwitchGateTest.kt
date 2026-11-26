// SPDX-License-Identifier: MIT
package net.dighole.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileSwitchGateTest {
    @Test
    fun latestRequestWins() {
        val gate = ProfileSwitchGate<String>()
        assertTrue(gate.begin("second"))
        assertFalse(gate.begin("third"))
        assertTrue(gate.closing)
        assertEquals("third", gate.complete())
        assertFalse(gate.closing)
        assertNull(gate.complete())
    }

    @Test
    fun cancelDropsRequest() {
        val gate = ProfileSwitchGate<String>()
        gate.begin("second")
        gate.cancel()
        assertFalse(gate.closing)
        assertNull(gate.complete())
        assertTrue(gate.begin("third"))
    }
}
