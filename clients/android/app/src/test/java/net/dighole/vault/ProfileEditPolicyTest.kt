// SPDX-License-Identifier: MIT
package net.dighole.vault

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileEditPolicyTest {
    @Test
    fun inactiveProfileCanBeRenamed() {
        assertTrue(canRenameProfile("Home", "Work", active = false))
    }

    @Test
    fun activeProfileKeepsItsName() {
        assertTrue(canRenameProfile("Home", "Home", active = true))
        assertFalse(canRenameProfile("Home", "Work", active = true))
    }
}
