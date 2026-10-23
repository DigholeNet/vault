// SPDX-License-Identifier: MIT
package net.dighole.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RecoveryStateTest {
    @Test
    fun singleRecovery() {
        val recovery = RecoveryState()
        var reconnectCalls = 0
        // Repeated watchdog requests must not interrupt the pending handshake.
        repeat(10) {
            if (recovery.begin()) reconnectCalls++
            assertFalse(recovery.completeIfReady(false))
        }
        assertEquals(1, reconnectCalls)
        recovery.onConfigured()
        assertTrue(recovery.completeIfReady(true))
        assertTrue(recovery.begin())
    }

    @Test
    fun sharedRecovery() {
        val recovery = RecoveryState()
        assertTrue(recovery.begin()) // watchdog
        assertFalse(recovery.begin(restart = true)) // debounced network callback
        assertFalse(recovery.completeIfReady(true)) // old TUN still runs before handshake
        recovery.onConfigured()
        assertFalse(recovery.completeIfReady(false)) // async I/O restart is pending
        assertFalse(recovery.begin())
        assertTrue(recovery.completeIfReady(true))
        assertTrue(recovery.begin())
    }

    @Test
    fun offlineRecovery() {
        val recovery = RecoveryState()
        assertTrue(recovery.begin())
        // An arbitrary number of failed native retries never expires recovery.
        repeat(1000) {
            assertFalse(recovery.begin(restart = true))
            assertTrue(recovery.isRecovering())
            assertFalse(recovery.completeIfReady(true))
        }
        recovery.onConfigured()
        assertTrue(recovery.completeIfReady(true))
        assertFalse(recovery.isRecovering())
    }

    @Test
    fun networkWake() {
        val recovery = RecoveryState()
        assertTrue(recovery.begin())
        recovery.onConfigured()
        assertFalse(recovery.completeIfReady(false))
        // Network restoration starts a fresh attempt, but does not emit a
        // second recovery notification or accept the previous configuration.
        assertFalse(recovery.begin(restart = true))
        assertFalse(recovery.completeIfReady(true))
        recovery.onConfigured()
        assertTrue(recovery.completeIfReady(true))
    }

    @Test
    fun resetRecovery() {
        val recovery = RecoveryState()
        assertTrue(recovery.begin())
        recovery.onConfigured()
        assertTrue(recovery.isRecovering())
        recovery.reset()
        assertFalse(recovery.isRecovering())
        assertFalse(recovery.completeIfReady(true))
        assertTrue(recovery.begin())
        assertFalse(recovery.completeIfReady(true))
        recovery.onConfigured()
        assertTrue(recovery.completeIfReady(true))
    }

    @Test
    fun concurrentRecovery() {
        val recovery = RecoveryState()
        val calls = java.util.concurrent.atomic.AtomicInteger()
        val start = java.util.concurrent.CountDownLatch(1)
        val threads = List(16) {
            Thread {
                start.await()
                if (recovery.begin()) calls.incrementAndGet()
            }.apply { start() }
        }
        start.countDown()
        threads.forEach { it.join() }
        assertEquals(1, calls.get())
    }

    @Test
    fun waitForIo() {
        val recovery = RecoveryState()
        var notifications = 0
        assertTrue(recovery.begin())
        // Service defers Connected when configuration belongs to recovery.
        if (!recovery.onConfigured()) notifications++
        repeat(3) {
            if (recovery.completeIfReady(false)) notifications++
        }
        assertEquals(0, notifications)
        if (recovery.completeIfReady(true)) notifications++
        if (recovery.completeIfReady(true)) notifications++
        assertEquals(1, notifications)
    }

    @Test
    fun initialConnection() {
        val recovery = RecoveryState()
        assertFalse(recovery.onConfigured())
        assertFalse(recovery.completeIfReady(true))
    }

}
