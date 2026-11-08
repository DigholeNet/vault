package net.dighole.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StatusPresentationTest {
    @Test fun durationPastOneDay() {
        assertEquals("00:00:00", StatusPresentation.duration(-1))
        assertEquals("00:00:09", StatusPresentation.duration(9999))
        assertEquals("01:01:01", StatusPresentation.duration(3661000))
        assertEquals("25:00:00", StatusPresentation.duration(90000000))
    }

    @Test fun trafficFormatting() {
        assertEquals("0.00 B", StatusPresentation.bytes(0))
        assertEquals("1.00 KB", StatusPresentation.bytes(1024))
        assertEquals("1.50 MB", StatusPresentation.bytes(1572864))
        assertEquals("1.00 TB", StatusPresentation.bytes(1099511627776))
    }

    @Test fun clockAcrossReconnects() {
        val clock = ConnectionClock()
        assertNull(clock.startedAt)
        assertEquals(1000L, clock.connected(1000))
        assertEquals(1000L, clock.connected(9000))
        clock.disconnected()
        assertNull(clock.startedAt)
        assertEquals(10000L, clock.connected(10000))
    }

    private val connected = VpnStatusEvent.Connected("192.0.2.1", "2001:db8::1")

    @Test fun stateRestore() {
        val live = VpnUiState(isConnecting = true).applying(connected)
        val restored = VpnUiState().applying(connected)
        assertEquals(restored, live)
        assertTrue(live.isConnected)
        assertFalse(live.isConnecting)
        assertEquals(connected.ipv4, live.ipv4)
        assertEquals(connected.ipv6, live.ipv6)
    }

    @Test fun reconnectState() {
        val state = VpnUiState().applying(connected).applying(VpnStatusEvent.Reconnecting)
        assertTrue(state.isConnected)
        assertTrue(state.isConnecting)
        assertEquals(connected.ipv4, state.ipv4)
        assertEquals(connected.ipv6, state.ipv6)
        assertEquals(VpnUiState().applying(connected), state.applying(connected))
    }

    @Test fun clearedState() {
        val state = VpnUiState().applying(connected).applying(VpnStatusEvent.Reconnecting)
        assertEquals(VpnUiState(), state.applying(VpnStatusEvent.Disconnected))
        assertEquals(VpnUiState(), state.applying(VpnStatusEvent.Error("failed")))
    }

    @Test fun pendingPermission() {
        val pending = VpnUiState(isConnecting = true)
        assertEquals(pending, pending.applying(VpnStatusEvent.TrafficStats(1, 2, 3, 4)))
    }
}
