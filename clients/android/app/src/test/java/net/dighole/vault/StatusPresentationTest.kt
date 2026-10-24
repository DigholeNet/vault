package net.dighole.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StatusPresentationTest {
    @Test fun durationAlwaysShowsHoursAndDoesNotWrapAtOneDay() {
        assertEquals("00:00:00", StatusPresentation.duration(-1))
        assertEquals("00:00:09", StatusPresentation.duration(9999))
        assertEquals("01:01:01", StatusPresentation.duration(3661000))
        assertEquals("25:00:00", StatusPresentation.duration(90000000))
    }

    @Test fun trafficUsesTheSameUnitsAndPrecisionAsIos() {
        assertEquals("0.00 B", StatusPresentation.bytes(0))
        assertEquals("1.00 KB", StatusPresentation.bytes(1024))
        assertEquals("1.50 MB", StatusPresentation.bytes(1572864))
        assertEquals("1.00 TB", StatusPresentation.bytes(1099511627776))
    }

    @Test fun clockSurvivesReconnectionAndOnlyResetsOnDisconnect() {
        val clock = ConnectionClock()
        assertNull(clock.startedAt)
        assertEquals(1000L, clock.connected(1000))
        assertEquals(1000L, clock.connected(9000))
        clock.disconnected()
        assertNull(clock.startedAt)
        assertEquals(10000L, clock.connected(10000))
    }
}
