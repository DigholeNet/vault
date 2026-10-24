package net.dighole.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class PingSupportTest {
    @Test fun legacyIpv4DoesNotReceiveUnsupportedFamilyFlag() {
        val command = PingSupport.command("1.1.1.1", false, true)
        assertEquals("/system/bin/ping", command.first())
        assertFalse(command.contains("-4"))
        assertFalse(command.contains("-6"))
    }

    @Test fun ipv6SupportsSeparateAndUnifiedBinaries() {
        val legacy = PingSupport.command("2606:4700:4700::1111", true, true)
        assertEquals("/system/bin/ping6", legacy.first())
        assertFalse(legacy.contains("-6"))
        assertEquals("-6", PingSupport.command("::1", true, false)[1])
    }

    @Test fun parsesDeviceOutputAndSubMillisecondSamples() {
        assertEquals(203L, PingSupport.rttMillis("64 bytes from 1.1.1.1: time=203 ms\n" +
            "rtt min/avg/max/mdev = 203.452/203.452/203.452/0.000 ms"))
        assertEquals(0L, PingSupport.rttMillis("time=0.350 ms"))
        assertEquals(1L, PingSupport.rttMillis("time<1 ms"))
        assertNull(PingSupport.rttMillis("ping: invalid option -- 4"))
        assertNull(PingSupport.rttMillis("100% packet loss"))
    }
}
