// SPDX-License-Identifier: MIT
package net.dighole.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.InetAddress

class TunnelAddressesTest {
    @Test fun ipv4Dns() {
        val addresses = TunnelAddresses.parse("192.168.10.2", "255.255.255.0", "", 0)
        assertEquals(24, addresses.ipv4Prefix)
        assertEquals(listOf("1.1.1.1", "8.8.8.8").map(InetAddress::getByName),
            addresses.dns(emptyList(), listOf("2606:4700:4700::1111")))
    }

    @Test fun ipv6Dns() {
        val addresses = TunnelAddresses.parse("", "", "fd00::2", 96)
        assertNull(addresses.ipv4)
        assertNull(addresses.ipv4Prefix)
        assertEquals(96, addresses.ipv6Prefix)
        assertEquals(listOf("2001:4860:4860::8888", "2001:4860:4860::8844").map(InetAddress::getByName),
            addresses.dns(listOf("9.9.9.9"), emptyList()))
    }

    @Test fun dualStackDns() {
        val dual = TunnelAddresses.parse("192.168.10.2", "255.255.255.0", "fd00::2", 96)
        val defaults = listOf("1.1.1.1", "8.8.8.8", "2001:4860:4860::8888", "2001:4860:4860::8844")
        assertEquals(defaults.map(InetAddress::getByName), dual.dns(emptyList(), emptyList()))
        assertEquals(listOf("9.9.9.9", "2001:4860:4860::8888", "2001:4860:4860::8844").map(InetAddress::getByName),
            dual.dns(listOf("9.9.9.9"), emptyList()))
        assertEquals(listOf("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111").map(InetAddress::getByName),
            dual.dns(emptyList(), listOf("2606:4700:4700::1111")))
        assertEquals(listOf("9.9.9.9", "2606:4700:4700::1111").map(InetAddress::getByName),
            dual.dns(listOf("9.9.9.9"), listOf("2606:4700:4700::1111")))
    }

    @Test fun dnsFamilyMismatch() {
        val dual = TunnelAddresses.parse("192.168.10.2", "255.255.255.0", "fd00::2", 96)
        assertThrows(IllegalArgumentException::class.java) { dual.dns(listOf("fd00::1"), emptyList()) }
        assertThrows(IllegalArgumentException::class.java) { dual.dns(emptyList(), listOf("1.1.1.1")) }
        assertThrows(IllegalArgumentException::class.java) { dual.dns(listOf("example.com"), emptyList()) }
    }

    @Test fun invalidAssignment() {
        listOf(
            { TunnelAddresses.parse("", "", "", 0) },
            { TunnelAddresses.parse("192.168.10.2", "", "", 0) },
            { TunnelAddresses.parse("", "255.255.255.0", "fd00::2", 96) },
            { TunnelAddresses.parse("192.168.10.2", "255.0.255.0", "", 0) },
            { TunnelAddresses.parse("192.168.10.2", "255.255.255.999", "", 0) },
            { TunnelAddresses.parse("fd00::2", "255.255.255.0", "", 0) },
            { TunnelAddresses.parse("", "", "192.168.10.2", 96) },
            { TunnelAddresses.parse("", "", "fd00::2", 129) }
        ).forEach { invalid -> assertThrows(IllegalArgumentException::class.java) { invalid() } }
    }
}
