// SPDX-License-Identifier: MIT
package net.dighole.vault

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** Validated assignment used by Android's TUN builder and live-network matching. */
internal data class TunnelAddresses(
    val ipv4: Inet4Address?,
    val ipv4Prefix: Int?,
    val ipv6: Inet6Address?,
    val ipv6Prefix: Int?
) {
    fun dns(configuredIpv4: List<String>, configuredIpv6: List<String>): List<InetAddress> {
        val servers = mutableListOf<InetAddress>()
        if (ipv4 != null) {
            val v4 = configuredIpv4.ifEmpty { listOf("1.1.1.1", "8.8.8.8") }.map(::numericAddress)
            require(v4.all { it is Inet4Address }) { "IPv4 DNS requires IPv4 addresses" }
            servers.addAll(v4)
        }
        if (ipv6 != null) {
            val v6 = configuredIpv6.ifEmpty {
                listOf("2001:4860:4860::8888", "2001:4860:4860::8844")
            }.map(::numericAddress)
            require(v6.all { it is Inet6Address }) { "IPv6 DNS requires IPv6 addresses" }
            servers.addAll(v6)
        }
        return servers.distinct()
    }

    companion object {
        fun parse(ipv4: String, mask: String, ipv6: String, prefix: Int): TunnelAddresses {
            require(ipv4.isNotEmpty() || ipv6.isNotEmpty()) { "No tunnel address assigned" }
            require(ipv4.isNotEmpty() == mask.isNotEmpty()) { "Incomplete tunnel IPv4 assignment" }
            val v4 = ipv4.takeIf { it.isNotEmpty() }?.let {
                requireNotNull(numericAddress(it) as? Inet4Address) { "Invalid tunnel IPv4 address" }
            }
            val v6 = ipv6.takeIf { it.isNotEmpty() }?.let {
                require(prefix in 0..128) { "Invalid tunnel IPv6 prefix" }
                requireNotNull(numericAddress(it) as? Inet6Address) { "Invalid tunnel IPv6 address" }
            }
            return TunnelAddresses(v4, if (v4 != null) maskPrefix(mask) else null, v6, if (v6 != null) prefix else null)
        }

        private fun maskPrefix(mask: String): Int {
            val address = numericAddress(mask)
            require(address is Inet4Address) { "Invalid IPv4 mask" }
            val bits = address.address.fold(0L) { value, byte -> (value shl 8) or (byte.toLong() and 255) }
            val inverse = bits xor 0xffffffffL
            require(inverse and (inverse + 1) == 0L) { "Non-contiguous IPv4 mask" }
            return java.lang.Long.bitCount(bits)
        }

        private fun numericAddress(value: String): InetAddress {
            require(SettingsValidation.address(value)) { "Invalid numeric address: $value" }
            return InetAddress.getByName(value)
        }
    }
}
