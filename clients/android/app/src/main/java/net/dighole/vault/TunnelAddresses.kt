// SPDX-License-Identifier: MIT
package net.dighole.vault

import net.dighole.vaultcore.uniffi.SettingsException
import net.dighole.vaultcore.uniffi.TunnelAssignment
import net.dighole.vaultcore.uniffi.tunnelDnsServers
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** Validated assignment used by Android's TUN builder and live-network matching. */
internal data class TunnelAddresses(
    val ipv4: Inet4Address?,
    val ipv4Prefix: Int?,
    val ipv6: Inet6Address?,
    val ipv6Prefix: Int?,
    private val coreAssignment: TunnelAssignment
) {
    fun dns(configuredIpv4: List<String>, configuredIpv6: List<String>): List<InetAddress> = try {
        tunnelDnsServers(coreAssignment, configuredIpv4, configuredIpv6)
            .map(::numericAddress)
            .distinct()
    } catch (error: SettingsException) {
        throw IllegalArgumentException(error.message, error)
    }

    companion object {
        fun from(assignment: TunnelAssignment): TunnelAddresses = TunnelAddresses(
            assignment.ipv4?.let { numericAddress(it.address) as Inet4Address },
            assignment.ipv4?.prefixLen?.toInt(),
            assignment.ipv6?.let { numericAddress(it.address) as Inet6Address },
            assignment.ipv6?.prefixLen?.toInt(),
            assignment
        )

        private fun numericAddress(value: String): InetAddress = InetAddress.getByName(value)
    }
}
