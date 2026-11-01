// SPDX-License-Identifier: MIT
package net.dighole.vault.data

data class VaultConfig(
    val host: String = "",
    val port: Int = 9527,
    val password: String = "",
    val dnsIpv4: String = "",
    val dnsIpv6: String = "",
    val mtu: String = "",
    val probeDomains: String = ""
)

/** Preserve legacy DNS entries and their order within each address family. */
internal fun splitLegacyDns(value: String): Pair<String, String> {
    val entries = value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    return entries.filter { ':' !in it }.joinToString(",") to
        entries.filter { ':' in it }.joinToString(",")
}
