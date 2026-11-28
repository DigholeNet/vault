// SPDX-License-Identifier: MIT
package net.dighole.vault.data

data class VaultConfig(
    val name: String = "",
    val host: String = "",
    val port: Int = 9527,
    val password: String = "",
    val dnsIpv4: String = "",
    val dnsIpv6: String = "",
    val mtu: String = "",
    val hostLatencyMs: Long? = null
)

internal fun parseConfigList(value: String): List<String> =
    value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
