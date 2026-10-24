// SPDX-License-Identifier: MIT
package net.dighole.vault.data

data class VaultConfig(
    val host: String = "",
    val port: Int = 9527,
    val password: String = "",
    val dns: String = "1.1.1.1,8.8.8.8",
    val mtu: String = "",
    val probeDomains: String = ""
)
