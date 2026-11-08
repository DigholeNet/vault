package net.dighole.vault

import net.dighole.vaultcore.uniffi.diagnosticDnsQuery
import net.dighole.vaultcore.uniffi.tunnelParameters

/** Syntax checks only: editing settings never resolves hostnames on the network. */
internal object SettingsValidation {
    fun domain(value: String): Boolean {
        val host = value.removeSuffix(".")
        return host.isNotEmpty() && value.length <= 253 &&
            runCatching { diagnosticDnsQuery(host, 0u, false) }.isSuccess
    }
    fun address(value: String): Boolean = if (':' in value) {
        value.all { it in "0123456789abcdefABCDEF:." } &&
            runCatching { java.net.InetAddress.getByName(value) }.isSuccess
    } else value.split('.').let { parts ->
        parts.size == 4 && parts.all { it.isNotEmpty() && it.all(Char::isDigit) && it.toIntOrNull() in 0..255 }
    }
    fun server(value: String): Boolean = address(value) || domain(value)
    fun dns(value: String, ipv6: Boolean? = null): Boolean {
        if (value.isBlank()) return true
        val entries = value.split(',')
        return entries.size <= 4 && entries.all {
            val literal = it.trim()
            address(literal) && (ipv6 == null || (java.net.InetAddress.getByName(literal) is java.net.Inet6Address) == ipv6)
        }
    }
    fun domains(value: String): Boolean {
        if (value.isBlank()) return true
        val entries = value.split(',')
        return entries.size <= 32 && entries.all { domain(it.trim()) }
    }
    fun mtu(value: String): Boolean = value.isBlank() || mtuValue(value) != null
    fun mtuValue(value: String): Int? = value.trim().toIntOrNull()?.takeIf { it in TunnelPolicy.mtuMin..TunnelPolicy.mtuMax }
}

/** Platform-independent tunnel limits and defaults supplied by the shared core. */
internal object TunnelPolicy {
    private val parameters by lazy { tunnelParameters() }
    val mtuMin: Int get() = parameters.mtuMin.toInt()
    val mtuMax: Int get() = parameters.mtuMax.toInt()
    val overhead: Int get() = parameters.overhead.toInt()
    val dnsIpv4: List<String> get() = parameters.dnsIpv4
    val dnsIpv6: List<String> get() = parameters.dnsIpv6
}
