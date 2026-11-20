package net.dighole.vault

import net.dighole.vaultcore.uniffi.calculateTunnelMtu
import net.dighole.vaultcore.uniffi.isValidAddress
import net.dighole.vaultcore.uniffi.isValidDnsList
import net.dighole.vaultcore.uniffi.isValidDomain
import net.dighole.vaultcore.uniffi.isValidDomainList
import net.dighole.vaultcore.uniffi.isValidMtu
import net.dighole.vaultcore.uniffi.isValidServer
import net.dighole.vaultcore.uniffi.tunnelParameters

/** Platform-independent settings rules supplied by vault-core. */
internal object SettingsValidation {
    fun domain(value: String): Boolean = isValidDomain(value)
    fun address(value: String): Boolean = isValidAddress(value)
    fun server(value: String): Boolean = isValidServer(value)
    fun dns(value: String, ipv6: Boolean? = null): Boolean = isValidDnsList(value, ipv6)
    fun domains(value: String): Boolean = isValidDomainList(value)
    fun mtu(value: String): Boolean = isValidMtu(value)
}

/** Platform-independent tunnel limits supplied by the shared core. */
internal object TunnelPolicy {
    private val parameters by lazy { tunnelParameters() }
    val mtuMax: Int get() = parameters.mtuMax.toInt()
    fun mtu(linkMtu: Int?, cap: Int?): Int = calculateTunnelMtu(linkMtu?.toUInt(), cap?.toUShort()).toInt()
}
