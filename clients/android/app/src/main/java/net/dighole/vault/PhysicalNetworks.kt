// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.net.IpPrefix
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.RouteInfo
import java.net.InetAddress

/** A resolver, UDP binding and TUN exclusion list must all use the same generation. */
internal class PhysicalNetworks(private val changed: () -> Unit) {
    data class Link(
        val name: String?,
        val addresses: Set<LinkAddress>,
        val defaults: Set<RouteInfo>,
        val dns: List<InetAddress>,
        val nat64: IpPrefix?,
        val mtu: Int?
    ) {
        constructor(properties: LinkProperties) : this(
            properties.interfaceName,
            properties.linkAddresses.toSet(),
            properties.routes.filter { it.isDefaultRoute }.toSet(),
            properties.dnsServers.toList(),
            properties.nat64Prefix,
            properties.mtu.takeIf { it > 0 }
        )
    }

    data class Selected(val network: Network, val link: Link, val generation: ULong, val canMapPorts: Boolean)
    private data class Candidate(val link: Link? = null, val capabilities: NetworkCapabilities? = null)

    private val candidates = linkedMapOf<Network, Candidate>()
    private var generation = 0uL

    @Volatile
    var selected: Selected? = null
        private set

    @Synchronized
    fun capabilities(network: Network, capabilities: NetworkCapabilities) =
        update(network, candidates[network].orEmpty().copy(capabilities = capabilities))

    @Synchronized
    fun link(network: Network, properties: LinkProperties) =
        update(network, candidates[network].orEmpty().copy(link = Link(properties)))

    @Synchronized
    fun lost(network: Network) = update(network, null)

    private fun Candidate?.orEmpty(): Candidate = this ?: Candidate()

    private fun update(network: Network, candidate: Candidate?) {
        if (candidate == null) candidates.remove(network) else candidates[network] = candidate
        val eligible = candidates.entries.filter { (_, candidate) ->
            candidate.link?.let { it.name != null && it.addresses.isNotEmpty() } == true &&
                candidate.capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
        }
        val winner = eligible.maxWithOrNull(compareBy(
            { it.value.capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true },
            { transportRank(requireNotNull(it.value.capabilities)) }
        ))
        val previous = selected
        val network = winner?.key
        val link = winner?.value?.link
        val canMapPorts = winner?.value?.capabilities?.let {
            it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                it.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        } == true
        if (previous?.network == network && previous?.link == link &&
            (previous?.canMapPorts ?: false) == canMapPorts
        ) return
        generation++
        selected = if (network != null && link != null) Selected(network, link, generation, canMapPorts) else null
        changed()
    }

    private fun transportRank(caps: NetworkCapabilities): Int = listOf(
        NetworkCapabilities.TRANSPORT_CELLULAR,
        NetworkCapabilities.TRANSPORT_WIFI,
        NetworkCapabilities.TRANSPORT_ETHERNET
    ).indexOfLast(caps::hasTransport)
}
