// SPDX-License-Identifier: MIT
package net.dighole.vault

import kotlin.math.roundToLong

internal object PingSupport {
    fun command(host: String, ipv6: Boolean, separatePing6: Boolean): List<String> {
        val executable = if (ipv6 && separatePing6) "/system/bin/ping6" else "/system/bin/ping"
        val family = if (ipv6 && !separatePing6) listOf("-6") else emptyList()
        return listOf(executable) + family + listOf("-c", "1", "-W", "2", host)
    }

    fun rttMillis(output: String): Long? {
        val average = Regex("(?:rtt|round-trip)[^=]*=\\s*[0-9.]+/([0-9.]+)/").find(output)
            ?.groupValues?.get(1)?.toDoubleOrNull()
        val reply = Regex("time[=<]\\s*([0-9.]+)\\s*ms").find(output)
            ?.groupValues?.get(1)?.toDoubleOrNull()
        return (average ?: reply)?.takeIf { it.isFinite() && it >= 0 }?.roundToLong()
    }
}
