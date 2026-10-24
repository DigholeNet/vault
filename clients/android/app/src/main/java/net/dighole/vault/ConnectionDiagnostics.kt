// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.NetworkCapabilities
import android.os.CancellationSignal
import android.os.SystemClock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URL
import java.util.concurrent.Executor
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal data class ProbeResult(val domain: String, val stage: Int, val passed: Boolean,
    val durationMs: Long, val detail: String)

/** Explicit VPN Network for tunnel checks; default routing for app HTTPS. */
internal object ConnectionDiagnostics {
    @Suppress("DEPRECATION") // Enumerate VPN transports even while the default network is changing.
    fun vpnNetwork(manager: ConnectivityManager): Network? = manager.allNetworks.firstOrNull {
        manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    suspend fun run(manager: ConnectivityManager, network: Network, domains: List<String>,
        onResult: suspend (ProbeResult) -> Unit) = withContext(Dispatchers.IO) {
        val started = SystemClock.elapsedRealtime()
        for (domain in domains) {
            var addresses = emptyList<InetAddress>()
            for (stage in 0..6) {
                ensureActive()
                check(SystemClock.elapsedRealtime() - started < 60000 && vpnNetwork(manager) == network) {
                    "VPN changed or diagnostic time budget exhausted"
                }
                val before = SystemClock.elapsedRealtime()
                val attempt = runCatching {
                    when (stage) {
                        0, 3 -> {
                            addresses = resolve(network, domain, if (stage == 0) 1 else 28)
                            if (stage == 0) check(addresses.isNotEmpty()) { "No A records" }
                            addresses.joinToString { it.hostAddress.orEmpty() }.ifEmpty { "No AAAA records" }
                        }
                        1, 4 -> {
                            if (stage == 4 && addresses.isEmpty()) "Skipped: no AAAA records"
                            else {
                                check(addresses.isNotEmpty()) { "No DNS answers for TCP" }
                                tryAddresses(addresses) { address ->
                                    network.socketFactory.createSocket().use {
                                        it.connect(InetSocketAddress(address, 443), 4000)
                                    }
                                    "TCP 443"
                                }
                            }
                        }
                        2, 5 -> {
                            if (stage == 5 && addresses.isEmpty()) "Skipped: no AAAA records"
                            else {
                                check(addresses.isNotEmpty()) { "No DNS answers for HTTPS" }
                                tryAddresses(addresses) { tunnelHttps(network, domain, it) }
                            }
                        }
                        else -> https(domain)
                    }
                }
                ensureActive()
                check(vpnNetwork(manager) == network) { "VPN changed" }
                val result = ProbeResult(domain, stage, attempt.isSuccess,
                    SystemClock.elapsedRealtime() - before,
                    attempt.getOrElse { it.message ?: it.javaClass.simpleName })
                VaultFileLogger.log(android.util.Log.INFO, "Diagnostics",
                    "[probe] $domain stage=$stage passed=${result.passed} duration=${result.durationMs}ms ${result.detail}")
                onResult(result)
            }
        }
        // ICMP is an observation of application routing, as on iOS; it never changes the connectivity verdict.
        for ((stage, host) in listOf(7 to "1.1.1.1", 8 to "2606:4700:4700::1111")) {
            repeat(2) {
                ensureActive()
                check(vpnNetwork(manager) == network) { "VPN changed" }
                val sample = runCatching { ping(host, stage == 8) }
                onResult(ProbeResult(host, stage, sample.isSuccess, sample.getOrDefault(0),
                    sample.exceptionOrNull()?.message ?: "ICMP echo reply"))
            }
        }
    }

    private fun tryAddresses(addresses: List<InetAddress>, attempt: (InetAddress) -> String): String {
        var failure: Exception? = null
        for (address in addresses.take(2)) {
            try { return attempt(address) } catch (error: java.io.IOException) { failure = error }
        }
        throw failure ?: java.io.IOException("No usable address")
    }

    private fun tunnelHttps(network: Network, domain: String, address: InetAddress): String {
        val raw = network.socketFactory.createSocket()
        try {
            raw.connect(InetSocketAddress(address, 443), 4000)
            val factory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
            (factory.createSocket(raw, domain, 443, true) as javax.net.ssl.SSLSocket).use { socket ->
                socket.soTimeout = 4000
                socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                socket.startHandshake()
                socket.outputStream.write("HEAD / HTTP/1.1\r\nHost: $domain\r\nConnection: close\r\n\r\n".toByteArray())
                socket.outputStream.flush()
                val line = buildString {
                    val input = socket.inputStream
                    while (length < 1024) {
                        val byte = input.read()
                        if (byte == -1 || byte == 10) break
                        append(byte.toChar())
                    }
                }.trim()
                check(line.startsWith("HTTP/1.")) { "Invalid HTTP response" }
                return line
            }
        } finally { raw.close() }
    }

    private fun ping(host: String, ipv6: Boolean): Long {
        val process = ProcessBuilder(PingSupport.command(host, ipv6, java.io.File("/system/bin/ping6").canExecute()))
            .redirectErrorStream(true).start()
        try {
            check(process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) { "ICMP timed out" }
            val output = process.inputStream.bufferedReader().readText()
            check(process.exitValue() == 0) { output.take(240) }
            return PingSupport.rttMillis(output) ?: error("No ICMP RTT sample")
        } finally { process.destroy() }
    }

    private suspend fun resolve(network: Network, domain: String, type: Int): List<InetAddress> = withTimeout(5000) {
        suspendCancellableCoroutine { continuation ->
            val signal = CancellationSignal()
            continuation.invokeOnCancellation { signal.cancel() }
            DnsResolver.getInstance().query(network, domain, type, DnsResolver.FLAG_EMPTY,
                Executor { it.run() }, signal, object : DnsResolver.Callback<List<InetAddress>> {
                    override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                        if (continuation.isActive) {
                            if (rcode == 0) continuation.resume(answer)
                            else continuation.resumeWithException(java.io.IOException("DNS rcode $rcode"))
                        }
                    }
                    override fun onError(error: DnsResolver.DnsException) {
                        if (continuation.isActive) continuation.resumeWithException(error)
                    }
                })
        }
    }

    private fun https(domain: String): String {
        val url = URL("https://$domain/")
        val connection = url.openConnection() as HttpsURLConnection
        try {
            connection.connectTimeout = 4000
            connection.readTimeout = 4000
            connection.instanceFollowRedirects = false
            connection.requestMethod = "HEAD"
            val status = connection.responseCode
            check(status in 100..599) { "Invalid HTTP response" }
            return "HTTP $status"
        } finally { connection.disconnect() }
    }
}
