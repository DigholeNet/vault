// SPDX-License-Identifier: MIT
package net.dighole.vaultcore

/**
 * Rate limiter for high-frequency log statements.
 *
 * During a reconnect storm the same message (e.g. "dropping packet") can be
 * emitted once per packet, flooding logcat and the log file. Callers gate a
 * log statement with [shouldLog]; each call site (identified by [key]) is
 * allowed through at most once per [intervalMs].
 *
 * Keys are fixed string literals defined at call sites, so the internal map
 * stays bounded.
 */
object LogThrottle {
    private val lastLogTimeMs = HashMap<String, Long>()

    @Synchronized
    fun shouldLog(key: String, intervalMs: Long): Boolean {
        val now = System.currentTimeMillis()
        val last = lastLogTimeMs[key]
        if (last != null && now - last < intervalMs) {
            return false
        }
        lastLogTimeMs[key] = now
        return true
    }
}
