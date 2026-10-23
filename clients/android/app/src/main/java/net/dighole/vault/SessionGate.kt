// SPDX-License-Identifier: MIT
package net.dighole.vault

import java.io.Closeable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Serializes session publication with stop; blocking resource creation stays outside. */
internal class SessionGate {
    private val configurationMutex = Mutex()
    private var generation = 0L
    private var active = false

    /** Serialize resource creation through publication, without blocking stop(). */
    suspend fun configure(action: suspend () -> Unit) = configurationMutex.withLock { action() }

    @Synchronized
    fun begin(): Long {
        generation++
        active = true
        return generation
    }

    @Synchronized
    fun update(token: Long, action: () -> Unit): Boolean {
        if (!active || token != generation) return false
        action()
        return true
    }

    /** Evaluate additional freshness checks under the same lock as publication. */
    @Synchronized
    fun updateIf(token: Long, condition: () -> Boolean, action: () -> Unit): Boolean {
        if (!active || token != generation || !condition()) return false
        action()
        return true
    }

    @Synchronized
    fun stop(action: () -> Unit) {
        active = false
        generation++
        action()
    }

    fun <T : Closeable> commit(
        token: Long,
        resource: T,
        condition: () -> Boolean = { true },
        onCreated: () -> Unit = {},
        action: (T) -> Unit
    ): Boolean {
        var accepted = false
        try {
            update(token) {
                // Creation may invalidate an existing resource even when this
                // replacement is already superseded. Account for that first.
                onCreated()
                if (!condition()) return@update
                accepted = true
                action(resource)
            }
            return accepted
        } finally {
            if (!accepted) resource.close()
        }
    }
}
