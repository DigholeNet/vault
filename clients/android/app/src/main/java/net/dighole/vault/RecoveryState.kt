// SPDX-License-Identifier: MIT
package net.dighole.vault

/** Tracks recovery through handshake and TUN setup, beyond the reconnect call. */
// No deadline: an established VPN waits through long outages until recovery or user stop.
internal class RecoveryState {
    private var recovering = false
    private var configured = false

    @Synchronized
    fun begin(restart: Boolean = false): Boolean {
        // A new connection attempt must not complete using the previous
        // attempt's configuration while its TUN I/O is still recovering.
        if (restart) configured = false
        if (recovering) return false
        recovering = true
        configured = false
        return true
    }

    @Synchronized
    fun isRecovering(): Boolean = recovering

    @Synchronized
    fun onConfigured(): Boolean {
        if (!recovering) return false
        configured = true
        return true
    }

    @Synchronized
    fun completeIfReady(ioReady: Boolean): Boolean {
        if (!recovering || !configured || !ioReady) return false
        reset()
        return true
    }

    @Synchronized
    fun reset() {
        recovering = false
        configured = false
    }
}
