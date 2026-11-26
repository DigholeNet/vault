// SPDX-License-Identifier: MIT
package net.dighole.vault

internal class ProfileSwitchGate<T> {
    var closing = false
        private set
    private var pending: T? = null

    fun begin(request: T): Boolean {
        pending = request
        if (closing) return false
        closing = true
        return true
    }

    fun complete(): T? {
        val request = pending
        pending = null
        closing = false
        return request
    }

    fun cancel() {
        pending = null
        closing = false
    }
}
