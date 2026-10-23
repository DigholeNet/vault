// SPDX-License-Identifier: MIT
package net.dighole.vaultcore

/**
 * 16-byte peer identifier.
 */
data class PeerId(val id: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PeerId) return false
        return id.contentEquals(other.id)
    }

    override fun hashCode(): Int = id.contentHashCode()
}
