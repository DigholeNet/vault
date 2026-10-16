// SPDX-License-Identifier: MIT
package net.dighole.vaultcore

import java.util.logging.Level
import java.util.logging.Logger

/**
 * JDK [java.util.logging] backed implementation of [VaultLogger].
 * Used as the default fallback in unit tests and non-Android JVM environments.
 */
class JdkVaultLogger(name: String) : VaultLogger {
    private val delegate = Logger.getLogger(name)

    override fun finest(message: String, throwable: Throwable?) {
        delegate.log(Level.FINEST, message, throwable)
    }

    override fun finer(message: String, throwable: Throwable?) {
        delegate.log(Level.FINER, message, throwable)
    }

    override fun fine(message: String, throwable: Throwable?) {
        delegate.log(Level.FINE, message, throwable)
    }

    override fun config(message: String, throwable: Throwable?) {
        delegate.log(Level.CONFIG, message, throwable)
    }

    override fun info(message: String, throwable: Throwable?) {
        delegate.log(Level.INFO, message, throwable)
    }

    override fun warning(message: String, throwable: Throwable?) {
        delegate.log(Level.WARNING, message, throwable)
    }

    override fun severe(message: String, throwable: Throwable?) {
        delegate.log(Level.SEVERE, message, throwable)
    }

    override fun isLoggable(level: VaultLogLevel): Boolean {
        return delegate.isLoggable(level.toJdkLevel())
    }

    private fun VaultLogLevel.toJdkLevel(): Level = when (this) {
        VaultLogLevel.FINEST -> Level.FINEST
        VaultLogLevel.FINER -> Level.FINER
        VaultLogLevel.FINE -> Level.FINE
        VaultLogLevel.CONFIG -> Level.CONFIG
        VaultLogLevel.INFO -> Level.INFO
        VaultLogLevel.WARNING -> Level.WARNING
        VaultLogLevel.SEVERE -> Level.SEVERE
    }
}
