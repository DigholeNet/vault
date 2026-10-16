// SPDX-License-Identifier: MIT
package net.dighole.vaultcore

/**
 * Lightweight logging abstraction for the vaultcore module.
 *
 * vaultcore is a pure JVM library and cannot depend on Android SDK classes
 * (e.g. [android.util.Log]). This interface allows the Android app module
 * to inject a platform-specific implementation at runtime.
 */
interface VaultLogger {
    fun finest(message: String, throwable: Throwable? = null)
    fun finer(message: String, throwable: Throwable? = null)
    fun fine(message: String, throwable: Throwable? = null)
    fun config(message: String, throwable: Throwable? = null)
    fun info(message: String, throwable: Throwable? = null)
    fun warning(message: String, throwable: Throwable? = null)
    fun severe(message: String, throwable: Throwable? = null)
    fun isLoggable(level: VaultLogLevel): Boolean
}

enum class VaultLogLevel {
    FINEST, FINER, FINE, CONFIG, INFO, WARNING, SEVERE
}

/**
 * Global factory for obtaining [VaultLogger] instances.
 *
 * By default a JDK ([java.util.logging]) backed logger is used so that
 * vaultcore works out-of-the-box in unit tests and other JVM environments.
 * The Android app should call [setFactory] during Application startup to
 * route logs to [android.util.Log].
 */
object VaultLoggers {
    private var factory: (String) -> VaultLogger = { JdkVaultLogger(it) }

    fun setFactory(factory: (String) -> VaultLogger) {
        this.factory = factory
    }

    fun getLogger(name: String): VaultLogger = factory(name)
}
