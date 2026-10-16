// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.util.Log
import net.dighole.vaultcore.VaultLogLevel
import net.dighole.vaultcore.VaultLogger

/**
 * Android [android.util.Log] backed implementation of [VaultLogger].
 * Routes vpncore logs into the Android logcat pipeline with proper
 * filtering support via `adb shell setprop log.tag.<TAG> <LEVEL>`.
 *
 * Every line is also mirrored to [VaultFileLogger] so vpncore events
 * (handshake, heartbeat, reconnect) survive in the rolling log file.
 */
class AndroidVaultLogger(private val tag: String) : VaultLogger {

    override fun finest(message: String, throwable: Throwable?) {
        if (throwable != null) Log.v(tag, message, throwable) else Log.v(tag, message)
        VaultFileLogger.log(Log.VERBOSE, tag, message, throwable)
    }

    override fun finer(message: String, throwable: Throwable?) {
        if (throwable != null) Log.v(tag, message, throwable) else Log.v(tag, message)
        VaultFileLogger.log(Log.VERBOSE, tag, message, throwable)
    }

    override fun fine(message: String, throwable: Throwable?) {
        if (throwable != null) Log.d(tag, message, throwable) else Log.d(tag, message)
        VaultFileLogger.log(Log.DEBUG, tag, message, throwable)
    }

    override fun config(message: String, throwable: Throwable?) {
        if (throwable != null) Log.d(tag, message, throwable) else Log.d(tag, message)
        VaultFileLogger.log(Log.DEBUG, tag, message, throwable)
    }

    override fun info(message: String, throwable: Throwable?) {
        if (throwable != null) Log.i(tag, message, throwable) else Log.i(tag, message)
        VaultFileLogger.log(Log.INFO, tag, message, throwable)
    }

    override fun warning(message: String, throwable: Throwable?) {
        if (throwable != null) Log.w(tag, message, throwable) else Log.w(tag, message)
        VaultFileLogger.log(Log.WARN, tag, message, throwable)
    }

    override fun severe(message: String, throwable: Throwable?) {
        if (throwable != null) Log.e(tag, message, throwable) else Log.e(tag, message)
        VaultFileLogger.log(Log.ERROR, tag, message, throwable)
    }

    override fun isLoggable(level: VaultLogLevel): Boolean {
        return Log.isLoggable(tag, level.toAndroidPriority())
    }

    private fun VaultLogLevel.toAndroidPriority(): Int = when (this) {
        VaultLogLevel.FINEST, VaultLogLevel.FINER -> Log.VERBOSE
        VaultLogLevel.FINE, VaultLogLevel.CONFIG -> Log.DEBUG
        VaultLogLevel.INFO -> Log.INFO
        VaultLogLevel.WARNING -> Log.WARN
        VaultLogLevel.SEVERE -> Log.ERROR
    }
}
