// SPDX-License-Identifier: MIT
package net.dighole.vault

import android.os.SystemClock
import android.util.Log
import net.dighole.vaultcore.uniffi.appendSharedLog
import net.dighole.vaultcore.uniffi.clearSharedLogs
import net.dighole.vaultcore.uniffi.readSharedLogs
import net.dighole.vaultcore.uniffi.setLogFilePath
import java.io.File
import java.io.FileOutputStream
import java.util.TimeZone
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

/**
 * Shared vault.log writes, rotation, reads and merges are owned by vault-core.
 * This object only provides Android's background queue and the optional
 * app-scoped external event log readable with authorized ADB.
 */
object VaultFileLogger {
    private const val TAG = "VaultFileLogger"
    private const val MAX_LOG_SIZE = 1024 * 1024L
    private const val LOG_FILE_NAME = "vault.log"

    private val writerThread = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "vault-file-logger").apply { isDaemon = true }
    }

    @Volatile
    private var logFile: File? = null

    private var eventFile: File? = null
    private val eventSequence = AtomicLong()

    @Suppress("TooGenericExceptionCaught")
    @Synchronized
    fun init(context: android.content.Context) {
        if (logFile != null) return
        try {
            val logsDir = File(context.filesDir, "logs")
            logsDir.mkdirs()
            logFile = File(logsDir, LOG_FILE_NAME)
            logFile?.absolutePath?.let { path ->
                try {
                    setLogFilePath(path)
                } catch (error: UnsatisfiedLinkError) {
                    Log.w(TAG, "vault-bridge native library unavailable", error)
                }
            }
            context.getExternalFilesDir(null)?.let { directory ->
                val events = File(directory, "logs")
                events.mkdirs()
                eventFile = File(events, "vpn-events.log")
            }
            log(Log.INFO, TAG, "File logger initialized at ${logFile?.absolutePath}")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to init file logger", e)
        }
    }

    val currentLogPath: String?
        get() = logFile?.absolutePath

    /** Queue Kotlin records; core appends synchronously on this writer thread. */
    @Suppress("TooGenericExceptionCaught")
    fun log(priority: Int, tag: String, message: String, throwable: Throwable? = null) {
        // Capture the time at the call site so lines reflect event order,
        // not writer-queue delay.
        val timestampMs = System.currentTimeMillis()
        val level = when (priority) {
            Log.VERBOSE -> "VERBOSE"
            Log.DEBUG -> "DEBUG"
            Log.INFO -> "INFO"
            Log.WARN -> "WARNING"
            Log.ERROR -> "ERROR"
            else -> "INFO"
        }
        val stackTrace = throwable?.let { Log.getStackTraceString(it) }
        writerThread.execute {
            try {
                val text = buildString {
                    append(message)
                    stackTrace?.let { append('\n').append(it) }
                }
                appendSharedLog(level, tag, text, timestampMs.toULong())
            } catch (e: Exception) {
                Log.w(TAG, "Failed to write log line", e)
            }
        }
    }

    /** Low-volume lifecycle events; app-scoped copy is readable with authorized ADB. */
    @Suppress("TooGenericExceptionCaught")
    fun event(tag: String, message: String) {
        val entry = "seq=${eventSequence.incrementAndGet()} elapsedMs=${SystemClock.elapsedRealtime()} " +
            "thread=${Thread.currentThread().name} [$tag] $message"
        log(Log.INFO, tag, entry)
        val file = eventFile ?: return
        writerThread.execute {
            try {
                rotateIfNeeded(file, File(file.parentFile, "vpn-events.prev.log"))
                file.appendText(entry + "\n")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to write diagnostic event", e)
            }
        }
    }

    /** Queue UI reads/clears behind Kotlin writes; native writes remain append-safe. */
    suspend fun readLogs(): String = queuedLogs(false)
    suspend fun clearAndRead(): String = queuedLogs(true)

    @Suppress("TooGenericExceptionCaught")
    private suspend fun queuedLogs(clear: Boolean): String = kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
        writerThread.execute {
            try {
                if (clear) {
                    clearSharedLogs()
                    eventFile?.let { file ->
                        FileOutputStream(file, false).use { stream -> stream.flush() }
                        val backup = File(file.parentFile, "vpn-events.prev.log")
                        if (backup.exists() && !backup.delete()) {
                            throw java.io.IOException("Failed to clear event log backup")
                        }
                    }
                }
                val offsetSeconds = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 1000
                val content = readSharedLogs(offsetSeconds)
                if (continuation.isActive) continuation.resumeWith(Result.success(content))
            } catch (error: Exception) {
                if (continuation.isActive) continuation.resumeWith(Result.failure(error))
            }
        }
    }

    private fun rotateIfNeeded(file: File, prev: File) {
        if (file.exists() && file.length() > MAX_LOG_SIZE) {
            prev.delete()
            if (!file.renameTo(prev)) {
                Log.w(TAG, "Log rotation failed")
            }
        }
    }
}
